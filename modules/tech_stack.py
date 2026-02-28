# modules/tech_stack.py
# Deep Tech Stack Detection + Real CVE Lookup (using Wappalyzer + NVD API fallback)
from config import HEADERS, TIMEOUT
import requests
from bs4 import BeautifulSoup
try:
    from Wappalyzer import Wappalyzer, WebPage
except ImportError:
    Wappalyzer = None  # fallback if not installed

def scan(target_url, pages):
    """
    Detects technologies, versions, and checks for known vulnerabilities (CVEs).
    - Uses Wappalyzer for deep fingerprinting (if installed)
    - Falls back to headers + meta tags
    - Queries NVD API for CVEs on detected versions
    Returns detailed findings with severity and links
    """
    findings = []
    techs = {}

    # === Primary: Wappalyzer (best detection) ===
    if Wappalyzer:
        try:
            webpage = WebPage.new_from_url(target_url, headers=HEADERS, timeout=TIMEOUT)
            wapp = Wappalyzer.latest()
            detected = wapp.analyze_with_versions_and_categories(webpage)

            for name, data in detected.items():
                version = data.get('version', 'unknown')
                if version and version != 'unknown':
                    techs[name] = version
                else:
                    techs[name] = 'detected (no version)'

        except Exception as e:
            findings.append(f"Low - Wappalyzer error: {str(e)} (using fallback detection)")
    else:
        findings.append("Note: Install 'wappalyzer' via pip for deeper tech detection")

    # === Fallback: Headers + Meta tags ===
    for _, resp in pages[:3]:  # Check first few pages only
        h = resp.headers

        if 'Server' in h:
            server = h['Server']
            techs['Server'] = server

        if 'X-Powered-By' in h:
            powered = h['X-Powered-By']
            techs['X-Powered-By'] = powered

        soup = BeautifulSoup(resp.text, 'html.parser')

        # Meta generator
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and generator.get('content'):
            techs['Generator'] = generator['content']

        # WordPress / CMS specific
        if soup.find('link', attrs={'rel': 'https://api.w.org/'}):
            techs['WordPress'] = 'detected'

        # Laravel / PHP frameworks
        if 'X-Powered-By' in h and 'PHP' in h['X-Powered-By']:
            techs['PHP'] = h['X-Powered-By'].split('PHP/')[-1] if '/' in h['X-Powered-By'] else 'unknown'

    # === CVE Lookup (NVD API - simple & free) ===
    for tech, version in techs.items():
        if version == 'detected (no version)' or version == 'unknown':
            findings.append(f"Medium - {tech} detected (no version) → Manual CVE check recommended")
            continue

        try:
            # Clean version for query (e.g., "Apache/2.4.41" → "Apache 2.4.41")
            query_tech = tech.replace('-', ' ').replace('_', ' ')
            query_version = version.strip('/').strip()

            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query_tech}+{query_version}&resultsPerPage=5"
            r = requests.get(nvd_url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                total = data.get('totalResults', 0)
                if total > 0:
                    vulns = data['vulnerabilities'][:3]  # top 3
                    for vuln in vulns:
                        cve = vuln['cve']['id']
                        severity = vuln['cve'].get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity', 'Unknown')
                        desc = vuln['cve']['descriptions'][0]['value'][:150] + '...'
                        findings.append(
                            f"High - Outdated {tech} {version} → {cve} ({severity}) | "
                            f"Description: {desc} | "
                            f"Link: https://nvd.nist.gov/vuln/detail/{cve}"
                        )
                else:
                    findings.append(f"Low - {tech} {version} detected → No recent CVEs found in NVD")
            else:
                findings.append(f"Low - {tech} {version} detected → CVE lookup failed (API error)")
        except Exception as e:
            findings.append(f"Low - {tech} {version} detected → CVE check error: {str(e)}")

    if not techs:
        findings.append("No technologies or versions reliably detected.")

    if not any("High" in f or "Medium" in f for f in findings):
        findings.append("✅ No outdated/vulnerable tech stack issues detected.")

    return findings
