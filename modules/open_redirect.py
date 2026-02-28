# modules/open_redirect.py
# Deep Open Redirect Scanner – Tests links, query params, meta refresh, and JS redirects
from config import HEADERS, TIMEOUT
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def scan(target_url, pages):
    """
    Deep Open Redirect testing across all crawled pages.
    - Tests query parameters (url=, redirect=, next=, etc.)
    - Tests <a> links with redirect patterns
    - Tests meta refresh and JavaScript location redirects
    Returns findings with PoC URLs
    """
    findings = []
    seen_pocs = set()

    # Common redirect parameter names
    redirect_params = ['url', 'redirect', 'next', 'return', 'return_to', 'redir', 'r', 'go', 'to']

    # Safe external test domain (used only for detection)
    test_domain = "https://www.google.com"

    for page_url, resp in pages:
        # === 1. Query parameter testing ===
        parsed = urlparse(page_url)
        if parsed.query:
            for param in redirect_params:
                if param in parsed.query.lower():
                    # Try common payloads
                    for payload in ["//www.google.com", "https://www.google.com", "//evil.com"]:
                        test_url = page_url.replace(f"{param}=", f"{param}={payload}")
                        try:
                            r = requests.get(test_url, headers=HEADERS, allow_redirects=False, timeout=TIMEOUT)
                            location = r.headers.get('Location', '')
                            if r.status_code in (301, 302, 303, 307, 308) and test_domain.split('//')[1] in location:
                                poc = test_url
                                if poc not in seen_pocs:
                                    seen_pocs.add(poc)
                                    findings.append(
                                        f"Medium - Open Redirect Found (Query Param) | "
                                        f"Parameter: {param} | "
                                        f"PoC: {poc} | "
                                        f"Location: {page_url}"
                                    )
                        except:
                            pass

        # === 2. Link testing (href with redirect patterns) ===
        soup = BeautifulSoup(resp.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(page_url, href)

            if any(p in href.lower() for p in redirect_params):
                for payload in ["//www.google.com", "https://www.google.com"]:
                    test_href = href.replace('=', f'={payload}')
                    test_full = urljoin(page_url, test_href)

                    try:
                        r = requests.get(test_full, headers=HEADERS, allow_redirects=False, timeout=TIMEOUT)
                        location = r.headers.get('Location', '')
                        if r.status_code in (301, 302, 303, 307, 308) and test_domain.split('//')[1] in location:
                            poc = test_full
                            if poc not in seen_pocs:
                                seen_pocs.add(poc)
                                findings.append(
                                    f"Medium - Open Redirect Found (Link) | "
                                    f"PoC: {poc} | "
                                    f"Location: {page_url}"
                                )
                                break
                    except:
                        pass

        # === 3. Meta refresh & JavaScript redirects ===
        # Meta refresh
        meta_refresh = soup.find('meta', attrs={'http-equiv': 'refresh'})
        if meta_refresh and meta_refresh.get('content'):
            content = meta_refresh['content']
            if any(p in content.lower() for p in redirect_params):
                findings.append(f"Low - Possible Open Redirect via Meta Refresh | Location: {page_url}")

        # Basic JS redirect detection (location.href, window.location)
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and any(word in script.string.lower() for word in ['location.href', 'window.location', 'location.assign']):
                if any(p in script.string.lower() for p in redirect_params):
                    findings.append(f"Low - Possible Open Redirect via JavaScript | Location: {page_url}")
                    break

    if not findings:
        findings.append("✅ No open redirect vulnerabilities detected.")

    return findings
