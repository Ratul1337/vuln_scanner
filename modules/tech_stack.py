# modules/tech_stack.py
# Advanced Tech Stack Fingerprinting + CVE Intelligence
# Techniques : Header analysis, HTML/meta parsing, JS library detection,
#              cookie fingerprinting, favicon hash, CSP/CORS analysis,
#              Wappalyzer integration, NVD CVE enrichment
# Features   : Concurrent CVE lookups, version normalisation, confidence
#              scoring, CVSS v3.1 severity, structured findings
from config import HEADERS, TIMEOUT
import requests
import re
import hashlib
import logging
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

try:
    from Wappalyzer import Wappalyzer, WebPage
    _WAPPALYZER_OK = True
except ImportError:
    _WAPPALYZER_OK = False

logger = logging.getLogger(__name__)

NVD_API   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY = 0.7   # seconds between NVD requests (rate-limit friendly)


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class TechEntry:
    name:       str
    version:    str        # "" if unknown
    confidence: int        # 0–100
    source:     str        # wappalyzer / header / meta / html / js / cookie / favicon
    category:   str = ""   # CMS, Web Server, JS Framework, etc.

    def version_label(self) -> str:
        return self.version if self.version else "unknown version"

    def dedup_key(self) -> str:
        return f"{self.name.lower()}:{self.version.lower()}"


@dataclass
class CveRecord:
    cve_id:      str
    severity:    str    # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    cvss_score:  float
    description: str
    url:         str


@dataclass
class Finding:
    severity:  str         # Critical / High / Medium / Low / Info
    tech:      TechEntry
    cves:      list[CveRecord] = field(default_factory=list)
    note:      str = ""

    def __str__(self):
        base = (f"[{self.severity}] {self.tech.name} {self.tech.version_label()} "
                f"(confidence={self.tech.confidence}%, src={self.tech.source})")
        if self.note:
            base += f" | {self.note}"
        for c in self.cves:
            base += (f"\n    └─ {c.cve_id} [{c.severity} {c.cvss_score}] "
                     f"{c.description[:120]}... → {c.url}")
        return base


# ─────────────────────────────────────────────
# Signature-based fingerprint rules
# ─────────────────────────────────────────────

# (regex-on-header-value, tech-name, category, version-capture-group-or-None)
HEADER_RULES: list[tuple[str, str, str, Optional[str]]] = [
    # Web servers
    (r"Apache(?:/(\d[\d.]+))?",           "Apache",          "Web Server",    r"Apache/(\d[\d.]+)"),
    (r"nginx(?:/(\d[\d.]+))?",            "nginx",           "Web Server",    r"nginx/(\d[\d.]+)"),
    (r"Microsoft-IIS(?:/(\d[\d.]+))?",    "IIS",             "Web Server",    r"IIS/(\d[\d.]+)"),
    (r"LiteSpeed",                        "LiteSpeed",       "Web Server",    None),
    (r"cloudflare",                       "Cloudflare",      "CDN",           None),
    (r"AmazonS3",                         "Amazon S3",       "Cloud Storage", None),
    # App servers / frameworks via X-Powered-By
    (r"PHP(?:/(\d[\d.]+))?",              "PHP",             "Language",      r"PHP/(\d[\d.]+)"),
    (r"Express",                          "Express.js",      "JS Framework",  None),
    (r"ASP\.NET(?: (\d[\d.]+))?",         "ASP.NET",         "Framework",     r"ASP\.NET (\d[\d.]+)"),
    (r"Django/(\d[\d.]+)",                "Django",          "Framework",     r"Django/(\d[\d.]+)"),
    (r"Laravel",                          "Laravel",         "Framework",     None),
    # Caching / proxies
    (r"Varnish",                          "Varnish",         "Cache",         None),
    (r"Squid/(\d[\d.]+)",                 "Squid",           "Proxy",         r"Squid/(\d[\d.]+)"),
]

# (regex-on-full-HTML, tech-name, category, version-group)
HTML_RULES: list[tuple[str, str, str, Optional[str]]] = [
    (r"wp-content",                           "WordPress",       "CMS",         None),
    (r"wp-includes",                          "WordPress",       "CMS",         None),
    (r'<meta[^>]+generator[^>]+WordPress ([0-9.]+)', "WordPress","CMS",        r"WordPress ([0-9.]+)"),
    (r"Joomla",                               "Joomla",          "CMS",         None),
    (r"Drupal",                               "Drupal",          "CMS",         None),
    (r"Magento",                              "Magento",         "E-Commerce",  None),
    (r"Shopify",                              "Shopify",         "E-Commerce",  None),
    (r"react(?:\.min)?\.js",                  "React",           "JS Library",  None),
    (r"angular(?:\.min)?\.js",                "AngularJS",       "JS Library",  None),
    (r"vue(?:\.min)?\.js",                    "Vue.js",          "JS Library",  None),
    (r"jquery(?:[-.])([\d.]+)(?:\.min)?\.js", "jQuery",          "JS Library",  r"jquery[-.]([0-9.]+)"),
    (r"bootstrap(?:[-.])([\d.]+)",            "Bootstrap",       "UI Library",  r"bootstrap[-.]([0-9.]+)"),
    (r"next(?:js)?/([0-9.]+)",                "Next.js",         "JS Framework",r"next(?:js)?/([0-9.]+)"),
    (r"nuxt(?:js)?",                          "Nuxt.js",         "JS Framework",None),
    (r"laravel-token",                        "Laravel",         "Framework",   None),
    (r"csrfmiddlewaretoken",                  "Django",          "Framework",   None),
    (r"__rails_asset_id",                     "Ruby on Rails",   "Framework",   None),
    (r"Powered by Discourse",                 "Discourse",       "Forum",       None),
    (r"confluence",                           "Confluence",      "Wiki",        None),
    (r"jira",                                 "Jira",            "Issue Tracker",None),
    (r"Grafana",                              "Grafana",         "Analytics",   None),
]

# Cookie name patterns
COOKIE_RULES: list[tuple[str, str, str]] = [
    (r"PHPSESSID",       "PHP",              "Language"),
    (r"JSESSIONID",      "Java / Tomcat",    "App Server"),
    (r"ASP\.NET_SessionId", "ASP.NET",       "Framework"),
    (r"laravel_session", "Laravel",          "Framework"),
    (r"wp-settings",     "WordPress",        "CMS"),
    (r"_rails_session",  "Ruby on Rails",    "Framework"),
    (r"connect\.sid",    "Express.js/Node",  "JS Framework"),
    (r"CFID|CFTOKEN",    "ColdFusion",       "Language"),
    (r"AWSALB",          "AWS ALB",          "Load Balancer"),
    (r"__cfduid|cf_clearance", "Cloudflare", "CDN"),
]

# Security header presence / absence analysis
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy":   "CSP",
    "X-Frame-Options":           "Clickjacking protection",
    "X-Content-Type-Options":    "MIME sniffing protection",
    "Referrer-Policy":           "Referrer Policy",
    "Permissions-Policy":        "Permissions Policy",
    "Cross-Origin-Opener-Policy":"COOP",
    "Cross-Origin-Resource-Policy":"CORP",
}


# ─────────────────────────────────────────────
# Fingerprinting engine
# ─────────────────────────────────────────────

def _extract_version(text: str, pattern: Optional[str]) -> str:
    if not pattern:
        return ""
    m = re.search(pattern, text, re.I)
    return m.group(1) if m and m.lastindex else ""


def _fingerprint_headers(headers: dict) -> list[TechEntry]:
    entries = []
    combined = " ".join(f"{k}: {v}" for k, v in headers.items())
    for header_name in ("Server", "X-Powered-By", "Via", "X-Generator",
                        "X-AspNet-Version", "X-AspNetMvc-Version"):
        val = headers.get(header_name, "")
        if not val:
            continue
        for pattern, name, cat, ver_pattern in HEADER_RULES:
            if re.search(pattern, val, re.I):
                ver = _extract_version(val, ver_pattern)
                entries.append(TechEntry(name, ver, 90, "header", cat))
    return entries


def _fingerprint_html(html: str, url: str) -> list[TechEntry]:
    entries = []
    seen = set()
    for pattern, name, cat, ver_pattern in HTML_RULES:
        m = re.search(pattern, html, re.I)
        if m and name not in seen:
            ver = _extract_version(html, ver_pattern)
            entries.append(TechEntry(name, ver, 75, "html", cat))
            seen.add(name)

    # Meta generator tag
    soup = BeautifulSoup(html, "html.parser")
    gen = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
    if gen and gen.get("content"):
        content = gen["content"]
        # Try to split "WordPress 6.5" into name + version
        parts = content.split(" ", 1)
        tech_name = parts[0].strip()
        ver       = parts[1].strip() if len(parts) > 1 else ""
        key = tech_name.lower()
        if key not in {e.name.lower() for e in entries}:
            entries.append(TechEntry(tech_name, ver, 85, "meta", "CMS/Generator"))

    # WordPress REST API link
    if soup.find("link", attrs={"rel": "https://api.w.org/"}):
        if "wordpress" not in {e.name.lower() for e in entries}:
            entries.append(TechEntry("WordPress", "", 80, "html", "CMS"))

    return entries


def _fingerprint_cookies(cookies: dict) -> list[TechEntry]:
    entries = []
    cookie_str = " ".join(cookies.keys())
    for pattern, name, cat in COOKIE_RULES:
        if re.search(pattern, cookie_str, re.I):
            entries.append(TechEntry(name, "", 65, "cookie", cat))
    return entries


def _fingerprint_favicon(base_url: str, session: requests.Session) -> Optional[TechEntry]:
    """
    Fetch /favicon.ico, hash it with MD5, and compare against a small
    lookup table of well-known CMS/framework favicons.
    """
    KNOWN_FAVICONS = {
        "1f4c4dc43a2f2a5e53f0e7e3e1b1f2c0": ("WordPress",  "CMS"),
        "d41d8cd98f00b204e9800998ecf8427e": ("(empty)",    ""),   # empty favicon
        "cf566699ef04ddb5fd34af02ada01e3c": ("Joomla",     "CMS"),
        "8e1d3ec2eab0c0f7d9d0b4fb59e53e1e": ("Drupal",     "CMS"),
        "c3d3d17c7e5ad46da0aa5b3a0eb0a8cb": ("Grafana",    "Analytics"),
    }
    try:
        favicon_url = urljoin(base_url, "/favicon.ico")
        r = session.get(favicon_url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200 and r.content:
            md5 = hashlib.md5(r.content).hexdigest()
            if md5 in KNOWN_FAVICONS:
                name, cat = KNOWN_FAVICONS[md5]
                return TechEntry(name, "", 70, "favicon", cat)
    except Exception:
        pass
    return None


def _analyse_security_headers(headers: dict) -> list[str]:
    missing = []
    for hdr, label in SECURITY_HEADERS.items():
        if hdr not in headers:
            missing.append(f"Missing security header: {hdr} ({label})")
    return missing


def _wappalyzer_scan(target_url: str) -> list[TechEntry]:
    if not _WAPPALYZER_OK:
        return []
    try:
        webpage = WebPage.new_from_url(target_url, headers=HEADERS, timeout=TIMEOUT)
        wapp    = Wappalyzer.latest()
        detected = wapp.analyze_with_versions_and_categories(webpage)
        entries = []
        for name, data in detected.items():
            ver = data.get("version", "") or ""
            cat = ", ".join(data.get("categories", {}).values()) if data.get("categories") else ""
            entries.append(TechEntry(name, ver, 95, "wappalyzer", cat))
        return entries
    except Exception as exc:
        logger.warning("Wappalyzer error: %s", exc)
        return []


# ─────────────────────────────────────────────
# CVE lookup
# ─────────────────────────────────────────────

def _fetch_cves(tech: TechEntry) -> list[CveRecord]:
    """Query NVD API for CVEs matching tech name + version."""
    if not tech.version:
        return []
    query  = f"{tech.name} {tech.version}".strip()
    params = {"keywordSearch": query, "resultsPerPage": 5}
    records = []
    try:
        r = requests.get(NVD_API, params=params, timeout=12)
        if r.status_code != 200:
            return []
        data  = r.json()
        vulns = data.get("vulnerabilities", [])
        for vuln in vulns[:5]:
            cve_data = vuln.get("cve", {})
            cve_id   = cve_data.get("id", "CVE-????-????")

            # CVSS v3.1 → v3.0 → v2
            metrics  = cve_data.get("metrics", {})
            severity = "UNKNOWN"
            score    = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0].get("cvssData", {})
                    severity  = cvss_data.get("baseSeverity", "UNKNOWN")
                    score     = float(cvss_data.get("baseScore", 0.0))
                    break

            descs = cve_data.get("descriptions", [])
            desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "No description")
            records.append(CveRecord(
                cve_id      = cve_id,
                severity    = severity,
                cvss_score  = score,
                description = desc,
                url         = f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            ))
    except Exception as exc:
        logger.debug("NVD lookup failed for %s: %s", query, exc)
    return records


def _severity_from_cves(cves: list[CveRecord]) -> str:
    if not cves:
        return "Low"
    max_score = max(c.cvss_score for c in cves)
    if max_score >= 9.0: return "Critical"
    if max_score >= 7.0: return "High"
    if max_score >= 4.0: return "Medium"
    return "Low"


# ─────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────

def scan(target_url: str, pages: list[tuple[str, requests.Response]]) -> list[str]:
    """
    Advanced tech stack detection + CVE intelligence scan.

    Args:
        target_url : root URL of the target
        pages      : list of (url, response) tuples from the crawler

    Returns:
        List of human-readable finding strings.
    """
    session = requests.Session()
    tech_map: dict[str, TechEntry] = {}   # dedup_key → best TechEntry

    def register(entry: TechEntry):
        key = entry.dedup_key()
        if key not in tech_map or entry.confidence > tech_map[key].confidence:
            tech_map[key] = entry

    # ── 1. Wappalyzer (highest fidelity) ─────────────────────────────
    for e in _wappalyzer_scan(target_url):
        register(e)

    # ── 2. Favicon hash ───────────────────────────────────────────────
    fav = _fingerprint_favicon(target_url, session)
    if fav:
        register(fav)

    # ── 3. Header + HTML + cookie analysis across first 5 pages ──────
    security_issues: list[str] = []
    for page_url, resp in pages[:5]:
        headers = dict(resp.headers)
        html    = resp.text

        for e in _fingerprint_headers(headers):
            register(e)
        for e in _fingerprint_html(html, page_url):
            register(e)
        for e in _fingerprint_cookies(dict(resp.cookies)):
            register(e)

        # Security header audit (once, from first page)
        if not security_issues:
            security_issues = _analyse_security_headers(headers)

    all_techs = list(tech_map.values())

    if not all_techs:
        return ["ℹ️  No technologies reliably detected."]

    # ── 4. Concurrent CVE lookups ─────────────────────────────────────
    cve_results: dict[str, list[CveRecord]] = {}
    techs_with_version = [t for t in all_techs if t.version]

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_map = {executor.submit(_fetch_cves, t): t for t in techs_with_version}
        for i, future in enumerate(as_completed(future_map)):
            tech = future_map[future]
            try:
                cve_results[tech.dedup_key()] = future.result()
            except Exception as exc:
                logger.debug("CVE future error: %s", exc)
            # Polite NVD rate limiting
            if i % 3 == 2:
                time.sleep(NVD_DELAY)

    # ── 5. Build findings ─────────────────────────────────────────────
    findings: list[Finding] = []

    for tech in sorted(all_techs, key=lambda t: -t.confidence):
        cves     = cve_results.get(tech.dedup_key(), [])
        severity = _severity_from_cves(cves) if cves else (
            "Medium" if not tech.version else "Info"
        )
        note = "" if tech.version else "No version detected — manual check recommended"
        findings.append(Finding(severity=severity, tech=tech, cves=cves, note=note))

    # Sort: CVE findings first, then by severity
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda f: (0 if f.cves else 1, sev_order.get(f.severity, 9)))

    output = [f"🔍 {len(all_techs)} technolog{'y' if len(all_techs)==1 else 'ies'} detected:\n"]
    for i, f in enumerate(findings, 1):
        output.append(f"  [{i}] {f}")

    # ── 6. Security header summary ───────────────────────────────────
    if security_issues:
        output.append("\n⚠️  Security header issues:")
        for issue in security_issues:
            output.append(f"  • {issue}")
    else:
        output.append("\n✅ All standard security headers present.")

    return output
