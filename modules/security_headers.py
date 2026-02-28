# modules/security_headers.py
# Deep Security Headers Checker - Passive, checks ALL crawled pages
from config import HEADERS

def scan(target_url, pages):
    """
    Deep scan for missing security headers across multiple pages.
    Returns list of clear findings with severity and location.
    """
    findings = []
    seen = set()   # Prevent duplicate reports

    for url, resp in pages:
        headers = resp.headers

        # Core security headers we check
        important_headers = {
            'Content-Security-Policy': 'High - Missing CSP → XSS & Clickjacking possible',
            'X-Frame-Options': 'Medium - Missing X-Frame-Options → Clickjacking risk',
            'Strict-Transport-Security': 'High - Missing HSTS → No forced HTTPS (MITM risk)',
            'X-Content-Type-Options': 'Medium - Missing X-Content-Type-Options → MIME sniffing',
            'Referrer-Policy': 'Low - Missing Referrer-Policy → Information leakage',
            'Permissions-Policy': 'Low - Missing Permissions-Policy → Feature control missing',
        }

        for header, message in important_headers.items():
            if header not in headers:
                key = f"{header}_{url}"
                if key not in seen:
                    seen.add(key)
                    findings.append(f"{message} | Location: {url}")

        # Server / technology exposure
        if 'Server' in headers:
            server = headers['Server']
            key = f"Server_{server}_{url}"
            if key not in seen:
                seen.add(key)
                findings.append(f"Low - Server banner exposed: {server} | Location: {url}")

        if 'X-Powered-By' in headers:
            powered = headers['X-Powered-By']
            findings.append(f"Low - Technology exposed: X-Powered-By = {powered} | Location: {url}")

        # Extra common weak headers
        if 'X-AspNet-Version' in headers or 'X-AspNetMvc-Version' in headers:
            findings.append(f"Low - ASP.NET version exposed | Location: {url}")

    if not findings:
        findings.append("✅ No missing security headers found (site is well configured).")

    return findings
