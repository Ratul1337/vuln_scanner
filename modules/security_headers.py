# modules/security_headers.py
# Advanced Security Headers Analyzer
# Techniques : Presence check, value quality analysis, CSP policy parsing,
#              HSTS preload validation, CORS misconfiguration, cookie flags,
#              information disclosure, cache control audit
# Features   : Per-header scoring, site-wide aggregation, structured findings,
#              remediation guidance, concurrent page analysis
from config import HEADERS, TIMEOUT
import re
import hashlib
import logging
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────

@dataclass
class Finding:
    severity:    str        # Critical / High / Medium / Low / Info
    category:    str        # Missing / Weak / Exposed / Misconfigured
    header:      str        # Header name (or "Cookie" / "Meta" etc.)
    url:         str
    detail:      str        # What exactly is wrong
    fix:         str        # Remediation one-liner
    value:       str = ""   # Actual header value if present

    def __str__(self):
        val_part = f" | value={self.value!r}" if self.value else ""
        return (f"[{self.severity}] {self.category} | {self.header}{val_part}\n"
                f"    detail : {self.detail}\n"
                f"    fix    : {self.fix}\n"
                f"    url    : {self.url}")

    def dedup_key(self) -> str:
        return hashlib.md5(f"{self.header}:{self.category}:{self.url}".encode()).hexdigest()


# ─────────────────────────────────────────────
# Header policy definitions
# ─────────────────────────────────────────────

# Headers that must be present
REQUIRED_HEADERS: list[dict] = [
    dict(
        name     = "Strict-Transport-Security",
        severity = "High",
        fix      = "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ),
    dict(
        name     = "Content-Security-Policy",
        severity = "High",
        fix      = "Add a CSP policy. Minimum: Content-Security-Policy: default-src 'self'",
    ),
    dict(
        name     = "X-Content-Type-Options",
        severity = "Medium",
        fix      = "Add: X-Content-Type-Options: nosniff",
    ),
    dict(
        name     = "X-Frame-Options",
        severity = "Medium",
        fix      = "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors instead)",
    ),
    dict(
        name     = "Referrer-Policy",
        severity = "Low",
        fix      = "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    dict(
        name     = "Permissions-Policy",
        severity = "Low",
        fix      = "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    ),
    dict(
        name     = "Cross-Origin-Opener-Policy",
        severity = "Medium",
        fix      = "Add: Cross-Origin-Opener-Policy: same-origin",
    ),
    dict(
        name     = "Cross-Origin-Resource-Policy",
        severity = "Medium",
        fix      = "Add: Cross-Origin-Resource-Policy: same-origin",
    ),
    dict(
        name     = "Cross-Origin-Embedder-Policy",
        severity = "Low",
        fix      = "Add: Cross-Origin-Embedder-Policy: require-corp",
    ),
]

# Headers that should NOT be present (information disclosure)
DISCLOSURE_HEADERS: list[dict] = [
    dict(name="Server",              severity="Low",
         fix="Remove or genericise the Server header in your web server config."),
    dict(name="X-Powered-By",        severity="Low",
         fix="Remove X-Powered-By (e.g. php.ini: expose_php=Off)."),
    dict(name="X-AspNet-Version",    severity="Low",
         fix="Remove: <httpRuntime enableVersionHeader='false'/>"),
    dict(name="X-AspNetMvc-Version", severity="Low",
         fix="Remove: MvcHandler.DisableMvcResponseHeader = true;"),
    dict(name="X-Generator",         severity="Low",
         fix="Remove X-Generator from your CMS/framework response headers."),
    dict(name="X-Drupal-Cache",      severity="Low",
         fix="Configure Drupal to strip debug headers in production."),
    dict(name="X-Varnish",           severity="Info",
         fix="Consider removing X-Varnish to avoid infrastructure disclosure."),
    dict(name="Via",                 severity="Info",
         fix="Consider removing Via header to limit proxy topology disclosure."),
]


# ─────────────────────────────────────────────
# Value-quality analysers
# ─────────────────────────────────────────────

def _analyse_hsts(value: str, url: str) -> list[Finding]:
    issues = []
    lower  = value.lower()

    m = re.search(r"max-age\s*=\s*(\d+)", lower)
    if not m:
        issues.append(Finding(
            severity = "High", category = "Weak",
            header   = "Strict-Transport-Security", url = url,
            detail   = "max-age directive missing from HSTS header",
            fix      = "Set max-age to at least 31536000 (1 year)",
            value    = value,
        ))
    elif int(m.group(1)) < 15_552_000:  # < 180 days
        issues.append(Finding(
            severity = "Medium", category = "Weak",
            header   = "Strict-Transport-Security", url = url,
            detail   = f"max-age={m.group(1)} is below the recommended 180 days (15552000)",
            fix      = "Increase max-age to at least 31536000",
            value    = value,
        ))

    if "includesubdomains" not in lower:
        issues.append(Finding(
            severity = "Low", category = "Weak",
            header   = "Strict-Transport-Security", url = url,
            detail   = "includeSubDomains not set — subdomains can be accessed over HTTP",
            fix      = "Append ; includeSubDomains",
            value    = value,
        ))

    if "preload" not in lower:
        issues.append(Finding(
            severity = "Info", category = "Weak",
            header   = "Strict-Transport-Security", url = url,
            detail   = "preload directive missing — domain not eligible for HSTS preload list",
            fix      = "Append ; preload and submit to hstspreload.org",
            value    = value,
        ))
    return issues


def _analyse_csp(value: str, url: str) -> list[Finding]:
    issues = []
    lower  = value.lower()

    dangerous = {
        "'unsafe-inline'": ("High",   "unsafe-inline allows inline script execution, negating XSS protection"),
        "'unsafe-eval'":   ("High",   "unsafe-eval allows eval(), a major XSS risk"),
        "data:":           ("Medium", "data: URIs in CSP can be used to load attacker-controlled content"),
        "*":               ("High",   "Wildcard (*) source defeats CSP entirely"),
        "http:":           ("Medium", "http: source scheme allows loading resources over plain HTTP"),
    }
    for token, (sev, detail) in dangerous.items():
        if token in lower:
            issues.append(Finding(
                severity = sev, category = "Weak",
                header   = "Content-Security-Policy", url = url,
                detail   = detail,
                fix      = f"Remove {token!r} from your CSP policy",
                value    = value[:200],
            ))

    if "default-src" not in lower and "script-src" not in lower:
        issues.append(Finding(
            severity = "Medium", category = "Weak",
            header   = "Content-Security-Policy", url = url,
            detail   = "CSP lacks default-src and script-src — policy is incomplete",
            fix      = "Add at minimum: default-src 'self'",
            value    = value[:200],
        ))
    return issues


def _analyse_xcto(value: str, url: str) -> list[Finding]:
    if value.strip().lower() != "nosniff":
        return [Finding(
            severity = "Medium", category = "Weak",
            header   = "X-Content-Type-Options", url = url,
            detail   = f"Value should be 'nosniff', got: {value!r}",
            fix      = "Set X-Content-Type-Options: nosniff",
            value    = value,
        )]
    return []


def _analyse_xfo(value: str, url: str) -> list[Finding]:
    valid = {"deny", "sameorigin"}
    if value.strip().lower() not in valid:
        return [Finding(
            severity = "Medium", category = "Weak",
            header   = "X-Frame-Options", url = url,
            detail   = f"Unrecognised value: {value!r}. Expected DENY or SAMEORIGIN.",
            fix      = "Use X-Frame-Options: DENY or migrate to CSP frame-ancestors",
            value    = value,
        )]
    return []


def _analyse_referrer(value: str, url: str) -> list[Finding]:
    weak_policies = {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}
    if value.strip().lower() in weak_policies:
        return [Finding(
            severity = "Low", category = "Weak",
            header   = "Referrer-Policy", url = url,
            detail   = f"{value!r} leaks full URL in Referer header to third parties",
            fix      = "Use: strict-origin-when-cross-origin or no-referrer",
            value    = value,
        )]
    return []


def _analyse_cors(value: str, url: str) -> list[Finding]:
    """Check Access-Control-Allow-Origin for open CORS."""
    issues = []
    if value.strip() == "*":
        issues.append(Finding(
            severity = "High", category = "Misconfigured",
            header   = "Access-Control-Allow-Origin", url = url,
            detail   = "Wildcard CORS (*) allows any origin to read cross-origin responses",
            fix      = "Restrict to specific trusted origins: Access-Control-Allow-Origin: https://your-domain.com",
            value    = value,
        ))
    return issues


def _analyse_cache(value: str, url: str) -> list[Finding]:
    """Flag pages returning sensitive cache directives."""
    lower = value.lower()
    if "no-store" not in lower and "private" not in lower:
        return [Finding(
            severity = "Low", category = "Weak",
            header   = "Cache-Control", url = url,
            detail   = "Response may be cached by intermediaries — ensure sensitive pages use no-store",
            fix      = "Add: Cache-Control: no-store, no-cache, must-revalidate",
            value    = value,
        )]
    return []


def _analyse_cookies(raw_header: str, url: str) -> list[Finding]:
    """Inspect Set-Cookie values for missing security flags."""
    issues = []
    lower = raw_header.lower()
    name_match = re.match(r"([^=]+)=", raw_header)
    cookie_name = name_match.group(1).strip() if name_match else "unknown"

    if "secure" not in lower:
        issues.append(Finding(
            severity = "High", category = "Missing",
            header   = f"Cookie({cookie_name})", url = url,
            detail   = "Secure flag missing — cookie transmitted over HTTP",
            fix      = "Add Secure flag to Set-Cookie",
            value    = raw_header[:120],
        ))
    if "httponly" not in lower:
        issues.append(Finding(
            severity = "High", category = "Missing",
            header   = f"Cookie({cookie_name})", url = url,
            detail   = "HttpOnly flag missing — cookie accessible via JavaScript (XSS risk)",
            fix      = "Add HttpOnly flag to Set-Cookie",
            value    = raw_header[:120],
        ))
    samesite = re.search(r"samesite\s*=\s*(\w+)", lower)
    if not samesite:
        issues.append(Finding(
            severity = "Medium", category = "Missing",
            header   = f"Cookie({cookie_name})", url = url,
            detail   = "SameSite attribute missing — CSRF risk",
            fix      = "Add SameSite=Strict or SameSite=Lax to Set-Cookie",
            value    = raw_header[:120],
        ))
    elif samesite.group(1) == "none" and "secure" not in lower:
        issues.append(Finding(
            severity = "High", category = "Misconfigured",
            header   = f"Cookie({cookie_name})", url = url,
            detail   = "SameSite=None requires Secure flag",
            fix      = "Add Secure flag when using SameSite=None",
            value    = raw_header[:120],
        ))
    return issues


# ─────────────────────────────────────────────
# Per-page analyser
# ─────────────────────────────────────────────

def _analyse_page(url: str, headers: dict) -> list[Finding]:
    findings: list[Finding] = []
    h_lower = {k.lower(): v for k, v in headers.items()}

    # ── 1. Required header presence ───────────────────────────────────
    for spec in REQUIRED_HEADERS:
        hdr = spec["name"]
        if hdr not in headers:
            findings.append(Finding(
                severity = spec["severity"],
                category = "Missing",
                header   = hdr,
                url      = url,
                detail   = f"{hdr} header is absent",
                fix      = spec["fix"],
            ))

    # ── 2. Value quality checks on present headers ─────────────────
    checks = {
        "Strict-Transport-Security":  _analyse_hsts,
        "Content-Security-Policy":    _analyse_csp,
        "X-Content-Type-Options":     _analyse_xcto,
        "X-Frame-Options":            _analyse_xfo,
        "Referrer-Policy":            _analyse_referrer,
        "Access-Control-Allow-Origin":_analyse_cors,
        "Cache-Control":              _analyse_cache,
    }
    for hdr, analyser in checks.items():
        if hdr in headers:
            findings.extend(analyser(headers[hdr], url))

    # ── 3. Information disclosure ──────────────────────────────────
    for spec in DISCLOSURE_HEADERS:
        hdr = spec["name"]
        if hdr in headers:
            val = headers[hdr]
            findings.append(Finding(
                severity = spec["severity"],
                category = "Exposed",
                header   = hdr,
                url      = url,
                detail   = f"Header discloses infrastructure info: {val!r}",
                fix      = spec["fix"],
                value    = val,
            ))

    # ── 4. Cookie flag audit ───────────────────────────────────────
    for raw_cookie in headers.get("Set-Cookie", "").splitlines():
        if raw_cookie.strip():
            findings.extend(_analyse_cookies(raw_cookie, url))

    # ── 5. HTTPS check from URL ────────────────────────────────────
    if urlparse(url).scheme == "http":
        findings.append(Finding(
            severity = "High", category = "Misconfigured",
            header   = "Transport",
            url      = url,
            detail   = "Page served over plain HTTP — all traffic is unencrypted",
            fix      = "Enable TLS and redirect HTTP → HTTPS",
        ))

    return findings


# ─────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────

def scan(target_url: str, pages: list[tuple[str, object]]) -> list[str]:
    """
    Advanced security headers analysis across all crawled pages.

    Args:
        target_url : root URL (used for context)
        pages      : list of (url, response) tuples

    Returns:
        List of human-readable finding strings.
    """
    all_findings: list[Finding] = []
    seen_dedup:   set[str]      = set()

    # ── Concurrent page analysis ──────────────────────────────────────
    with ThreadPoolExecutor(max_workers=min(10, max(1, len(pages)))) as executor:
        futures = {
            executor.submit(_analyse_page, url, dict(resp.headers)): url
            for url, resp in pages
        }
        for future in as_completed(futures):
            try:
                for finding in future.result():
                    key = finding.dedup_key()
                    if key not in seen_dedup:
                        seen_dedup.add(key)
                        all_findings.append(finding)
            except Exception as exc:
                logger.warning("Header analysis worker raised: %s", exc)

    if not all_findings:
        return ["✅ All security headers are present and correctly configured."]

    # ── Sort by severity ──────────────────────────────────────────────
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    all_findings.sort(key=lambda f: order.get(f.severity, 9))

    # ── Summary counts ────────────────────────────────────────────────
    counts = {}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  ".join(f"{s}:{n}" for s, n in counts.items())

    output = [f"⚠️  {len(all_findings)} header issue(s) found  [{summary}]\n"]
    for i, f in enumerate(all_findings, 1):
        output.append(f"  [{i}] {f}\n")

    return output
