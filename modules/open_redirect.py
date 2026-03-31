# modules/open_redirect.py
# Advanced Open Redirect Scanner
# Techniques : Query params, POST bodies, Link hrefs, Meta refresh,
#              JS redirect sinks, Header injection, Path-based redirects
# Features   : Bypass encoding variants, multi-redirect chain following,
#              WAF detection, structured findings, concurrent testing
from config import HEADERS, TIMEOUT
import requests
import re
import hashlib
import logging
from bs4 import BeautifulSoup
from urllib.parse import (
    urljoin, urlparse, parse_qs, urlencode, quote, unquote
)
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────

@dataclass
class Finding:
    severity:    str       # High / Medium / Low / Info
    vector:      str       # QueryParam / PostParam / Link / MetaRefresh / JS / Header / Path
    method:      str       # GET / POST
    url:         str       # PoC URL or endpoint
    parameter:   str
    payload:     str
    redirect_to: str       # actual Location header value or destination
    evidence:    str       # raw confirmation detail
    bypass_used: str = ""  # encoding/bypass technique if non-standard

    def __str__(self):
        bypass = f" [bypass={self.bypass_used}]" if self.bypass_used else ""
        return (f"[{self.severity}] Open Redirect ({self.vector}){bypass} | "
                f"{self.method} {self.url} | param={self.parameter} | "
                f"payload={self.payload!r} → {self.redirect_to!r} | "
                f"evidence={self.evidence!r}")

    def dedup_key(self):
        return hashlib.md5(
            f"{self.url}:{self.parameter}:{self.vector}".encode()
        ).hexdigest()


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

# Canary domain — clearly external, never an actual attack target
CANARY_DOMAIN   = "canary-redirect-test.example.com"
CANARY_HTTPS    = f"https://{CANARY_DOMAIN}"
CANARY_PROTOCOL = f"//{CANARY_DOMAIN}"

# Common redirect parameter names (extended list)
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "redirectUrl",
    "next", "next_url", "nextUrl", "return", "return_to", "returnTo",
    "returnUrl", "return_url", "redir", "redir_url", "r", "go", "goto",
    "to", "target", "dest", "destination", "link", "out", "exit",
    "forward", "location", "continue", "back", "ref", "ref_url",
    "jump", "navigate", "path", "page", "view",
]

# Redirect payload variants (ordered from least to most obfuscated)
REDIRECT_PAYLOADS: list[tuple[str, str]] = [
    # Standard
    (CANARY_HTTPS,                        "plain-https"),
    (CANARY_PROTOCOL,                     "protocol-relative"),
    # Slash bypass
    (f"////{CANARY_DOMAIN}",              "quad-slash"),
    (f"\\\\{CANARY_DOMAIN}",             "backslash"),
    (f"\\/{CANARY_DOMAIN}",              "backslash-slash"),
    # Encoding bypass
    (f"//{quote(CANARY_DOMAIN)}",         "url-encoded-host"),
    (f"%2F%2F{CANARY_DOMAIN}",           "double-encoded-slash"),
    (f"https:%2F%2F{CANARY_DOMAIN}",     "encoded-slash-after-scheme"),
    # Scheme bypass
    (f"HtTpS://{CANARY_DOMAIN}",         "mixed-case-scheme"),
    (f"https://{CANARY_DOMAIN}%23",      "fragment-bypass"),
    (f"https://{CANARY_DOMAIN}?x=1",     "query-appended"),
    # Subdomain / at-sign confusion
    (f"https://trusted@{CANARY_DOMAIN}", "at-sign-confusion"),
    (f"https://{CANARY_DOMAIN}.evil.com","subdomain-confusion"),
    # Whitespace bypass
    (f" {CANARY_HTTPS}",                 "leading-space"),
    (f"\t{CANARY_HTTPS}",               "tab-prefix"),
    # Null byte / newline injection (header injection probe)
    (f"{CANARY_HTTPS}%0d%0aX-Injected: 1", "crlf-injection"),
    # Data URI
    (f"data:text/html,<script>location='{CANARY_HTTPS}'</script>", "data-uri"),
    # JavaScript URI
    (f"javascript:location='{CANARY_HTTPS}'",                      "javascript-uri"),
]

# JS redirect sink patterns
JS_REDIRECT_SINKS = [
    r"location\s*=\s*['\"`]?",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"location\.assign\s*\(",
    r"window\.location\s*=",
    r"window\.navigate\s*\(",
    r"document\.location\s*=",
    r"self\.location\s*=",
    r"top\.location\s*=",
]

# HTTP redirect status codes
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _is_open_redirect(location: str) -> bool:
    """Return True if Location header points to the canary domain."""
    if not location:
        return False
    loc = unquote(location).lower()
    return CANARY_DOMAIN.lower() in loc


def _get_safe(url: str, session: requests.Session,
              allow_redirects: bool = False) -> Optional[requests.Response]:
    try:
        return session.get(url, headers=HEADERS, timeout=TIMEOUT,
                           allow_redirects=allow_redirects)
    except Exception as exc:
        logger.debug("GET error %s: %s", url, exc)
        return None


def _post_safe(url: str, data: dict,
               session: requests.Session) -> Optional[requests.Response]:
    try:
        return session.post(url, data=data, headers=HEADERS,
                            timeout=TIMEOUT, allow_redirects=False)
    except Exception as exc:
        logger.debug("POST error %s: %s", url, exc)
        return None


def _follow_redirect_chain(url: str, session: requests.Session,
                           max_hops: int = 5) -> list[str]:
    """
    Manually follow redirect chain up to max_hops.
    Returns list of Location headers seen.
    """
    chain = []
    current = url
    for _ in range(max_hops):
        r = _get_safe(current, session, allow_redirects=False)
        if r is None or r.status_code not in REDIRECT_STATUSES:
            break
        loc = r.headers.get("Location", "")
        if not loc:
            break
        chain.append(loc)
        current = urljoin(current, loc)
    return chain


def _detect_waf(resp: requests.Response) -> bool:
    waf_headers = {"x-sucuri-id", "x-firewall", "x-waf", "cf-ray", "x-protected-by"}
    if any(h.lower() in {k.lower() for k in resp.headers} for h in waf_headers):
        return True
    waf_bodies = ["access denied", "request blocked", "security check",
                  "you have been blocked", "cloudflare ray id"]
    return any(kw in resp.text.lower() for kw in waf_bodies)


def _inject_param_value(original_url: str, param: str, value: str) -> str:
    """Replace the value of `param` in `original_url` with `value`."""
    parsed  = urlparse(original_url)
    params  = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return parsed._replace(query=new_query).geturl()


# ─────────────────────────────────────────────
# Test workers
# ─────────────────────────────────────────────

def _test_query_param(
    page_url: str,
    param: str,
    session: requests.Session,
) -> list[Finding]:
    findings = []
    for payload, bypass_tag in REDIRECT_PAYLOADS:
        test_url = _inject_param_value(page_url, param, payload)
        r = _get_safe(test_url, session, allow_redirects=False)
        if r is None:
            continue
        location = r.headers.get("Location", "")

        # Direct single-hop redirect
        if r.status_code in REDIRECT_STATUSES and _is_open_redirect(location):
            findings.append(Finding(
                severity    = "High",
                vector      = "QueryParam",
                method      = "GET",
                url         = test_url,
                parameter   = param,
                payload     = payload,
                redirect_to = location,
                evidence    = f"HTTP {r.status_code} Location: {location}",
                bypass_used = bypass_tag if bypass_tag != "plain-https" else "",
            ))
            break  # one confirmed finding per param is enough

        # Multi-hop redirect chain
        if r.status_code in REDIRECT_STATUSES:
            chain = _follow_redirect_chain(test_url, session)
            if any(_is_open_redirect(loc) for loc in chain):
                dest = next(loc for loc in chain if _is_open_redirect(loc))
                findings.append(Finding(
                    severity    = "High",
                    vector      = "QueryParam (chained)",
                    method      = "GET",
                    url         = test_url,
                    parameter   = param,
                    payload     = payload,
                    redirect_to = dest,
                    evidence    = f"Chain: {' → '.join(chain)}",
                    bypass_used = bypass_tag,
                ))
                break

        # CRLF / header injection in redirect
        if "%0d%0a" in payload.lower() or "%0a" in payload.lower():
            if "x-injected" in {k.lower() for k in r.headers}:
                findings.append(Finding(
                    severity    = "High",
                    vector      = "QueryParam (CRLF)",
                    method      = "GET",
                    url         = test_url,
                    parameter   = param,
                    payload     = payload,
                    redirect_to = location,
                    evidence    = "Injected header found in response",
                    bypass_used = "crlf-injection",
                ))
                break

    return findings


def _test_post_param(
    action: str,
    param: str,
    form_inputs: list[str],
    session: requests.Session,
    page_url: str,
) -> list[Finding]:
    findings = []
    for payload, bypass_tag in REDIRECT_PAYLOADS[:8]:  # fewer probes for POST
        data = {name: ("test" if name != param else payload) for name in form_inputs}
        r = _post_safe(action, data, session)
        if r is None:
            continue
        location = r.headers.get("Location", "")
        if r.status_code in REDIRECT_STATUSES and _is_open_redirect(location):
            findings.append(Finding(
                severity    = "High",
                vector      = "PostParam",
                method      = "POST",
                url         = action,
                parameter   = param,
                payload     = payload,
                redirect_to = location,
                evidence    = f"HTTP {r.status_code} Location: {location}",
                bypass_used = bypass_tag if bypass_tag != "plain-https" else "",
            ))
            break
    return findings


def _test_link_param(
    href: str,
    page_url: str,
    session: requests.Session,
) -> list[Finding]:
    """Test a link whose href already contains a redirect-like parameter."""
    findings = []
    parsed = urlparse(href)
    params = parse_qs(parsed.query, keep_blank_values=True)
    for param in params:
        if param.lower() not in {p.lower() for p in REDIRECT_PARAMS}:
            continue
        for payload, bypass_tag in REDIRECT_PAYLOADS[:10]:
            test_href = _inject_param_value(href, param, payload)
            full_url  = urljoin(page_url, test_href)
            r = _get_safe(full_url, session, allow_redirects=False)
            if r is None:
                continue
            location = r.headers.get("Location", "")
            if r.status_code in REDIRECT_STATUSES and _is_open_redirect(location):
                findings.append(Finding(
                    severity    = "High",
                    vector      = "Link",
                    method      = "GET",
                    url         = full_url,
                    parameter   = param,
                    payload     = payload,
                    redirect_to = location,
                    evidence    = f"HTTP {r.status_code} Location: {location}",
                    bypass_used = bypass_tag if bypass_tag != "plain-https" else "",
                ))
                break
    return findings


# ─────────────────────────────────────────────
# Passive analysis (no requests)
# ─────────────────────────────────────────────

def _passive_analysis(page_url: str, html: str) -> list[Finding]:
    """
    Inspect page source for redirect sinks without firing requests.
    Returns Low/Info findings.
    """
    findings = []
    soup = BeautifulSoup(html, "html.parser")

    # Meta refresh
    for meta in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
        content = meta.get("content", "")
        url_match = re.search(r"url\s*=\s*([^\s;\"']+)", content, re.I)
        if url_match:
            dest = url_match.group(1)
            if dest.startswith(("http://", "https://", "//")) and \
               urlparse(dest).netloc != urlparse(page_url).netloc:
                findings.append(Finding(
                    severity    = "Medium",
                    vector      = "MetaRefresh",
                    method      = "GET",
                    url         = page_url,
                    parameter   = "meta[http-equiv=refresh]",
                    payload     = "(static — no injection)",
                    redirect_to = dest,
                    evidence    = f"Meta content: {content[:120]}",
                ))

    # JavaScript redirect sinks with externally controllable data hint
    for script in soup.find_all("script"):
        src = script.string or ""
        if not src:
            continue
        for sink_pattern in JS_REDIRECT_SINKS:
            if re.search(sink_pattern, src, re.I):
                # Flag only if a redirect param name appears nearby
                for param in REDIRECT_PARAMS:
                    if re.search(rf"\b{re.escape(param)}\b", src, re.I):
                        findings.append(Finding(
                            severity    = "Low",
                            vector      = "JS-sink",
                            method      = "GET",
                            url         = page_url,
                            parameter   = param,
                            payload     = "(passive — param feeds JS sink)",
                            redirect_to = "(unknown — runtime)",
                            evidence    = f"Sink '{sink_pattern}' near param '{param}'",
                        ))
                        break
                break  # one finding per script block

    # Inline onclick / href="javascript:..."
    for tag in soup.find_all(True):
        onclick = tag.get("onclick", "")
        if onclick and any(re.search(p, onclick, re.I) for p in JS_REDIRECT_SINKS):
            findings.append(Finding(
                severity    = "Low",
                vector      = "JS-sink (onclick)",
                method      = "GET",
                url         = page_url,
                parameter   = tag.get("name") or tag.get("id") or tag.name,
                payload     = "(passive)",
                redirect_to = "(unknown — runtime)",
                evidence    = f"onclick: {onclick[:100]}",
            ))

    return findings


# ─────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────

def scan(target_url: str, pages: list[tuple[str, requests.Response]]) -> list[str]:
    """
    Advanced Open Redirect scan across all crawled pages.

    Args:
        target_url : root URL of the target
        pages      : list of (url, response) tuples from the crawler

    Returns:
        List of human-readable finding strings.
    """
    all_findings: list[Finding] = []
    seen_dedup:   set[str]      = set()
    session = requests.Session()
    tasks   = []

    for page_url, baseline_resp in pages:
        html = baseline_resp.text

        # ── Passive analysis (no requests needed) ─────────────────────
        for f in _passive_analysis(page_url, html):
            key = f.dedup_key()
            if key not in seen_dedup:
                seen_dedup.add(key)
                all_findings.append(f)

        # ── Active: query parameters ──────────────────────────────────
        parsed = urlparse(page_url)
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param in params:
                if param.lower() in {p.lower() for p in REDIRECT_PARAMS}:
                    tasks.append((_test_query_param,
                                  dict(page_url=page_url, param=param, session=session)))

        # ── Active: links in page ─────────────────────────────────────
        soup = BeautifulSoup(html, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if any(p in href.lower() for p in REDIRECT_PARAMS):
                full_href = urljoin(page_url, href)
                tasks.append((_test_link_param,
                               dict(href=full_href, page_url=page_url, session=session)))

        # ── Active: POST forms ─────────────────────────────────────────
        for form in soup.find_all("form"):
            action     = urljoin(page_url, form.get("action", "") or page_url)
            method_tag = form.get("method", "get").strip().lower()
            if method_tag != "post":
                continue
            form_inputs = [
                inp.get("name")
                for inp in form.find_all(["input", "select", "textarea"])
                if inp.get("name")
            ]
            for param in form_inputs:
                if param.lower() in {p.lower() for p in REDIRECT_PARAMS}:
                    tasks.append((_test_post_param,
                                  dict(action=action, param=param,
                                       form_inputs=form_inputs,
                                       session=session, page_url=page_url)))

    # ── Concurrent active tests ───────────────────────────────────────
    max_workers = min(10, max(1, len(tasks)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fn, **kw): kw for fn, kw in tasks}
        for future in as_completed(futures):
            try:
                for finding in future.result():
                    key = finding.dedup_key()
                    if key not in seen_dedup:
                        seen_dedup.add(key)
                        all_findings.append(finding)
            except Exception as exc:
                logger.warning("Worker raised: %s", exc)

    # ── Sort by severity ──────────────────────────────────────────────
    order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    all_findings.sort(key=lambda f: order.get(f.severity, 9))

    if not all_findings:
        return ["✅ No open redirect vulnerabilities detected."]

    output = [f"⚠️  {len(all_findings)} open redirect finding(s):\n"]
    for i, f in enumerate(all_findings, 1):
        output.append(f"  [{i}] {f}")
    return output
