from flask import Flask, render_template, request, jsonify
import threading
import uuid
import time
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from config import HEADERS, MAX_PAGES, CRAWL_DELAY, TIMEOUT, REPORTS_FOLDER, MODULE_DISPLAY_NAMES
from modules import security_headers, xss, sqli, open_redirect, tech_stack

app = Flask(__name__)

# Global scan status store (scan_id -> {progress, status, message})
SCAN_STATUS = {}
SCAN_LOCK = threading.Lock()

# Shared deep crawler (used by all modules for multi-page scanning)
def deep_crawl(start_url):
    visited = set()
    to_visit = [start_url]
    pages = []  # list of (url, response)

    while to_visit and len(pages) < MAX_PAGES:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            if resp.status_code == 200:
                pages.append((url, resp))
                soup = BeautifulSoup(resp.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href'])
                    parsed = urlparse(full_url)
                    if parsed.netloc == urlparse(start_url).netloc and full_url not in visited:
                        to_visit.append(full_url)
        except Exception as e:
            print(f"Crawl error on {url}: {e}")

        time.sleep(CRAWL_DELAY)  # Polite delay

    return pages

# Registry of modules (auto-discovered from modules/ folder)
VULN_MODULES = {
    "security_headers": security_headers.scan,
    "xss": xss.scan,
    "sqli": sqli.scan,
    "open_redirect": open_redirect.scan,
    "tech_stack": tech_stack.scan,
}

@app.route("/", methods=["GET", "POST"])
def index():
    scan_results = []
    scanning = False

    if request.method == "POST":
        # Require an explicit manual marker set by the launch button to avoid accidental scans
        manual_flag = request.form.get("manual", "0")
        target_url = request.form.get("url", "").strip()
        selected = request.form.getlist("modules")  # list of selected module keys like ['xss', 'tech_stack']

        # If the POST did not come from the explicit Launch button, do not start scanning
        if manual_flag != '1':
            scan_results = ["Scan not started — click LAUNCH DEEP SCAN to begin a manual scan."]
            return render_template("index.html",
                                   results=scan_results,
                                   modules=MODULE_DISPLAY_NAMES.items(),
                                   scanning=False,
                                   scan_id=None)

        if not target_url.startswith(('http://', 'https://')):
            scan_results = ["Error: Please enter a full URL starting with http:// or https://"]
        elif not selected:
            scan_results = ["Error: Select at least one vulnerability module"]
        else:
            scanning = True
            scan_id = str(uuid.uuid4())
            with SCAN_LOCK:
                SCAN_STATUS[scan_id] = {"progress": 1, "status": "running", "message": "Scan queued"}

            def run_scan(scan_id):
                print(f"Deep scan started → Target: {target_url}")
                print(f"Selected modules: {', '.join(selected)}")
                all_findings = []

                # Perform deep crawl once (shared across modules)
                print("Performing deep crawl...")
                with SCAN_LOCK:
                    SCAN_STATUS[scan_id]["progress"] = 10
                    SCAN_STATUS[scan_id]["message"] = "Crawling site"
                pages = deep_crawl(target_url)

                with SCAN_LOCK:
                    SCAN_STATUS[scan_id]["progress"] = 35
                    SCAN_STATUS[scan_id]["message"] = f"Crawled {len(pages)} page(s)"

                # Run each selected module and update progress
                per_mod = 0
                if selected:
                    per_mod = 50 / len(selected)
                current = 35
                for mod_key in selected:
                    if mod_key in VULN_MODULES:
                        print(f"Running deep scan: {MODULE_DISPLAY_NAMES.get(mod_key, mod_key)}")
                        try:
                            module_findings = VULN_MODULES[mod_key](target_url, pages)
                            all_findings.extend(module_findings)
                        except Exception as e:
                            all_findings.append(f"Error in {mod_key} module: {str(e)}")
                        current += per_mod
                        with SCAN_LOCK:
                            SCAN_STATUS[scan_id]["progress"] = int(min(95, current))
                            SCAN_STATUS[scan_id]["message"] = f"Running: {MODULE_DISPLAY_NAMES.get(mod_key, mod_key)}"

                if not all_findings:
                    all_findings.append("No issues detected with the selected modules on this target.")

                # Save detailed report
                timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
                report_path = os.path.join(REPORTS_FOLDER, f"vuln_scan_{timestamp}.txt")
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write(f"Deep Vulnerability Scan Report\n")
                    f.write(f"Target: {target_url}\n")
                    f.write(f"Modules: {', '.join([MODULE_DISPLAY_NAMES.get(m, m) for m in selected])}\n")
                    f.write(f"Pages crawled: {len(pages)}\n")
                    f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    f.write("\n".join(all_findings))
                    f.write("\n\n--- End of Report ---")

                print(f"Scan complete! Report saved: {report_path}")
                with SCAN_LOCK:
                    SCAN_STATUS[scan_id]["progress"] = 100
                    SCAN_STATUS[scan_id]["status"] = "completed"
                    SCAN_STATUS[scan_id]["message"] = f"Completed — report: {os.path.basename(report_path)}"
            threading.Thread(target=run_scan, args=(scan_id,)).start()
            scan_results = [
                f"Deep scan started with {len(selected)} module(s)...",
                "Check your terminal for live progress.",
                "Refresh this page after completion to see summary (full details always in reports/ folder)."
            ]
            # Pass scan_id to template so client can poll status
            return render_template("index.html",
                                   results=scan_results,
                                   modules=MODULE_DISPLAY_NAMES.items(),
                                   scanning=scanning,
                                   scan_id=scan_id)

    return render_template("index.html",
                           results=scan_results,
                           modules=MODULE_DISPLAY_NAMES.items(),
                           scanning=scanning,
                           scan_id=None)


@app.route('/status/<scan_id>')
def status(scan_id):
    with SCAN_LOCK:
        data = SCAN_STATUS.get(scan_id)
    if not data:
        # Return a neutral response (200) so clients polling won't log repeated errors.
        return jsonify({"progress": 0, "status": "unknown", "message": "Unknown scan id"})
    return jsonify(data)


if __name__ == "__main__":
    print("Deep Vulnerability Scanner Dashboard started!")
    print("Open in browser: http://127.0.0.1:5000")
    # Disable the reloader so background scan status remains in the same process
    app.run(debug=True, use_reloader=False)

