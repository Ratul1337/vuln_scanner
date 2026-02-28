import os

# ====================== SHARED CONFIG FOR DEEP SCANNING ======================

REPORTS_FOLDER = "reports"
if not os.path.exists(REPORTS_FOLDER):
    os.makedirs(REPORTS_FOLDER)

# Polite headers (helps avoid blocks during deep scanning)
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 VulnScanner/1.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
}

# Crawler settings for DEEP scanning
MAX_PAGES = 12          # How many pages to crawl (deep but safe)
CRAWL_DELAY = 1.2       # Seconds between requests (polite)
TIMEOUT = 8             # Seconds per request

# Common display names for dashboard
MODULE_DISPLAY_NAMES = {
    "security_headers": "Security Headers (Passive)",
    "xss": "Reflected XSS (Active - Deep)",
    "sqli": "SQL Injection (Active - Deep)",
    "open_redirect": "Open Redirect (Active)",
    "tech_stack": "Tech Stack & Outdated Services + CVEs (Deep)"
}
