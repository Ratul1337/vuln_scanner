# 🚀 NEON VULN SCANNER

A clean, modular, deep web vulnerability scanner with a stunning cyberpunk dashboard.

(Built for educational purposes and authorized penetration testing.)

## ✨ Features

- **5 Independent Modules** (each in its own file):
  - Security Headers (Passive)
  - Reflected XSS (Active - Deep with 25+ payloads)
  - SQL Injection (Active - Deep: error, boolean, time-based)
  - Open Redirect (Active)
  - Tech Stack & Outdated Services + **Real CVE Lookup** (Wappalyzer + NVD)

- Modern neon cyberpunk dashboard (Tailwind + animations + confetti)
- Deep crawler (scans up to 12 pages)
- Clean text reports with PoCs
- Fully modular — super easy to add new modules

## ⚠️ IMPORTANT LEGAL WARNING

**Only scan websites you own or have explicit written permission for.**  
Unauthorized scanning is illegal in most countries.  
This tool is for learning and authorized bug bounty / pentesting only.

## Installation

```bash
git clone https://github.com/YOUR-USERNAME/vuln-scanner.git
cd vuln-scanner

python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate

pip install -r requirements.txt


How to Run

python app.py

Then open http://127.0.0.1:5000 in your browser.

License
MIT License — feel free to use and modify.

Made with ❤️ for educational purposes only.
Github - @ratul1337
