# WHOip — Ethical IP reconnaissance toolkit

WHOip is a compact, auditable CLI for IP/domain reconnaissance: geolocation, reverse-DNS, WHOIS, concurrent banner grabs, HTTP/TLS fingerprinting, optional Shodan and nmap integration, plus JSON + neon HTML reports.

**Ethics & Legal:** Only run WHOip against systems/networks you own or have explicit written permission to test. Scanning can trigger security alerts and may be illegal without permission.

## Quick install (Debian/Ubuntu)
```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git nmap
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
chmod +x whoip.py
```

## Usage
```bash
# Simple scan (prints JSON)
python3 whoip.py scan example.com

# Save JSON + HTML
python3 whoip.py scan 1.2.3.4 -o reports/1.2.3.4.json --html reports/1.2.3.4.html
```
