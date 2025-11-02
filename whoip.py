#!/usr/bin/env python3
"""WHOip — Ethical IP reconnaissance toolkit (updated)
Adds: --delay (seconds between port probes batches), --rate (max probes per second), progress output, and improved CLI for packaging.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import json
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime
from html import escape
from typing import List, Dict, Any, Optional
import shutil
import xml.etree.ElementTree as ET
import threading

try:
    import requests
except Exception:
    print("Missing dependency 'requests'. Install: pip install -r requirements.txt")
    sys.exit(1)

# optional whois lib
try:
    import whois as pywhois
except Exception:
    pywhois = None

# ----------------- Config -----------------
DEFAULT_PORTS = [21,22,23,25,53,80,110,143,443,465,587,3306,3389,8080]
BANNER_THREADS = 20
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,as,query,timezone,zip,reverse,message"


# ----------------- Utilities -----------------
def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

# ----------------- Lookups -----------------
def geo_lookup_ip(ip: str) -> Dict[str,Any]:
    try:
        r = requests.get(IP_API_URL.format(ip=ip), timeout=8)
        data = r.json()
        if data.get("status") != "success":
            return {"error": data.get("message","failed")}
        return data
    except Exception as e:
        return {"error": str(e)}

def rdns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def whois_lookup(target: str) -> Dict[str,Any]:
    if pywhois is None:
        return {"error": "python-whois not installed (pip install python-whois)"}
    try:
        w = pywhois.whois(target)
        # convert to JSON-safe
        return {k: repr(v) for k, v in dict(w).items()}
    except Exception as e:
        return {"error": str(e)}

# ----------------- Concurrency banner grabbing (with throttling) -----------------

def tcp_probe(ip: str, port: int, timeout: float=6.0) -> Optional[str]:
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # attempt to receive a banner
        try:
            s.settimeout(1.0)
            data = s.recv(4096)
            if data:
                return data.decode(errors="replace").strip()
        except Exception:
            pass
        # try an HTTP probe for common web ports
        if port in (80, 8080):
            try:
                s.sendall(b"GET / HTTP/1.0\r\nHost: \r\n\r\n")
                s.settimeout(2.0)
                data = s.recv(8192)
                if data:
                    # return first few lines
                    return "\n".join(data.decode(errors="replace").splitlines()[:8])
            except Exception:
                pass
        return None
    except Exception:
        return None
    finally:
        if s:
            try: s.close()
            except: pass


class ThrottledScanner:
    """Manage rate-limited, threaded probes. Simple token-bucket style."""
    def __init__(self, rate: float = 0.0):
        # rate = max probes per second; <=0 means unlimited
        self.rate = float(rate)
        self._lock = threading.Lock()
        self._tokens = 0.0
        self._last = time.time()

    def wait_for_slot(self):
        if self.rate <= 0:
            return
        with self._lock:
            now = time.time()
            elapsed = now - self._last
            # replenish tokens
            self._tokens += elapsed * self.rate
            if self._tokens > self.rate * 2:
                # cap burst to 2s worth
                self._tokens = self.rate * 2
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
        # else sleep until a token is available
        while True:
            time.sleep(0.01)
            with self._lock:
                now = time.time()
                elapsed = now - self._last
                self._tokens += elapsed * self.rate
                if self._tokens > self.rate * 2:
                    self._tokens = self.rate * 2
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return

def scan_ports_concurrent(ip: str, ports: List[int], threads: int = BANNER_THREADS, rate: float = 0.0, delay: float = 0.0) -> Dict[str,Any]:
    results = {}
    scanner = ThrottledScanner(rate=rate)

    def worker(p):
        # rate-limit before each probe
        scanner.wait_for_slot()
        res = tcp_probe(ip, p)
        results[str(p)] = res
        return p

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(worker, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            p = futures[fut]
            try:
                fut.result()
            except Exception as e:
                results[str(p)] = {"error": str(e)}
            if delay and not fut.cancelled():
                # small polite pause between completed probes to reduce burstiness
                time.sleep(delay)
    return results

# ----------------- HTTP fingerprint -----------------
def http_fingerprint(host: str, timeout: int=8) -> Dict[str,Any]:
    out = {}
    targets = []
    if host.startswith("http://") or host.startswith("https://"):
        targets = [host]
    else:
        targets = [f"http://{host}", f"https://{host}"]
    for t in targets:
        try:
            r = requests.get(t, timeout=timeout, allow_redirects=True, verify=False)
            headers = dict(r.headers)
            title = None
            try:
                body = r.text
                start = body.find("<title")
                if start != -1:
                    start = body.find(">", start) + 1
                    end = body.find("</title>", start)
                    if end != -1:
                        title = body[start:end].strip()
            except Exception:
                pass
            out[t] = {"status_code": r.status_code, "headers": headers, "title": title, "url": r.url}
        except Exception as e:
            out[t] = {"error": str(e)}
    return out

# ----------------- TLS cert -----------------
def tls_info(host: str, port: int = 443, timeout: int = 8) -> Dict[str,Any]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return {"error": str(e)}

# ----------------- Shodan -----------------
def shodan_lookup(ip: str, key: Optional[str]) -> Dict[str,Any]:
    if not key:
        return {"error": "no api key provided"}
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
        r = requests.get(url, timeout=8)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# ----------------- Nmap integration -----------------
def has_nmap() -> bool:
    return shutil.which("nmap") is not None
def run_nmap_xml(target: str, extra_args: Optional[List[str]] = None, timeout: int = 60) -> Dict[str,Any]:
    if not has_nmap():
        return {"error": "nmap not found on PATH"}
    args = ["nmap", "-sV", "-O", "-oX", "-", target]
    if extra_args:
        args = args[:-1] + extra_args + [args[-1]]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        stdout = proc.stdout
        if not stdout:
            return {"error": "nmap produced no xml output", "stderr": proc.stderr}
        root = ET.fromstring(stdout)
        parsed = {"hosts": []}
        for host in root.findall("./host"):
            h = {}
            addr = host.find("address")
            if addr is not None:
                h["address"] = addr.attrib
            ports = []
            for p in host.findall("./ports/port"):
                portnum = p.attrib.get("portid")
                proto = p.attrib.get("protocol")
                state = p.find("state")
                service = p.find("service")
                portinfo = {"port": portnum, "protocol": proto}
                if state is not None:
                    portinfo["state"] = state.attrib
                if service is not None:
                    portinfo["service"] = service.attrib
                ports.append(portinfo)
            if ports:
                h["ports"] = ports
            os_el = host.find("os")
            if os_el is not None:
                h["os"] = ET.tostring(os_el, encoding="unicode")
            parsed["hosts"].append(h)
        return parsed
    except subprocess.TimeoutExpired:
        return {"error": "nmap timed out"}
    except Exception as e:
        return {"error": str(e)}

# ----------------- Reporting (neon) -----------------
NEON_CSS = """
body{background:#0b0f14;color:#bfefff;font-family:Inter,Segoe UI,Arial; padding:24px}
.card{background:linear-gradient(135deg,#061018 0%, rgba(8,12,18,.7) 100%);border-radius:12px;padding:16px;box-shadow:0 6px 30px rgba(0,0,0,.6);} 
.h{font-size:20px;color:#7ef2ff;margin-bottom:6px}
.kv{display:flex;gap:10px;margin-bottom:6px}
.k{min-width:140px; color:#8be9ff}
.v{color:#e7ffee}
pre{background:#00111a;padding:10px;border-radius:8px;overflow:auto;white-space:pre-wrap}
a{color:#7ef2ff}
"""

def generate_html_report(report_json: Dict[str,Any]) -> str:
    title = f"WHOip report — {escape(report_json.get('target') or 'unknown')}"
    html = [f"<html><head><meta charset='utf-8'><title>{escape(title)}</title>",
            f"<style>{NEON_CSS}</style></head><body><div class='card'>"]
    html.append(f"<div class='h'>{escape(title)}</div>")
    html.append(f"<div class='kv'><div class='k'>Generated at</div><div class='v'>{escape(report_json.get('generated_at',''))}</div></div>")
    html.append(f"<div class='kv'><div class='k'>Target</div><div class='v'>{escape(report_json.get('target',''))}</div></div>")
    for sec in ("resolved_ip","geo","rdns","whois","nmap","banners","http","tls","shodan"):
        if sec in report_json:
            html.append(f"<div class='h'>{escape(sec.upper())}</div>")
            html.append(f"<pre>{escape(json.dumps(report_json.get(sec), indent=2, ensure_ascii=False))}</pre>")
    html.append("</div></body></html>")
    return "\n".join(html)

# ----------------- Orchestration -----------------
def do_scan(target: str, ports: Optional[List[int]] = None, shodan_key: Optional[str] = None,
            skip_whois: bool = False, run_nmap: bool = False, threads: int = BANNER_THREADS,
            rate: float = 0.0, delay: float = 0.0) -> Dict[str,Any]:
    out: Dict[str,Any] = {"generated_at": now_iso(), "target": target}
    # resolve
    ip = None
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target
    out["resolved_ip"] = ip
    # geo
    out["geo"] = geo_lookup_ip(ip)
    # rdns
    out["rdns"] = rdns(ip)
    # whois
    if not skip_whois:
        out["whois"] = whois_lookup(target)
    # nmap (optional)
    if run_nmap:
        out["nmap"] = run_nmap_xml(target)
    # banners (concurrent + throttling + polite delay)
    port_list = ports or DEFAULT_PORTS
    out["banners"] = scan_ports_concurrent(ip, port_list, threads=threads, rate=rate, delay=delay)
    # http fingerprint
    out["http"] = http_fingerprint(target)
    # tls
    out["tls"] = tls_info(target)
    # shodan
    if shodan_key:
        out["shodan"] = shodan_lookup(ip, shodan_key)
    return out

# ----------------- CLI -----------------
def parse_ports(s: Optional[str]) -> Optional[List[int]]:
    if not s:
        return None
    try:
        return [int(x.strip()) for x in s.split(",") if x.strip()]
    except Exception:
        return None

def main():
    p = argparse.ArgumentParser(prog="WHOip", description="WHOip — Ethical IP reconnaissance toolkit")
    sub = p.add_subparsers(dest="cmd")
    scan = sub.add_parser("scan", help="Run a scan (IP or domain)")
    scan.add_argument("target", help="IP or domain")
    scan.add_argument("-p","--ports", help="comma list of ports e.g. 22,80,443", default=None)
    scan.add_argument("--shodan", help="Shodan API key (optional)", default=None)
    scan.add_argument("--no-whois", help="Skip WHOIS", action="store_true")
    scan.add_argument("--nmap", help="Run nmap if available", action="store_true")
    scan.add_argument("-o","--out", help="Write JSON to file", default=None)
    scan.add_argument("--html", help="Write HTML report to file", default=None)
    scan.add_argument("--threads", help="Max concurrent threads for port scan", type=int, default=BANNER_THREADS)
    scan.add_argument("--rate", help="Max probes per second (0 = unlimited)", type=float, default=0.0)
    scan.add_argument("--delay", help="Polite delay (seconds) after each probe completion (small float)", type=float, default=0.0)

    report = sub.add_parser("report", help="Generate HTML report from JSON")
    report.add_argument("jsonfile", help="JSON file path")
    report.add_argument("-o","--out", help="Output HTML file", required=True)

    args = p.parse_args()
    if args.cmd == "scan":
        ports = parse_ports(args.ports) or DEFAULT_PORTS
        print(f"[+] WHOip: scanning {args.target} (resolved via DNS) ...")
        result = do_scan(args.target, ports=ports, shodan_key=args.shodan, skip_whois=args.no_whois, run_nmap=args.nmap,
                         threads=args.threads, rate=args.rate, delay=args.delay)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"[+] JSON saved to {args.out}")
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        if args.html:
            html = generate_html_report(result)
            with open(args.html, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"[+] HTML saved to {args.html}")
    elif args.cmd == "report":
        try:
            with open(args.jsonfile, "r", encoding="utf-8") as f:
                j = json.load(f)
        except Exception as e:
            print("Failed to read JSON:", e)
            sys.exit(1)
        html = generate_html_report(j)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] HTML saved to {args.out}")
    else:
        p.print_help()

if __name__ == "__main__":
    main()
