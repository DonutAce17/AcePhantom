# 🛰️ AcePhantom – Stealth SSRF Scanner

AcePhantom is a powerful and stealthy SSRF detection tool for Kali Linux.  
It detects both reflected and blind SSRF vulnerabilities using smart payload generation, internal resource crawling, and DNS rebinding tricks.

---

## 🚀 Features

- 🔁 Obfuscated payloads (Hex, Octal, IPv6, DNS Rebinding)
- 🕵️ Blind SSRF detection with callback listener
- 🧠 Adaptive payload behavior based on responses
- 🎯 Internal IP crawling (`127.0.0.1`, `169.254.169.254`, AWS metadata)
- 📥 Burp Suite `.xml` scan importer
- 🛰️ One-click binary for Kali Linux (`.deb` included)

---

## 🔧 Usage

Start the callback listener:
```bash
./acephantom --listen
