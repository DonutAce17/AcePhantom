# 🕵️‍♂️ AcePhantom – SSRF Scanner (v0.3.0)

> **“It goes where Burp can't.”**  
A fast, simple, blind SSRF detection tool built in Python — with Burp Suite XML support.

![AcePhantom Banner](https://i.imgur.com/vHZoIVT.png) <!-- optional banner or logo if you decide to add one later -->

---

## 🚀 Features

- 🔎 Detects blind Server-Side Request Forgery (SSRF)
- 💣 Supports both direct URL scanning and Burp Suite exported XML
- 🎯 Injects payloads using various IP encoding techniques (hex, octal, IPv6, etc.)
- 🧪 Cloud metadata exploitation attempts
- 📦 Exports findings in structured JSON (`acephantom_results.json`)
- 📡 Callback listener on port `8008` for interaction tracking

---

## 🧩 Installation

Download the `.deb` file from [Releases](https://github.com/DonutAce17/AcePhantom/releases) or build manually.

```bash
sudo dpkg -i acephantom_0.3.0_amd64.deb
