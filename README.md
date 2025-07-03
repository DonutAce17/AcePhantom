# AcePhantom 🔎🛰️

**AcePhantom** is a stealthy, smart, and feature-rich SSRF (Server-Side Request Forgery) vulnerability scanner built for **Kali Linux**.

> "It goes where Burp can't."

---

## 🚀 Features

- 🔁 **Obfuscated Payload Engine**  
  Encodes IPs (Hex, Octal, IPv6), DNS rebinding tricks, and more.

- 🕵️ **Deep Reflection Matching**  
  Identifies blind SSRF using indirect response analysis.

- 🧠 **AI-Inspired Payload Adaptation**  
  Dynamically changes payloads based on response codes or headers.

- 🎯 **Internal Resource Auto-Scanner**  
  Probes AWS IMDS (`169.254.169.254`) and `127.0.0.1` for SSRF-based privilege escalations.

- 📥 **Burp Suite XML Importer**  
  Re-scan multiple URLs exported from Burp Suite.

- 🛰️ **Custom Callback Listener**  
  Lightweight HTTP listener to catch blind SSRF callbacks.

---

## 🛠️ Usage

### Start the callback listener:
```bash
./acephantom --listen
