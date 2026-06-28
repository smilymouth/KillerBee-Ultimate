<p align="center">
  <img src="https://raw.githubusercontent.com/smilymouth/KillerBee-Ultimate/main/banner.png" width="800"/>
</p>

<h1 align="center">🐝 Killer Bee Ultimate</h1>

<p align="center">
  <em>Terminal-based cybersecurity toolkit for footprinting, scanning, and AI-powered reconnaissance</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/AI-Gemini-4285F4?style=for-the-badge&logo=google&logoColor=white"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/status-active-brightgreen?style=for-the-badge"/>
</p>

---

## 🔥 What is Killer Bee?

**Killer Bee Ultimate** is a powerful terminal-based cybersecurity toolkit built for ethical hackers, pentesters, and CTF players. It combines classic recon tools into one clean interactive menu and layers **Gemini AI** on top for intelligent analysis and real-time guidance.

> No switching between 10 tabs. One tool, full recon flow.

---

## ⚡ Features

### 🔍 Footprinting Tools
| Tool | Description |
|------|-------------|
| WHOIS Lookup | Domain registration info |
| DNS Lookup | Resolve domain via nslookup |
| Reverse IP Lookup | Hostname from IP using `host` |
| Subdomain Finder | Bruteforce subdomains via `subdomains.txt` |
| Email Harvesting | Guided recon via theHarvester / hunter.io |
| IP Geolocation | Live geolocation via ipinfo.io |

### 📡 Scanning Tools
| Tool | Description |
|------|-------------|
| Nmap Scan | SYN scan with sudo (`-sS -T4`) |
| Masscan Scan | Fast port scan up to 1000 ports |
| TCPing Port Ping | TCP connectivity check |
| Nikto Web Scanner | Web vulnerability scanner |
| Curl HTTP Check | HTTP header/status analysis |
| OpenVAS Scan | External OpenVAS integration |

### 🤖 Gemini AI Assistant
Ask anything — recon strategy, tool usage, vulnerability analysis — powered by Google Gemini directly in the terminal.

---

## 🚀 Installation

```bash
git clone https://github.com/smilymouth/KillerBee-Ultimate.git
cd KillerBee-Ultimate
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python KillerBee2.py
```

### System Dependencies
```bash
# Debian/Ubuntu
sudo apt install nmap masscan nikto tcping

# Arch
sudo pacman -S nmap masscan nikto
```

### Python Dependencies
colorama

requests

python-whois

google-generativeai

---

## 🛠️ Usage

```bash
python KillerBee2.py
```

On launch:
- Choose whether to enable **Gemini AI** (requires API key + model name)
- Enter your **sudo password** once for privileged scans (Nmap, Masscan)
- Navigate the interactive menu

For subdomain enumeration, place a `subdomains.txt` wordlist in the root directory.

---

## ⚠️ Legal Disclaimer

> This tool is intended for **authorized security testing only.**  
> Use only on systems you own or have **explicit written permission** to test.  
> Unauthorized scanning is illegal. The developer is not responsible for misuse.

---

## 👤 Author

**smilymouth** — Ethical hacker · CTF player · CyberHawk85

[![GitHub](https://img.shields.io/badge/GitHub-smilymouth-181717?style=flat-square&logo=github)](https://github.com/smilymouth)

---

<p align="center"><em>Made for the terminal. Built for recon. 🐝</em></p>
