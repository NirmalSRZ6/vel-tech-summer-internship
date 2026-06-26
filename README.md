# 🔍 Python Network Scanner

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Category-Cybersecurity-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

A beginner-friendly Python tool for **network reconnaissance and port scanning** — built as a cybersecurity portfolio project.

> ⚠️ **Legal Disclaimer:** This tool is for **educational purposes only**. Only scan networks and systems you **own** or have **explicit written permission** to test. Unauthorized scanning is illegal under the IT Act 2000 (India), CFAA (USA), and similar laws worldwide.

---

## 📌 What This Tool Does

| Feature | Description |
|---|---|
| 🖥️ Host Discovery | Finds all active devices on your network using ARP scanning |
| 🔌 Port Scanning | Checks 30+ common ports using fast multi-threaded TCP scanning |
| 🏷️ Service Detection | Identifies what service runs on each open port (HTTP, SSH, FTP...) |
| 🔎 Banner Grabbing | Retrieves software version info from open services |
| 📄 TXT Report | Saves a clean, human-readable text report |
| 📊 CSV Report | Saves a spreadsheet-ready CSV for further analysis |
| ⚠️ Security Alerts | Flags dangerous open ports (Telnet, SMB, RDP, VNC...) |

---

## 🗂️ Project Structure

```
network-scanner/
│
├── main.py                    # ← Start here! Main CLI entry point
│
├── scanner/                   # Core scanning modules
│   ├── __init__.py            # Makes scanner/ a Python package
│   ├── host_discovery.py      # ARP scanning to find devices
│   ├── port_scanner.py        # TCP port scanning with threading
│   ├── service_detector.py    # Banner grabbing for version info
│   └── report_generator.py    # Save results to TXT and CSV
│
├── sample_output/             # Example scan results
│   ├── sample_scan.txt        # Sample text report
│   └── sample_scan.csv        # Sample CSV report
│
├── output/                    # Your scan results go here (auto-created)
│
├── requirements.txt           # Python dependencies
├── .gitignore                 # Files to exclude from GitHub
└── README.md                  # This file
```

---

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Linux or macOS recommended (Windows works with limitations)

### Step 1 — Clone the Repository
```bash
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner
```

### Step 2 — Create a Virtual Environment (Recommended)
```bash
# Create virtual environment
python3 -m venv venv

# Activate it (Linux/Mac)
source venv/bin/activate

# Activate it (Windows)
venv\Scripts\activate
```

### Step 3 — Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Verify Installation
```bash
python main.py --version
# Output: network-scanner 1.0.0
```

---

## 🚀 How to Use

### Find Your Network Range First
```bash
# Linux / Mac
ip route
# Look for a line like: 192.168.1.0/24 dev wlan0

# Windows
ipconfig
# Look for IPv4 Address and Subnet Mask
```

### Basic Usage Examples

**1. Scan your entire home network (finds all devices):**
```bash
sudo python main.py 192.168.1.0/24
```

**2. Scan a single device (no sudo needed):**
```bash
python main.py 192.168.1.1 --ports-only
```

**3. Scan specific ports only:**
```bash
python main.py 192.168.1.1 --ports-only -p 22,80,443,3306,3389
```

**4. Full scan with banner grabbing (version info):**
```bash
sudo python main.py 192.168.1.0/24 --banners
```

**5. Save results with a custom filename:**
```bash
sudo python main.py 192.168.1.0/24 -o home_network_audit
# Creates: output/home_network_audit.txt and .csv
```

**6. Run without prompts (automated/scripted use):**
```bash
sudo python main.py 192.168.1.0/24 --no-prompt -o auto_scan
```

**7. See all ports the tool scans by default:**
```bash
python main.py --list-ports
```

### All Available Options
```
usage: network-scanner [-h] [-p PORTS] [-o FILENAME] [-b] [--ports-only]
                        [--no-prompt] [--timeout SECONDS] [--list-ports] [-v]
                        [target]

positional arguments:
  target              Network range (192.168.1.0/24) or IP (192.168.1.1)

optional arguments:
  -h, --help          Show this help message and exit
  -p, --ports PORTS   Custom ports: -p 22,80,443,3306
  -o, --output NAME   Output filename base: -o myscan
  -b, --banners       Grab service banners (version info)
  --ports-only        Skip host discovery, scan single IP directly
  --no-prompt         Run without interactive prompts
  --timeout SECONDS   Per-port timeout in seconds (default: 1.0)
  --list-ports        Show default ports and exit
  -v, --version       Show version number and exit
```

---

## 📸 Sample Output

### Terminal Output
```
    ╔══════════════════════════════════════════════════════════╗
    ║         🔍  PYTHON NETWORK SCANNER  v1.0                 ║
    ║         For Educational & Authorized Use Only            ║
    ╚══════════════════════════════════════════════════════════╝

  [*] Scan started: 2024-03-15 14:30:22
  [*] Target:       192.168.1.0/24

══════════════[ PHASE 1: HOST DISCOVERY ]══════════════

[*] Starting ARP scan on: 192.168.1.0/24
[*] Sending ARP broadcast packets...

  #    IP Address         MAC Address          Hostname
  ──── ────────────────── ──────────────────── ─────────────────────────
  1    192.168.1.1        c8:3a:35:b7:1e:a0    router.local
  2    192.168.1.5        b8:27:eb:12:34:56    raspberrypi.local
  3    192.168.1.12       3c:15:c2:ab:cd:ef    DESKTOP-WIN10.local

══════════════[ PHASE 2: PORT SCANNING ]══════════════

  ┌─ Scanning 192.168.1.1 (router.local)
  [→] Scanning 30 ports on 192.168.1.1...
  [→] Progress: 30/30 ports (100%)

  Open ports on 192.168.1.1 (4 found):
  PORT     SERVICE         STATUS     BANNER
  ──────── ─────────────── ────────── ──────────────────────────
  22       SSH             OPEN       SSH-2.0-OpenSSH_8.9p1
  53       DNS             OPEN
  80       HTTP            OPEN       Server: mini_httpd/1.29
  443      HTTPS           OPEN       HTTPS service (SSL/TLS)
```

### CSV Report (opens in Excel)
| IP Address | Hostname | Port | Service | Status | Banner | Security Note |
|---|---|---|---|---|---|---|
| 192.168.1.1 | router.local | 22 | SSH | OPEN | SSH-2.0-OpenSSH_8.9p1 | |
| 192.168.1.12 | DESKTOP-WIN10 | 445 | SMB | OPEN | | ⚠️ EternalBlue target |
| 192.168.1.12 | DESKTOP-WIN10 | 3389 | RDP | OPEN | | ⚠️ Brute force target |

---

## 🧠 How It Works — The Concepts

### 1. ARP Scanning (Host Discovery)
ARP (Address Resolution Protocol) maps IP addresses to MAC addresses. We broadcast an ARP request to the entire network — "Who has this IP?" — and any active device responds with its MAC address. This is how we find all devices.

### 2. TCP Port Scanning
We attempt a TCP connection to each port. If the connection succeeds → port is **OPEN** (service running). If refused → **CLOSED**. If it times out → likely **FILTERED** by a firewall.

### 3. Threading for Speed
Without threads: 30 ports × 1 second = 30 seconds. With threads: all 30 ports scan simultaneously = ~1–2 seconds. We use Python's `concurrent.futures.ThreadPoolExecutor`.

### 4. Banner Grabbing
Most network services send a greeting message when you connect. This "banner" usually contains the software name and version — e.g., `SSH-2.0-OpenSSH_8.9p1`. In security testing, this helps identify potentially vulnerable versions.

---

## 🔒 Ports Scanned by Default

| Port | Service | Security Risk |
|---|---|---|
| 21 | FTP | ⚠️ Plain text credentials |
| 22 | SSH | Secure remote access |
| 23 | Telnet | ⚠️ Completely unencrypted |
| 80 | HTTP | Web server |
| 443 | HTTPS | Secure web server |
| 445 | SMB | ⚠️ EternalBlue / WannaCry |
| 3306 | MySQL | Database |
| 3389 | RDP | ⚠️ Brute force target |
| 5900 | VNC | ⚠️ Often misconfigured |
| ... | ... | ... |

Run `python main.py --list-ports` to see all 30 ports.

---

## 🛠️ Technologies Used

| Technology | Purpose | Why it Matters in Security |
|---|---|---|
| **Python 3** | Core language | Most popular language in cybersecurity |
| **Scapy** | ARP packet crafting | Industry-standard packet manipulation library |
| **socket** | TCP connections | Foundation of network communication |
| **concurrent.futures** | Multi-threading | Performance optimization technique |
| **argparse** | CLI interface | Professional tool design |
| **csv** | Report generation | Data portability and analysis |

---

## 🚀 Future Improvements

Want to make this more advanced? Here are ideas:

- [ ] **OS Detection** — Guess the operating system from TTL values and TCP fingerprinting
- [ ] **CVE Lookup** — Auto-search vulnerabilities for detected software versions via NVD API
- [ ] **UDP Scanning** — Add UDP port scanning (DNS, SNMP, DHCP use UDP)
- [ ] **HTML Report** — Generate a styled HTML report with charts
- [ ] **Web Dashboard** — Build a Flask web UI to view results in a browser
- [ ] **Nmap Integration** — Run Nmap as a subprocess and parse its XML output
- [ ] **Database Storage** — Save all scans to SQLite for historical comparison
- [ ] **Email Alerts** — Send email when new devices join the network
- [ ] **Scheduled Scans** — Use cron to auto-scan and detect network changes
- [ ] **Shodan API** — Enrich results with Shodan's internet-wide scan data

---

## 📚 What I Learned Building This

- How ARP protocol works at the data link layer
- TCP 3-way handshake and connection states
- Multi-threading in Python for performance optimization
- Building professional CLI tools with argparse
- Network reconnaissance techniques used in penetration testing
- How to structure a Python project with packages and modules
- Writing clean, documented, production-quality Python code

---

## ⚖️ Legal & Ethical Use

This tool is built for:
- ✅ Scanning your own home/lab network
- ✅ Educational learning about networking and security
- ✅ Authorized penetration testing engagements
- ✅ CTF (Capture the Flag) competitions

**Never use for:**
- ❌ Scanning networks without permission
- ❌ Corporate or institutional networks without written authorization
- ❌ Any malicious purpose

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.

---


