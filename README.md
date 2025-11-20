# 📡 NScan

**NScan** is a high-performance, multi-threaded network reconnaissance tool built in Python. It goes beyond simple port scanning by implementing raw packet manipulation (Scapy) for stealth operations, OS fingerprinting, and local network discovery.

It allows security researchers to map networks, identify active services, and perform "stealth" scans that evade basic firewall logging.

## ✨ Features

* **🚀 Multi-Threaded Engine:** Scans thousands of ports in seconds using concurrent threading.
* **👻 Stealth Mode (SYN Scan):** Uses raw packet manipulation (via Scapy) to perform "Half-Open" TCP handshakes, often bypassing basic firewalls and logs.
* **🕵️ OS Fingerprinting:** Analyzes the `TTL` (Time To Live) of incoming packets to estimate the target operating system (Windows vs. Linux).
* **🏷️ Banner Grabbing:** Automatically connects to open ports to retrieve service versions (e.g., "Apache 2.4.49").
* **🗺️ Network Discovery:** Uses ARP broadcasting to map an entire local subnet (WiFi/LAN) and find all connected devices (IP & MAC addresses).
* **📄 JSON Reporting:** Exports all results to a structured JSON file for further analysis.

---

## 🛠️ Installation

### Prerequisites
* **Python 3.x**
* **Npcap** (Windows only - required for Scapy packet manipulation) -> [Download Npcap](https://npcap.com/#download)
* **Administrator/Root Privileges** (Required for Stealth & Discovery modes)

### Setup
```bash
# Clone the repository
git clone [https://github.com/Ferns404/NScan.git](https://github.com/Ferns404/NScan.git)
cd NScan

# Create a virtual environment (Recommended)
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1

# Install dependencies
pip install scapy colorama
```
---

### 🎮 Usage
NScan is a command-line tool. You must run these commands as Administrator (Windows) or Root (Linux/Mac) for packet manipulation features.

1. Standard Port Scan (Safe Mode)
Uses standard TCP connections. Fast and reliable.
Bash:
```bash python nscan.py <TARGET_IP_OR_DOMAIN> -p 1-1000```

2. Stealth Scan (Root/Admin Required)
Sends raw SYN packets. Determines OS based on TTL.
Bash:
```bash python nscan.py <TARGET_IP_OR_DOMAIN> --stealth ```

3. Network Discovery (Who is on my WiFi?)
Maps the local subnet using ARP requests.
Bash:
```bash python nscan.py <SUBNET_RANGE> --discover ```

4. Save Results
Save the output to a JSON file for reporting.
Bash:
```bash python nscan.py <TARGET_IP> --stealth -o report.json ```

---

## ⚠️ Disclaimer
NScan is for educational purposes and authorized security testing only. Scanning networks or targets without permission is illegal. The author is not responsible for misuse of this tool.

---

##  ⚖️ License
MIT License
