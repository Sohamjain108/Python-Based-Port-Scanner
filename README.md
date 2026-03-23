# 🔍 Project 1: Python-Based Port Scanner

## Overview

A multi-threaded Python port scanner that identifies open ports and services on target systems. Supports TCP connect scans, banner grabbing, and service version detection — simulating core Nmap concepts from scratch.

---

## 🎯 Learning Objectives

- Understand TCP/IP three-way handshake and socket programming
- Implement multi-threaded scanning for performance
- Practice network reconnaissance techniques used in SOC workflows
- Understand how Nmap operates under the hood

---

## 🛠️ Features

- ✅ TCP Connect Scan (full handshake)
- ✅ Multi-threaded for fast scanning
- ✅ Port range specification
- ✅ Banner grabbing (service fingerprinting)
- ✅ Common ports list (top 1000)
- ✅ Export results to JSON/TXT
- ✅ Verbose and quiet modes
- ✅ CIDR range support

---

## 📦 Installation

### On Kali Linux

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python (usually pre-installed on Kali)
python3 --version

# Clone or navigate to project
cd 1-python-port-scanner

# Install dependencies
pip3 install -r requirements.txt
```

---

## 🚀 Usage

### Basic Scan (single host, common ports)
```bash
python3 src/port_scanner.py -t 192.168.1.1
```

### Scan Specific Port Range
```bash
python3 src/port_scanner.py -t 192.168.1.1 -p 1-1024
```

### Scan Specific Ports
```bash
python3 src/port_scanner.py -t 192.168.1.1 -p 22,80,443,3306,8080
```

### Scan with Banner Grabbing
```bash
python3 src/port_scanner.py -t 192.168.1.1 -p 1-1000 --banner
```

### Save Output to File
```bash
python3 src/port_scanner.py -t 192.168.1.1 --output results.json
```

### Verbose Mode
```bash
python3 src/port_scanner.py -t 192.168.1.1 -p 1-65535 -v
```

### Scan a Subnet
```bash
python3 src/port_scanner.py -t 192.168.1.0/24 -p 80,443
```

---

## 📊 Sample Output

```
============================================================
        Python Port Scanner v1.0 | by Your Name
============================================================
[*] Target       : 192.168.1.1
[*] Port Range   : 1-1024
[*] Threads      : 100
[*] Scan Started : 2025-08-01 10:30:00
------------------------------------------------------------
[+] Port 22  /tcp  OPEN  ssh     Banner: OpenSSH 8.2p1
[+] Port 80  /tcp  OPEN  http    Banner: Apache httpd 2.4.41
[+] Port 443 /tcp  OPEN  https   Banner: -
------------------------------------------------------------
[*] Scan Complete. 3 open ports found.
[*] Duration: 4.23 seconds
============================================================
```

---

## 🧠 How It Works (TCP Connect Scan)

```
Client (Scanner)          Server (Target)
      |                        |
      |------- SYN ----------->|   Step 1: Scanner sends SYN
      |                        |
      |<------ SYN-ACK --------|   Step 2: Server replies SYN-ACK (port OPEN)
      |                        |   OR RST (port CLOSED)
      |------- ACK ----------->|   Step 3: Scanner completes handshake
      |------- RST ----------->|   Step 4: Scanner resets (clean disconnect)
```

---

## ⚙️ Kali Linux — Nmap Comparison

After running your custom scanner, verify with Nmap:

```bash
# Basic Nmap TCP scan
nmap -sT -p 1-1024 192.168.1.1

# Nmap with service version detection
nmap -sV -p 1-1024 192.168.1.1

# Aggressive scan (OS + version + scripts)
nmap -A 192.168.1.1
```

---

## 📁 Project Files

```
1-python-port-scanner/
├── src/
│   ├── port_scanner.py      # Main scanner script
│   ├── banner_grabber.py    # Banner grabbing module
│   ├── common_ports.py      # Top 1000 common ports list
│   └── utils.py             # Helper utilities
├── tests/
│   └── test_scanner.py      # Unit tests
├── docs/
│   └── tcp_ip_notes.md      # TCP/IP learning notes
├── requirements.txt
└── README.md
```

---

## ⚠️ Legal Notice

Only scan systems you own or have explicit written permission to test.
