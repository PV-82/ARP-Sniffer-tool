# ARP Sniffer & Spoofing Detector

A Python-based network packet sniffer and ARP spoofing detector built using the Scapy library.
Developed as part of an MSc Cybersecurity internship project at National College of Ireland.

---

## What It Does

- Captures live packets on a network interface in real time
- Parses and displays ARP, IP, TCP, UDP, and ICMP traffic
- Maintains an IP-to-MAC mapping table
- Detects ARP spoofing by identifying when a known IP changes its MAC address
- Raises alerts and logs them to `arp_sniffer.log`
- Exports captured packets to a `.pcap` file for forensic analysis
- Provides a clean interactive terminal menu

---

## Project Structure
arp-sniffer-tool/
│
├── sniffer.py        # Main tool — packet capture, ARP detection, terminal menu
├── arp_table.py      # IP-to-MAC mapping and spoofing detection logic
├── logger.py         # Timestamped alert and packet logging
├── requirements.txt  # Python dependencies
└── README.md         # This file

---

## Requirements

- Python 3.8+
- Scapy

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## How to Run

> **Root/sudo is required** for live packet capture on Linux.

### Interactive Menu (recommended)

```bash
sudo python3 sniffer.py
```

### Specify a Network Interface

```bash
sudo python3 sniffer.py --iface eth0
```

### Menu Options
[1] Start Sniffing         — Begin live packet capture
[2] Stop Sniffing          — Stop capture gracefully
[3] View ARP Table         — Display current IP-to-MAC mappings
[4] View Alerts            — Display all spoofing alerts detected
[5] View Log File          — Print contents of arp_sniffer.log
[6] Export Packets (.pcap) — Save captured packets to a .pcap file
[7] Exit                   — Exit the tool

---

## How ARP Spoofing Detection Works

ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on a local network.
In an ARP spoofing attack, a malicious actor sends fake ARP replies to associate their
MAC address with a legitimate IP, intercepting traffic (Man-in-the-Middle attack).

This tool detects spoofing by:
1. Recording the first MAC address seen for each IP
2. Monitoring every subsequent ARP reply for that IP
3. Raising an alert if the MAC address changes unexpectedly

---

## Log File

All alerts and packet events are saved to `arp_sniffer.log` automatically.
Alerts are also printed to the terminal in real time.

---

## Exporting Packets

Captured packets can be exported to a `.pcap` file and opened in **Wireshark**
for deeper forensic analysis.

---

## Practical Use Cases

- Real-time ARP spoofing detection on local networks
- Network forensics and packet capture for later analysis
- Educational tool to learn packet structures, ARP protocol, and defensive techniques
- Useful in small networks, home labs, and as a monitoring component in a larger security setup

---

## ⚠️ Ethical Notice

> This tool is intended for **educational and authorised use only.**
>
> Run this tool **only on networks you own or have explicit permission to monitor.**
> Packet capture and network monitoring may be illegal or violate acceptable use
> policies in some environments. Always obtain proper permission before
> scanning or sniffing any network.
>
> The author assumes no responsibility for misuse of this tool.

---

## Author

**PV** — MSc Cybersecurity Student, National College of Ireland  
GitHub: [PV-82](https://github.com/PV-82)