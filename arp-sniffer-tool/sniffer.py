"""
sniffer.py
----------
Main packet sniffer and ARP spoofing detector.
Captures live packets using Scapy, analyses ARP traffic,
and detects spoofing by monitoring IP-to-MAC mappings.

ETHICAL NOTICE:
Run this tool only on networks you own or have explicit permission to monitor.
Unauthorised packet capture may be illegal in your jurisdiction.
"""

import argparse
import threading
import time
from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, wrpcap, Ether

from arp_table import ARPTable
from logger import setup_logger, log_alert, log_packet, log_info, display_log

# Global state
arp_table = ARPTable()
logger = setup_logger()
captured_packets = []
sniffing = False


# ─────────────────────────────────────────────
# Packet Processing
# ─────────────────────────────────────────────

def process_packet(packet):
    """
    Callback for every captured packet.
    Handles ARP detection and general packet logging.
    """
    global captured_packets
    captured_packets.append(packet)

    # ── ARP Analysis ──
    if packet.haslayer(ARP):
        arp = packet[ARP]

        # ARP reply (op=2) is where spoofing happens
        if arp.op == 2:
            alert = arp_table.update(arp.psrc, arp.hwsrc)
            if alert:
                print(f"\n{'!'*55}")
                print(alert["message"])
                print(f"{'!'*55}\n")
                log_alert(logger, alert)
            else:
                log_packet(logger, f"ARP Reply: {arp.psrc} is at {arp.hwsrc}")

        elif arp.op == 1:
            log_packet(logger, f"ARP Request: Who has {arp.pdst}? Tell {arp.psrc}")

    # ── IP/TCP/UDP/ICMP Summary ──
    elif packet.haslayer(IP):
        ip = packet[IP]

        if packet.haslayer(TCP):
            summary = f"TCP  {ip.src}:{packet[TCP].sport} -> {ip.dst}:{packet[TCP].dport}"
        elif packet.haslayer(UDP):
            summary = f"UDP  {ip.src}:{packet[UDP].sport} -> {ip.dst}:{packet[UDP].dport}"
        elif packet.haslayer(ICMP):
            summary = f"ICMP {ip.src} -> {ip.dst} | Type: {packet[ICMP].type}"
        else:
            summary = f"IP   {ip.src} -> {ip.dst} | Proto: {ip.proto}"

        print(f"  [PKT] {summary}")
        log_packet(logger, summary)


# ─────────────────────────────────────────────
# Sniffing Control
# ─────────────────────────────────────────────

def start_sniffing(iface=None, packet_filter=""):
    """
    Starts packet capture in a background thread.
    """
    global sniffing
    sniffing = True

    iface_msg = iface if iface else "default"
    print(f"\n  [*] Sniffing started on interface: {iface_msg}")
    print("  [*] Press ENTER to stop...\n")
    log_info(logger, f"Sniffing started on interface: {iface_msg}")

    def run():
        sniff(
            iface=iface,
            filter=packet_filter,
            prn=process_packet,
            store=False,
            stop_filter=lambda p: not sniffing
        )

    thread = threading.Thread(target=run, daemon=True)
    thread.start()


def stop_sniffing():
    """
    Signals the sniffer to stop.
    """
    global sniffing
    sniffing = False
    print("\n  [*] Sniffing stopped.")
    log_info(logger, "Sniffing stopped.")


# ─────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────

def export_pcap(filename="capture.pcap"):
    """
    Saves captured packets to a .pcap file.
    """
    if not captured_packets:
        print("\n  [!] No packets to export.\n")
        return
    wrpcap(filename, captured_packets)
    print(f"\n  [*] {len(captured_packets)} packets saved to {filename}\n")
    log_info(logger, f"Exported {len(captured_packets)} packets to {filename}")


# ─────────────────────────────────────────────
# Terminal Menu
# ─────────────────────────────────────────────

def print_banner():
    print("""
  ╔══════════════════════════════════════════════════╗
  ║        ARP Sniffer & Spoofing Detector           ║
  ║        MSc Cybersecurity | NCI Dublin            ║
  ╚══════════════════════════════════════════════════╝
  ETHICAL NOTICE: Use only on networks you own or
  have explicit permission to monitor.
    """)


def menu(iface=None):
    """
    Interactive terminal menu.
    """
    print_banner()

    while True:
        print("""
  ┌─────────────────────────────┐
  │  [1] Start Sniffing         │
  │  [2] Stop Sniffing          │
  │  [3] View ARP Table         │
  │  [4] View Alerts            │
  │  [5] View Log File          │
  │  [6] Export Packets (.pcap) │
  │  [7] Exit                   │
  └─────────────────────────────┘""")

        choice = input("  Select option: ").strip()

        if choice == "1":
            if sniffing:
                print("\n  [!] Already sniffing.\n")
            else:
                start_sniffing(iface=iface)

        elif choice == "2":
            stop_sniffing()

        elif choice == "3":
            arp_table.display_table()

        elif choice == "4":
            arp_table.display_alerts()

        elif choice == "5":
            display_log()

        elif choice == "6":
            fname = input("  Enter filename (default: capture.pcap): ").strip()
            export_pcap(fname if fname else "capture.pcap")

        elif choice == "7":
            if sniffing:
                stop_sniffing()
            print("\n  [*] Goodbye.\n")
            break

        else:
            print("\n  [!] Invalid option. Try again.\n")


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ARP Sniffer and Spoofing Detector"
    )
    parser.add_argument(
        "--iface", "-i",
        type=str,
        default=None,
        help="Network interface to sniff on (e.g. eth0, wlan0)"
    )
    args = parser.parse_args()
    menu(iface=args.iface)