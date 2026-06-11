"""
arp_table.py
------------
Maintains an IP-to-MAC mapping table and detects ARP spoofing anomalies.
When a known IP address is seen with a different MAC address, an alert is raised.
"""

from datetime import datetime


class ARPTable:
    def __init__(self):
        # Stores {IP: MAC} mappings
        self.table = {}
        # Stores list of spoofing alert dicts
        self.alerts = []

    def update(self, ip, mac):
        """
        Check and update the ARP table.
        Returns an alert dict if spoofing is detected, else None.
        """
        mac = mac.lower()

        if ip in self.table:
            if self.table[ip] != mac:
                alert = {
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": ip,
                    "old_mac": self.table[ip],
                    "new_mac": mac,
                    "message": f"[ALERT] ARP Spoofing Detected! IP {ip} changed MAC from {self.table[ip]} to {mac}"
                }
                self.alerts.append(alert)
                self.table[ip] = mac  # Update to latest
                return alert
        else:
            # First time seeing this IP, just store it
            self.table[ip] = mac

        return None

    def get_table(self):
        """Returns the current IP-to-MAC mapping table."""
        return self.table

    def get_alerts(self):
        """Returns all detected spoofing alerts."""
        return self.alerts

    def display_table(self):
        """Prints the ARP table in a readable format."""
        print("\n" + "="*50)
        print(f"{'IP Address':<20} {'MAC Address':<20}")
        print("="*50)
        if not self.table:
            print("  No entries yet.")
        for ip, mac in self.table.items():
            print(f"{ip:<20} {mac:<20}")
        print("="*50 + "\n")

    def display_alerts(self):
        """Prints all spoofing alerts."""
        print("\n" + "="*50)
        print("  ARP SPOOFING ALERTS")
        print("="*50)
        if not self.alerts:
            print("  No alerts detected.")
        for alert in self.alerts:
            print(f"  [{alert['time']}]")
            print(f"  IP      : {alert['ip']}")
            print(f"  Old MAC : {alert['old_mac']}")
            print(f"  New MAC : {alert['new_mac']}")
            print("-"*50)
        print("="*50 + "\n")