"""
logger.py
---------
Handles logging of ARP spoofing alerts and packet events to a timestamped log file.
All alerts are saved to 'arp_sniffer.log' for later forensic analysis.
"""

import logging
import os
from datetime import datetime


LOG_FILE = "arp_sniffer.log"


def setup_logger():
    """
    Sets up and returns a logger that writes to both terminal and log file.
    """
    logger = logging.getLogger("ARPSniffer")
    logger.setLevel(logging.DEBUG)

    # Avoid duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    # File handler - saves everything to arp_sniffer.log
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.DEBUG)

    # Console handler - prints WARNING and above to terminal
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)

    # Format: [2026-06-11 14:22:13] LEVEL - message
    formatter = logging.Formatter(
        fmt="[%(asctime)s] %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def log_alert(logger, alert):
    """
    Logs an ARP spoofing alert.
    """
    logger.warning(alert["message"])
    logger.warning(f"  Old MAC: {alert['old_mac']} | New MAC: {alert['new_mac']}")


def log_packet(logger, packet_summary):
    """
    Logs a general packet event (debug level, goes to file only).
    """
    logger.debug(f"Packet: {packet_summary}")


def log_info(logger, message):
    """
    Logs a general info message.
    """
    logger.info(message)


def display_log():
    """
    Prints the contents of the log file to the terminal.
    """
    print("\n" + "="*50)
    print("  ARP SNIFFER LOG")
    print("="*50)
    if not os.path.exists(LOG_FILE):
        print("  No log file found yet.")
    else:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
            if not lines:
                print("  Log is empty.")
            for line in lines:
                print(" ", line.strip())
    print("="*50 + "\n")