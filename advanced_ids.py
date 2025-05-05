#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP, ICMP, DNSRR, DNS
from colorama import init, Fore, Style
from datetime import datetime
import csv
import logging
import os
import signal
import sys

# Initialize colorama
init(autoreset=True)

# ====== USER DETAILS & BANNER ======
def show_banner():
    banner = f"""
{Fore.CYAN}
╔════════════════════════════════════════════╗
║     Advanced Intrusion Detection System    ║
║           Internship Project (2025)        ║
║         Developed by: Kushal Kumawat       ║
║       Internship at: CodTech Interns       ║
╚════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

# ====== GLOBALS ======
alert_log = []
syn_count = {}

# ====== CSV & LOG SETUP ======
log_filename = "ids_alerts.log"
logging.basicConfig(filename=log_filename, level=logging.INFO, format="%(asctime)s - %(message)s")

def export_csv(alert_log):
    try:
        csv_path = "ids_alerts.csv"
        with open(csv_path, "w", newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Timestamp", "Alert Message"])
            for row in alert_log:
                writer.writerow(row)
        print(f"{Fore.GREEN}[+] Alerts exported to {csv_path}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error exporting CSV: {e}{Style.RESET_ALL}")

# ====== DETECTION FUNCTIONS ======
def log_alert(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_log.append([timestamp, msg])
    logging.info(msg)
    print(f"{Fore.RED}[!] ALERT: {msg}{Style.RESET_ALL}")

def detect_syn_flood(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        src_ip = pkt[IP].src
        syn_count[src_ip] = syn_count.get(src_ip, 0) + 1
        if syn_count[src_ip] > 100:
            log_alert(f"SYN Flood Detected from {src_ip}")

def detect_port_scan(pkt):
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        if flags in ["S", "F", "R"]:
            log_alert(f"Port Scan Detected from {pkt[IP].src}")

def detect_ping_of_death(pkt):
    if pkt.haslayer(ICMP):
        if pkt.haslayer(IP) and pkt[IP].len > 1400:
            log_alert(f"Ping of Death Detected from {pkt[IP].src}")

def detect_dns_spoof(pkt):
    if pkt.haslayer(DNSRR):
        spoofed_ip = pkt[DNSRR].rdata
        qname = pkt[DNS].qd.qname.decode('utf-8') if pkt[DNS].qd else "unknown"
        if spoofed_ip not in ["8.8.8.8", "1.1.1.1"]:
            log_alert(f"Possible DNS Spoofing: {qname} resolves to {spoofed_ip}")

# ====== MAIN PACKET HANDLER ======
def packet_handler(pkt):
    if pkt.haslayer(IP):
        detect_syn_flood(pkt)
        detect_port_scan(pkt)
        detect_ping_of_death(pkt)
        detect_dns_spoof(pkt)

# ====== SIGNAL HANDLER FOR CLEAN EXIT ======
def signal_handler(sig, frame):
    print(f"\n{Fore.YELLOW}[!] Monitoring stopped by user. Exporting logs...{Style.RESET_ALL}")
    export_csv(alert_log)
    print(f"{Fore.BLUE}[✓] Log file: {log_filename}{Style.RESET_ALL}")
    sys.exit(0)

# ====== MAIN FUNCTION ======
def main():
    show_banner()
    signal.signal(signal.SIGINT, signal_handler)
    print(f"{Fore.GREEN}[+] Starting network monitoring... Press Ctrl+C to stop.{Style.RESET_ALL}\n")
    sniff(prn=packet_handler, store=False)

if __name__ == "__main__":
    main()
