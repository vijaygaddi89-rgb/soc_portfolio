#!/usr/bin/env python3
# ==============================================
# Network Traffic Analyzer
# Author: Vijay Gaddi
# Description: Analyzes pcap files to detect
#              suspicious network activity
# ==============================================

from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import socket

# Configuration
PCAP_FILE  = "/home/vijay-gaddi/soc_directory/captures/day2-capture.pcap"
THRESHOLD  = 10  # connections before flagging

# Colors
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

# Known suspicious ports
SUSPICIOUS_PORTS = {
    22:   "SSH",
    23:   "Telnet (insecure!)",
    445:  "SMB (ransomware target!)",
    3389: "RDP (remote desktop)",
    4444: "Metasploit default!",
    5555: "Android Debug Bridge",
    6666: "Malware common port",
    8080: "HTTP Proxy",
    9001: "Tor default port"
}

def print_header():
    print(f"\n{BLUE}{'='*55}{RESET}")
    print(f"{BLUE}   NETWORK TRAFFIC ANALYZER — SOC TOOL{RESET}")
    print(f"{BLUE}   Analyst: Vijay Gaddi{RESET}")
    print(f"{BLUE}   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BLUE}{'='*55}{RESET}\n")

def analyze_pcap():
    print_header()

    # Storage
    ip_connections    = defaultdict(int)
    ip_bytes          = defaultdict(int)
    port_counts       = defaultdict(int)
    protocols         = defaultdict(int)
    suspicious_conns  = []
    tcp_flags         = defaultdict(int)

    print(f"{YELLOW}[*] Reading pcap file: {PCAP_FILE}{RESET}")

    try:
        packets = rdpcap(PCAP_FILE)
    except FileNotFoundError:
        print(f"{RED}[!] Pcap file not found: {PCAP_FILE}{RESET}")
        print(f"{RED}[!] Run tcpdump first to capture traffic!{RESET}")
        return
    except Exception as e:
        print(f"{RED}[!] Error reading pcap: {e}{RESET}")
        return

    total_packets = len(packets)
    print(f"{GREEN}[+] Total packets loaded: {total_packets}{RESET}\n")

    # Analyze each packet
    for packet in packets:

        # Only analyze IP packets
        if not packet.haslayer(IP):
            continue

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size   = len(packet)

        # Count connections per IP
        ip_connections[src_ip] += 1
        ip_bytes[src_ip]       += size

        # Protocol analysis
        if packet.haslayer(TCP):
            protocols['TCP'] += 1
            dst_port = packet[TCP].dport
            port_counts[dst_port] += 1

            # TCP flag analysis
            flags = packet[TCP].flags
            if flags == 2:   # SYN
                tcp_flags['SYN'] += 1
            elif flags == 18: # SYN-ACK
                tcp_flags['SYN-ACK'] += 1
            elif flags == 1:  # FIN
                tcp_flags['FIN'] += 1

            # Check suspicious ports
            if dst_port in SUSPICIOUS_PORTS:
                suspicious_conns.append({
                    'src': src_ip,
                    'dst': dst_ip,
                    'port': dst_port,
                    'service': SUSPICIOUS_PORTS[dst_port]
                })

        elif packet.haslayer(UDP):
            protocols['UDP'] += 1
            dst_port = packet[UDP].dport
            port_counts[dst_port] += 1

        elif packet.haslayer(ICMP):
            protocols['ICMP'] += 1

    # ==================
    # PRINT RESULTS
    # ==================

    # Summary
    print(f"{GREEN}{'='*55}{RESET}")
    print(f"{GREEN}   TRAFFIC SUMMARY{RESET}")
    print(f"{GREEN}{'='*55}{RESET}")
    print(f"{GREEN}[+] Total packets:      {total_packets}{RESET}")
    print(f"{GREEN}[+] Unique source IPs:  {len(ip_connections)}{RESET}")
    print(f"{GREEN}[+] Unique ports used:  {len(port_counts)}{RESET}")
    print(f"{GREEN}[+] Suspicious conns:   {len(suspicious_conns)}{RESET}\n")

    # Protocol breakdown
    print(f"{CYAN}{'='*55}{RESET}")
    print(f"{CYAN}   PROTOCOL BREAKDOWN{RESET}")
    print(f"{CYAN}{'='*55}{RESET}")
    for proto, count in sorted(protocols.items(),
                               key=lambda x: x[1],
                               reverse=True):
        percentage = (count / total_packets) * 100
        print(f"{CYAN}[+] {proto}: {count} packets ({percentage:.1f}%){RESET}")
    print()

    # TCP flags analysis
    if tcp_flags:
        print(f"{CYAN}{'='*55}{RESET}")
        print(f"{CYAN}   TCP FLAGS ANALYSIS{RESET}")
        print(f"{CYAN}{'='*55}{RESET}")
        for flag, count in tcp_flags.items():
            print(f"{CYAN}[+] {flag}: {count}{RESET}")

        # Port scan detection
        if tcp_flags.get('SYN', 0) > 50:
            print(f"{RED}[ALERT] High SYN count detected!{RESET}")
            print(f"{RED}[!]     Possible port scan or DoS!{RESET}")
        print()

    # Top communicating IPs
    print(f"{YELLOW}{'='*55}{RESET}")
    print(f"{YELLOW}   TOP COMMUNICATING IPs{RESET}")
    print(f"{YELLOW}{'='*55}{RESET}")
    for ip, count in sorted(ip_connections.items(),
                            key=lambda x: x[1],
                            reverse=True)[:10]:
        bytes_sent = ip_bytes[ip]
        kb = bytes_sent / 1024

        if count > THRESHOLD:
            print(f"{RED}[!] {ip}{RESET}")
            print(f"{RED}    Packets: {count} | Data: {kb:.1f} KB (HIGH!){RESET}")
        else:
            print(f"{GREEN}[OK] {ip}{RESET}")
            print(f"{GREEN}     Packets: {count} | Data: {kb:.1f} KB{RESET}")
    print()

    # Top ports
    print(f"{CYAN}{'='*55}{RESET}")
    print(f"{CYAN}   TOP DESTINATION PORTS{RESET}")
    print(f"{CYAN}{'='*55}{RESET}")
    for port, count in sorted(port_counts.items(),
                              key=lambda x: x[1],
                              reverse=True)[:10]:
        try:
            service = socket.getservbyport(port)
        except:
            service = "unknown"

        if port in SUSPICIOUS_PORTS:
            print(f"{RED}[!] Port {port} ({service}): {count} — SUSPICIOUS!{RESET}")
        else:
            print(f"{CYAN}[+] Port {port} ({service}): {count}{RESET}")
    print()

    # Suspicious connections
    if suspicious_conns:
        print(f"{RED}{'='*55}{RESET}")
        print(f"{RED}   SUSPICIOUS CONNECTIONS DETECTED!{RESET}")
        print(f"{RED}{'='*55}{RESET}")
        seen = set()
        for conn in suspicious_conns:
            key = f"{conn['src']}:{conn['port']}"
            if key not in seen:
                seen.add(key)
                print(f"{RED}[ALERT] {conn['src']} → port {conn['port']}{RESET}")
                print(f"{RED}        Service: {conn['service']}{RESET}")
                print(f"{RED}        Dest IP: {conn['dst']}{RESET}\n")
    else:
        print(f"{GREEN}[+] No suspicious connections found!{RESET}\n")

    print(f"{BLUE}{'='*55}{RESET}")
    print(f"{BLUE}   Analysis Complete!{RESET}")
    print(f"{BLUE}{'='*55}{RESET}\n")

if __name__ == "__main__":
    analyze_pcap()

