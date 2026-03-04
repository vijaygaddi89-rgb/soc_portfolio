#!/usr/bin/env python3
# ==============================================
# Apache Log Analyzer
# Author: Vijay Gaddi
# Description: Detects web attacks by analyzing
#              Apache access logs
# ==============================================

import re
from collections import defaultdict
from datetime import datetime

# Configuration
LOG_FILE  = "/var/log/apache2/access.log"
THRESHOLD = 10  # requests before alerting

# Colors
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

# Suspicious patterns to detect
SUSPICIOUS_PATHS = [
    '.git', 'wp-login', 'admin',
    'phpmyadmin', 'shell', 'passwd',
    'config', 'backup', '.env',
    'HNAP1', 'sdk', 'evox'
]

SUSPICIOUS_AGENTS = [
    'nmap', 'sqlmap', 'nikto',
    'masscan', 'zgrab', 'dirbuster',
    'hydra', 'metasploit'
]

def print_header():
    """Print tool header"""
    print(f"\n{BLUE}{'='*55}{RESET}")
    print(f"{BLUE}   APACHE LOG ANALYZER — SOC TOOL{RESET}")
    print(f"{BLUE}   Analyst: Vijay Gaddi{RESET}")
    print(f"{BLUE}   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BLUE}{'='*55}{RESET}\n")

def parse_log_line(line):
    """Extract fields from apache log line"""
    pattern = r'(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+\S+\s+".*?"\s+"(.*?)"'
    match = re.search(pattern, line)
    if match:
        return {
            'ip'     : match.group(1),
            'method' : match.group(2),
            'path'   : match.group(3),
            'status' : match.group(4),
            'agent'  : match.group(5)
        }
    return None

def analyze_logs():
    """Main analysis function"""
    print_header()

    # Storage
    ip_requests      = defaultdict(int)
    ip_404s          = defaultdict(int)
    suspicious_paths = defaultdict(list)
    suspicious_agents = defaultdict(list)
    status_counts    = defaultdict(int)
    total_lines      = 0

    print(f"{YELLOW}[*] Reading: {LOG_FILE}{RESET}\n")

    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                total_lines += 1
                parsed = parse_log_line(line)

                if not parsed:
                    continue

                ip     = parsed['ip']
                path   = parsed['path']
                status = parsed['status']
                agent  = parsed['agent'].lower()

                # Count requests per IP
                ip_requests[ip] += 1

                # Count status codes
                status_counts[status] += 1

                # Count 404s per IP
                if status == '404':
                    ip_404s[ip] += 1

                # Check suspicious paths
                for sus_path in SUSPICIOUS_PATHS:
                    if sus_path.lower() in path.lower():
                        suspicious_paths[ip].append(path)
                        break

                # Check suspicious agents
                for sus_agent in SUSPICIOUS_AGENTS:
                    if sus_agent in agent:
                        suspicious_agents[ip].append(agent)
                        break

    except PermissionError:
        print(f"{RED}[!] Permission denied! Run with sudo{RESET}")
        return
    except FileNotFoundError:
        print(f"{RED}[!] Log file not found: {LOG_FILE}{RESET}")
        return

    # ==================
    # PRINT RESULTS
    # ==================

    # Summary
    print(f"{GREEN}{'='*55}{RESET}")
    print(f"{GREEN}   SUMMARY{RESET}")
    print(f"{GREEN}{'='*55}{RESET}")
    print(f"{GREEN}[+] Total log lines:    {total_lines}{RESET}")
    print(f"{GREEN}[+] Unique IPs:         {len(ip_requests)}{RESET}")
    print(f"{GREEN}[+] Total 404 errors:   {ip_404s and sum(ip_404s.values()) or 0}{RESET}")
    print(f"{GREEN}[+] Suspicious IPs:     {len(suspicious_paths)}{RESET}\n")

    # Status code breakdown
    print(f"{CYAN}{'='*55}{RESET}")
    print(f"{CYAN}   STATUS CODE BREAKDOWN{RESET}")
    print(f"{CYAN}{'='*55}{RESET}")
    for status, count in sorted(status_counts.items()):
        if status.startswith('2'):
            color = GREEN
        elif status.startswith('4'):
            color = YELLOW
        elif status.startswith('5'):
            color = RED
        else:
            color = RESET
        print(f"{color}[+] HTTP {status}: {count} requests{RESET}")
    print()

    # Directory scanning detection
    print(f"{YELLOW}{'='*55}{RESET}")
    print(f"{YELLOW}   DIRECTORY SCANNING DETECTION{RESET}")
    print(f"{YELLOW}{'='*55}{RESET}")
    for ip, count in sorted(ip_404s.items(),
                            key=lambda x: x[1],
                            reverse=True):
        if count >= THRESHOLD:
            print(f"{RED}[ALERT] Directory scanning from {ip}!{RESET}")
            print(f"{RED}[!]     404 errors: {count}{RESET}")
            print(f"{RED}[!]     RECOMMENDED: Block {ip}!{RESET}\n")
        else:
            print(f"{GREEN}[OK] {ip} — {count} 404 errors{RESET}")
    print()

    # Suspicious paths
    if suspicious_paths:
        print(f"{RED}{'='*55}{RESET}")
        print(f"{RED}   SUSPICIOUS PATH ATTEMPTS{RESET}")
        print(f"{RED}{'='*55}{RESET}")
        for ip, paths in suspicious_paths.items():
            unique_paths = list(set(paths))
            print(f"{RED}[ALERT] {ip} accessed suspicious paths!{RESET}")
            for path in unique_paths:
                print(f"{RED}        → {path}{RESET}")
            print()

    # Suspicious user agents
    if suspicious_agents:
        print(f"{RED}{'='*55}{RESET}")
        print(f"{RED}   SUSPICIOUS USER AGENTS (ATTACK TOOLS!){RESET}")
        print(f"{RED}{'='*55}{RESET}")
        for ip, agents in suspicious_agents.items():
            unique_agents = list(set(agents))
            print(f"{RED}[ALERT] {ip} used attack tools!{RESET}")
            for agent in unique_agents:
                print(f"{RED}        → Tool: {agent}{RESET}")
            print()

    # Top requesters
    print(f"{CYAN}{'='*55}{RESET}")
    print(f"{CYAN}   TOP REQUESTING IPs{RESET}")
    print(f"{CYAN}{'='*55}{RESET}")
    for ip, count in sorted(ip_requests.items(),
                            key=lambda x: x[1],
                            reverse=True)[:5]:
        if count >= THRESHOLD:
            print(f"{RED}[!] {ip} — {count} total requests (HIGH!){RESET}")
        else:
            print(f"{GREEN}[OK] {ip} — {count} total requests{RESET}")

    print(f"\n{BLUE}{'='*55}{RESET}")
    print(f"{BLUE}   Analysis Complete!{RESET}")
    print(f"{BLUE}{'='*55}{RESET}\n")

if __name__ == "__main__":
    analyze_logs()
