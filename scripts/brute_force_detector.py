#!/usr/bin/env python3
# ==============================================
# Brute Force Detector
# Author: Vijay Gaddi
# Description: Detects SSH brute force attacks
#              by analyzing /var/log/auth.log
# ==============================================

import re
from collections import defaultdict
from datetime import datetime

# Configuration
LOG_FILE = "/var/log/auth.log"
THRESHOLD = 5  # alerts if IP exceeds this

# Colors for terminal output
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
RESET  = "\033[0m"

def parse_auth_log():
    """Read auth.log and extract failed login attempts"""
    
    print(f"\n{BLUE}{'='*50}{RESET}")
    print(f"{BLUE}   SOC BRUTE FORCE DETECTOR{RESET}")
    print(f"{BLUE}   Analyst: Vijay Gaddi{RESET}")
    print(f"{BLUE}   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BLUE}{'='*50}{RESET}\n")
    
    # Dictionary to store attempts per IP
    ip_attempts = defaultdict(list)
    
    # Pattern to match Invalid user lines
    pattern = r'Invalid user (\S+) from (\S+)'
    
    print(f"{YELLOW}[*] Reading log file: {LOG_FILE}{RESET}")
    
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                if 'Invalid user' in line:
                    match = re.search(pattern, line)
                    if match:
                        username = match.group(1)
                        ip = match.group(2)
                        # Extract timestamp
                        timestamp = line[:15]
                        ip_attempts[ip].append({
                            'username': username,
                            'timestamp': timestamp
                        })
    
    except PermissionError:
        print(f"{RED}[!] Permission denied!{RESET}")
        print(f"{RED}[!] Run with sudo: sudo python3 brute_force_detector.py{RESET}")
        return
    
    except FileNotFoundError:
        print(f"{RED}[!] Log file not found: {LOG_FILE}{RESET}")
        return
    
    # Analysis Results
    total_ips    = len(ip_attempts)
    total_attempts = sum(len(v) for v in ip_attempts.values())
    
    print(f"{GREEN}[+] Analysis Complete!{RESET}")
    print(f"{GREEN}[+] Total unique IPs found: {total_ips}{RESET}")
    print(f"{GREEN}[+] Total failed attempts: {total_attempts}{RESET}\n")
    
    # Check each IP against threshold
    print(f"{YELLOW}[*] Checking IPs against threshold ({THRESHOLD} attempts){RESET}\n")
    
    alerts_found = False
    
    for ip, attempts in sorted(ip_attempts.items(),
                               key=lambda x: len(x[1]),
                               reverse=True):
        count = len(attempts)
        
        if count >= THRESHOLD:
            alerts_found = True
            first_seen = attempts[0]['timestamp']
            last_seen  = attempts[-1]['timestamp']
            usernames  = set(a['username'] for a in attempts)
            
            print(f"{RED}{'='*50}{RESET}")
            print(f"{RED}[ALERT] BRUTE FORCE DETECTED!{RESET}")
            print(f"{RED}{'='*50}{RESET}")
            print(f"{RED}[!] Attacking IP:    {ip}{RESET}")
            print(f"{RED}[!] Total Attempts:  {count}{RESET}")
            print(f"{RED}[!] First Seen:      {first_seen}{RESET}")
            print(f"{RED}[!] Last Seen:       {last_seen}{RESET}")
            print(f"{RED}[!] Usernames tried: {', '.join(usernames)}{RESET}")
            print(f"{RED}[!] RECOMMENDED:     Block {ip} immediately!{RESET}")
            print(f"{RED}{'='*50}{RESET}\n")
        
        else:
            print(f"{GREEN}[OK] {ip} — {count} attempts (below threshold){RESET}")
    
    if not alerts_found:
        print(f"{GREEN}[+] No brute force attacks detected!{RESET}")
    
    print(f"\n{BLUE}{'='*50}{RESET}")
    print(f"{BLUE}   Scan Complete!{RESET}")
    print(f"{BLUE}{'='*50}{RESET}\n")

if __name__ == "__main__":
    parse_auth_log()

