# Investigation Report — Day 1
## SSH Brute Force Attack Detection

**Date:** 28 February 2026
**Analyst:** Vijay Gaddi
**Severity:** High

## Summary
Detected automated SSH brute force attack against
local machine. Single IP made 21 failed login attempts
within 1 minute using invalid username.

## Findings
- Total Failed Attempts: 21
- Attacking IP: 127.0.0.1
- Target Username: wronguser
- Time Period: 14:29 to 14:30 (1 minute)
- Attempts per minute: 21
- Attack Type: SSH Brute Force

## Evidence
- All attempts from single IP
- Attempts every 2-4 seconds (automated tool)
- Invalid username used every time
- Different process IDs (sshd[8051], sshd[8423]...)
  confirming automated attack tool

## Verdict
TRUE POSITIVE — Automated SSH Brute Force Attack

## Recommended Action
- Block 127.0.0.1 on firewall immediately
- Enable fail2ban to auto-block brute force
- Disable password authentication on SSH
- Use SSH key authentication instead

## Tools Used
- grep, awk, sort, uniq
- /var/log/auth.log
