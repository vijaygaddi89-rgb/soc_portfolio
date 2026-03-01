# Investigation Report — Day 2
## Port Scanning Detection

**Date:** 02 March 2026
**Analyst:** Vijay Gaddi
**Severity:** High

## Summary
Detected port scanning activity against local machine.
Nmap scan performed against localhost revealed 4 open
ports and left clear traces in system logs.

## Open Ports Found
| Port | Service | Version | Risk |
|------|---------|---------|------|
| 22 | SSH | OpenSSH 9.6p1 | High |
| 25 | SMTP | Postfix | Medium |
| 80 | HTTP | Apache 2.4.58 | Medium |
| 631 | IPP | CUPS 2.4 | Low |

## Security Issues Identified
- VRFY command enabled on SMTP (username enumeration)
- Apache showing default page (reveals fresh install)
- SSH exposed (brute force risk)
- Server headers revealing version info

## Scan Detected in Logs
- Multiple connections within same second
- Different ports used per probe (42978, 42982, 42990)
- Protocol version probing detected
- Key type enumeration detected (ssh-dss, ssh-rsa, ecdsa)
- All from single IP: 127.0.0.1

## How Scan Was Detected
Pattern: 8+ SSH connections in under 1 second
from same IP using different source ports
= automated port scanner confirmed

## Verdict
TRUE POSITIVE — Port Scanning Attack Detected
Attacker was performing reconnaissance

## Recommended Actions
- Block scanning IP on firewall
- Disable VRFY on SMTP server
- Hide Apache server headers
- Remove default Apache page
- Consider moving SSH to non-standard port

## Tools Used
- Nmap (-sV -sC -O flags)
- /var/log/auth.log analysis
- grep, tail
