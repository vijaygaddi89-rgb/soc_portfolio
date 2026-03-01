# Investigation Report — Day 2
## Network Traffic Analysis

**Date:** 01 March 2026
**Analyst:** Vijay Gaddi
**Severity:** Low (Clean Traffic)

## Summary
Captured and analyzed 1640 network packets from
WiFi interface wlp0s20f3. All traffic identified
as legitimate. No suspicious connections found.

## Findings
- Total Packets: 1640
- Capture Duration: ~60 seconds
- Interface: wlp0s20f3 (WiFi)

## Traffic Breakdown
- HTTP (port 80): Ubuntu connectivity checks
- DNS (port 53): Domain name lookups
- HTTPS (port 443): Encrypted web traffic
- ICMP: Ping traffic to google.com

## Top Communicating IPs
- 2607:6bc0::10 — 231 packets (Microsoft)
- 2620:1ec:50::12 — 210 packets (Microsoft)
- ec2-98-88-40-18.amazonaws.com — 55 packets (AWS)
- 104.20.29.66 — 26 packets (Cloudflare)

## Domains Identified
- connectivity-check.ubuntu.com (normal)
- cdn.jsdelivr.net (normal CDN)
- claude.ai (analyst using Claude)
- fastly.net (normal CDN)

## Verdict
CLEAN — No suspicious traffic detected
All connections identified as legitimate services

## Tools Used
- tcpdump (capture)
- tshark (analysis)
- awk, sort, uniq (data processing)
