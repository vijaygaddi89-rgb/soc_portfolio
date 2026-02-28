# Investigation Report — Day 1
## Apache Web Server Log Analysis

**Date:** 28 February 2026  
**Analyst:** Vijay Gaddi  
**Severity:** Medium

## Summary
Detected automated directory scanning attack against
local Apache web server. Single IP made 130 requests
in a short time, all resulting in 404 errors.

## Findings
- Total Requests: 130
- Total 404 Errors: 130 (100% error rate)
- Attacking IP: 127.0.0.1
- Attack Type: Directory Scanning

## Pages Probed by Attacker
- /admin — 20 attempts
- /wp-login.php — 10 attempts
- /page1 to /page100 — automated scanning

## Verdict
TRUE POSITIVE — Automated scanning attack detected

## Recommended Action
- Block source IP on firewall
- Enable rate limiting on web server
- Monitor for further probing attempts

## Tools Used
- grep, awk, sort, uniq, wc
- Apache access logs
