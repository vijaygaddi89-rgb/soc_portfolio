# SOC Lab Setup — Ubuntu LTS

## Hardware
- Laptop: Dell Inspiron 15 5518
- OS: Ubuntu LTS (dual boot with Windows)
- Storage: 77GB total, 60GB free

## Tools Installed
| Tool | Purpose |
|------|---------|
| Splunk Enterprise | SIEM platform |
| Wireshark | Network packet analysis |
| tcpdump | Command line packet capture |
| tshark | Terminal based Wireshark |
| Nmap | Port scanning and reconnaissance |
| Suricata | Intrusion Detection System |
| Hydra | Password attack simulation |
| John the Ripper | Password cracking |
| Binwalk | Firmware analysis |
| Exiftool | Metadata extraction |
| YARA | Malware pattern matching |

## Services Running
| Service | Purpose | Port |
|---------|---------|------|
| Apache2 | Web server for attack simulation | 80 |
| OpenSSH | SSH server for brute force simulation | 22 |
| Splunk | SIEM web interface | 8000 |
| Postfix | Mail server | 25 |

## Attack Simulations Performed
| Attack | Tool Used | Log Generated |
|--------|----------|---------------|
| SSH Brute Force | sshpass + bash loop | /var/log/auth.log |
| Directory Scanning | curl loop | /var/log/apache2/access.log |
| Port Scanning | Nmap -sV -sC -O | /var/log/auth.log |
| Network Traffic | tcpdump | captures/day2-capture.pcap |
