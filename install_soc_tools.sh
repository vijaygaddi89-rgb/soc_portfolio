#!/bin/bash
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
echo "=========================================="
echo "   SOC ANALYST TOOL INSTALLER"
echo "=========================================="
sudo apt update -y && sudo apt upgrade -y
echo -e "\n${YELLOW}[*] Installing all SOC tools...${NC}"
sudo apt install -y wireshark tshark tcpdump nmap netcat-openbsd suricata snort binwalk foremost exiftool sleuthkit autopsy yara logwatch gawk net-tools curl wget git python3 python3-pip jq htop unzip whois john hashcat hydra apache2
pip3 install requests scapy pandas colorama --break-system-packages
echo -e "\n=========================================="
echo -e "   VERIFICATION"
echo -e "=========================================="
for tool in wireshark tshark tcpdump nmap suricata yara binwalk exiftool git python3 jq curl wget john hashcat; do
    command -v $tool &> /dev/null && echo -e "${GREEN}[✓] $tool${NC}" || echo -e "${RED}[✗] $tool missing${NC}"
done
echo -e "\n${GREEN}DONE! Your SOC lab is ready at ~/soc_directory${NC}"
