# Python NFQUEUE Firewall Project

This is a simple Python firewall using Linux's NFQUEUE and `iptables`. It can block IPs, ports, and payload patterns in real-time.

## Features

- Block IP addresses  
- Block TCP/UDP ports  
- Block packets by payload content  
- Rate limiting to prevent flooding  
- CLI to manage rules live  
- Logs dropped packets with timestamps  

## Setup

1. Run on Kali Linux with `iptables` support.  
2. Install dependencies:


sudo apt update
sudo apt install python3 python3-netfilterqueue iptables
pip3 install scapy

3. Set iptables rules:


sudo iptables -I INPUT -j NFQUEUE --queue-num 1
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1

4. Run firewall:
 
sudo python3 firewall.py start

5. Use commands like:


sudo python3 firewall.py add-ip 8.8.8.8
sudo python3 firewall.py add-port 80
sudo python3 firewall.py list


## Demo

Run the provided demo script:


# firewall_project
