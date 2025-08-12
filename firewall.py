#!/usr/bin/env python3
import os
import sys
import time
import json
import signal
import logging
from collections import defaultdict, deque
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, Raw
import argparse

RULES_PATH = "rules.json"
LOG_PATH = "firewall.log"

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

RATE_LIMIT_WINDOW = 10
RATE_LIMIT_COUNT = 20
rate_buckets = defaultdict(lambda: deque())

def load_rules():
    if not os.path.exists(RULES_PATH):
        return {"blocked_ips": [], "blocked_ports": [], "blocked_payloads": []}
    with open(RULES_PATH) as f:
        return json.load(f)

def save_rules(rules):
    with open(RULES_PATH, "w") as f:
        json.dump(rules, f, indent=2)

def should_drop(pkt, rules):
    ip = pkt.getlayer(IP)
    if ip is None:
        return False
    src = ip.src
    dst = ip.dst

    now = time.time()
    bucket = rate_buckets[src]
    bucket.append(now)
    while bucket and bucket[0] < now - RATE_LIMIT_WINDOW:
        bucket.popleft()
    if len(bucket) > RATE_LIMIT_COUNT:
        logging.warning(f"Rate limit exceeded by {src} ({len(bucket)} requests in {RATE_LIMIT_WINDOW}s)")
        print(f"[!] Rate limit exceeded by {src}")
        return True

    if src in rules.get("blocked_ips", []) or dst in rules.get("blocked_ips", []):
        logging.info(f"Blocked by IP rule: {src} -> {dst}")
        print(f"[!] Dropped packet by IP rule: {src} -> {dst}")
        return True

    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        l = pkt.getlayer(TCP) or pkt.getlayer(UDP)
        sport = getattr(l, "sport", None)
        dport = getattr(l, "dport", None)
        if sport in rules.get("blocked_ports", []) or dport in rules.get("blocked_ports", []):
            logging.info(f"Blocked by port rule: {src}:{sport} -> {dst}:{dport}")
            print(f"[!] Dropped packet by port rule: {src}:{sport} -> {dst}:{dport}")
            return True

    if pkt.haslayer(Raw):
        try:
            payload = pkt[Raw].load.decode(errors="ignore")
        except Exception:
            payload = ""
        for pattern in rules.get("blocked_payloads", []):
            if pattern and pattern in payload:
                logging.info(f"Blocked by payload pattern from {src} to {dst} pattern={pattern}")
                print(f"[!] Dropped packet by payload pattern from {src} to {dst} pattern={pattern}")
                return True
    return False

def process_packet(nfpacket):
    try:
        pkt = IP(nfpacket.get_payload())
    except Exception:
        nfpacket.accept()
        return
    rules = load_rules()
    if should_drop(pkt, rules):
        nfpacket.drop()
        logging.info(f"DROPPED {pkt.src} -> {pkt.dst}")
    else:
        nfpacket.accept()

def run_queue(queue_num=1):
    open(LOG_PATH, 'w').close()
    print("[*] Firewall started and listening on NFQUEUE %d. Press Ctrl+C to stop." % queue_num)

    nfq = NetfilterQueue()
    nfq.bind(queue_num, process_packet)

    def signal_handler(sig, frame):
        print("\n[!] Stopping firewall...")
        nfq.unbind()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    try:
        nfq.run()
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        nfq.unbind()

def add_ip(ip):
    rules = load_rules()
    if ip not in rules["blocked_ips"]:
        rules["blocked_ips"].append(ip)
        save_rules(rules)
        print(f"[+] Added blocked IP: {ip}")
    else:
        print(f"[!] IP {ip} already blocked")

def remove_ip(ip):
    rules = load_rules()
    if ip in rules["blocked_ips"]:
        rules["blocked_ips"].remove(ip)
        save_rules(rules)
        print(f"[+] Removed blocked IP: {ip}")
    else:
        print(f"[!] IP {ip} not found in block list")

def add_port(port):
    port = int(port)
    rules = load_rules()
    if port not in rules["blocked_ports"]:
        rules["blocked_ports"].append(port)
        save_rules(rules)
        print(f"[+] Added blocked port: {port}")
    else:
        print(f"[!] Port {port} already blocked")

def remove_port(port):
    port = int(port)
    rules = load_rules()
    if port in rules["blocked_ports"]:
        rules["blocked_ports"].remove(port)
        save_rules(rules)
        print(f"[+] Removed blocked port: {port}")
    else:
        print(f"[!] Port {port} not found in block list")

def list_rules():
    rules = load_rules()
    print("Current firewall rules:")
    print(f"Blocked IPs: {rules.get('blocked_ips', [])}")
    print(f"Blocked ports: {rules.get('blocked_ports', [])}")
    print(f"Blocked payload patterns: {rules.get('blocked_payloads', [])}")

def add_payload(pattern):
    rules = load_rules()
    if pattern not in rules["blocked_payloads"]:
        rules["blocked_payloads"].append(pattern)
        save_rules(rules)
        print(f"[+] Added blocked payload pattern: {pattern}")
    else:
        print(f"[!] Payload pattern already blocked")

def remove_payload(pattern):
    rules = load_rules()
    if pattern in rules["blocked_payloads"]:
        rules["blocked_payloads"].remove(pattern)
        save_rules(rules)
        print(f"[+] Removed blocked payload pattern: {pattern}")
    else:
        print(f"[!] Payload pattern not found")

def main():
    parser = argparse.ArgumentParser(description="Simple NFQUEUE-based firewall")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("start", help="Start firewall (bind to NFQUEUE)")

    add_ip_parser = subparsers.add_parser("add-ip", help="Add IP to blocked list")
    add_ip_parser.add_argument("ip", help="IP address to block")

    remove_ip_parser = subparsers.add_parser("remove-ip", help="Remove IP from blocked list")
    remove_ip_parser.add_argument("ip", help="IP address to unblock")

    add_port_parser = subparsers.add_parser("add-port", help="Add TCP/UDP port to blocked list")
    add_port_parser.add_argument("port", help="Port number to block")

    remove_port_parser = subparsers.add_parser("remove-port", help="Remove port from blocked list")
    remove_port_parser.add_argument("port", help="Port number to unblock")

    list_parser = subparsers.add_parser("list", help="List current firewall rules")

    add_payload_parser = subparsers.add_parser("add-payload", help="Add payload pattern to block")
    add_payload_parser.add_argument("pattern", help="Payload substring to block")

    remove_payload_parser = subparsers.add_parser("remove-payload", help="Remove payload pattern")
    remove_payload_parser.add_argument("pattern", help="Payload substring to unblock")

    args = parser.parse_args()

    if args.command == "start":
        run_queue()
    elif args.command == "add-ip":
        add_ip(args.ip)
    elif args.command == "remove-ip":
        remove_ip(args.ip)
    elif args.command == "add-port":
        add_port(args.port)
    elif args.command == "remove-port":
        remove_port(args.port)
    elif args.command == "list":
        list_rules()
    elif args.command == "add-payload":
        add_payload(args.pattern)
    elif args.command == "remove-payload":
        remove_payload(args.pattern)

if __name__ == "__main__":
    main()
