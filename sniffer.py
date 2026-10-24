#!/usr/bin/env python3
"""
Basic Network Sniffer (Task 1 - Cyber Security Internship)

Captures packets using Scapy and shows:
  - Source / destination IPs
  - Protocol (TCP, UDP, ICMP, DNS, HTTP hints)
  - Source / destination ports
  - Payload preview (printable characters only)

Usage (Linux, needs root for raw sockets):
    sudo python3 sniffer.py                    # sniff 20 packets on default iface
    sudo python3 sniffer.py -i wlan0 -c 50     # specific interface, 50 packets
    sudo python3 sniffer.py -f "tcp port 80"   # BPF filter
    sudo python3 sniffer.py -c 100 -o log.txt  # also save to a file

Install:
    pip install scapy

LEGAL / ETHICAL NOTE:
    Only capture traffic on your OWN network or with written permission.
    Unauthorized sniffing is an offence under PECA 2016 (Pakistan).
"""

import argparse
import sys
from datetime import datetime

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw
except ImportError:
    sys.exit("Scapy not installed. Run: pip install scapy")

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
packet_count = 0
log_file = None


def out(line=""):
    """Print to screen and optionally to log file."""
    print(line)
    if log_file:
        log_file.write(line + "\n")


def payload_preview(pkt, limit=80):
    """Return printable preview of payload bytes."""
    if Raw in pkt:
        data = bytes(pkt[Raw].load)[:limit]
        return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return ""


def process_packet(pkt):
    global packet_count

    if IP in pkt:
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        proto = PROTO_NAMES.get(ip.proto, f"Other({ip.proto})")
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        src, dst = ip.src, ip.dst
        proto = PROTO_NAMES.get(ip.nh, f"Other({ip.nh})")
    else:
        return  # skip non-IP frames (ARP etc.)

    packet_count += 1
    sport = dport = None
    extra = ""

    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        extra = f"flags={pkt[TCP].flags}"
        if 80 in (sport, dport):
            proto = "TCP/HTTP"
        elif 443 in (sport, dport):
            proto = "TCP/HTTPS (encrypted)"
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        if DNS in pkt and pkt.haslayer(DNSQR):
            proto = "UDP/DNS"
            extra = f"query={pkt[DNSQR].qname.decode(errors='ignore')}"
    elif ICMP in pkt:
        extra = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"

    out(f"[{packet_count}] {datetime.now().strftime('%H:%M:%S')}")
    out(f"  Source      : {src}" + (f":{sport}" if sport else ""))
    out(f"  Destination : {dst}" + (f":{dport}" if dport else ""))
    out(f"  Protocol    : {proto}   Length: {len(pkt)} bytes   {extra}")
    preview = payload_preview(pkt)
    if preview:
        out(f"  Payload     : {preview}")
    out("-" * 60)


def main():
    global log_file
    parser = argparse.ArgumentParser(description="Basic network sniffer (Scapy)")
    parser.add_argument("-i", "--iface", help="Interface (default: Scapy default)")
    parser.add_argument("-c", "--count", type=int, default=20,
                        help="Number of packets (0 = unlimited, Ctrl+C to stop)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    parser.add_argument("-o", "--output", help="Save output to this text file")
    args = parser.parse_args()

    if args.output:
        log_file = open(args.output, "w", encoding="utf-8")

    out(f"Sniffing started (iface={args.iface or 'default'}, "
        f"count={args.count or 'unlimited'}, filter='{args.filter or 'none'}')")
    out("Press Ctrl+C to stop.\n")

    try:
        sniff(iface=args.iface, filter=args.filter or None,
              prn=process_packet, count=args.count, store=False)
    except PermissionError:
        sys.exit("Permission denied. Run with sudo (root needed for raw sockets).")
    except KeyboardInterrupt:
        pass
    finally:
        out(f"\nDone. {packet_count} IP packets captured.")
        if log_file:
            log_file.close()


if __name__ == "__main__":
    main()
