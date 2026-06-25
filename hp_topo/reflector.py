#!/usr/bin/env python3
import sys
from scapy.all import sniff, sendp, conf

packet_count = 0

def reflect_packet(pkt, iface):
    global packet_count

    sendp(pkt, iface=iface, verbose=False)

    packet_count += 1

    print(
        f"[reflector] #{packet_count} reflected on {iface} | "
        f"src={pkt.src} dst={pkt.dst} len={len(pkt)}"
    )

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 reflector.py <interface>")
        sys.exit(1)

    iface = sys.argv[1]
    print(f"[reflector] Active on interface: {iface}")

    conf.sniff_promisc = True

    sniff(
        iface=iface,
        filter="ether proto 0x88b5",
        prn=lambda pkt: reflect_packet(pkt, iface),
        store=False
    )

if __name__ == "__main__":
    main()