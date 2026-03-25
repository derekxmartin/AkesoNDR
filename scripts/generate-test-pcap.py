#!/usr/bin/env python3
"""
Generate a minimal test PCAP file with DNS and HTTP traffic.

Requires: pip install scapy
Usage:    python3 scripts/generate-test-pcap.py
Output:   tests/pcaps/test.pcap
"""

import sys

try:
    from scapy.all import (
        Ether, IP, UDP, TCP, DNS, DNSQR, DNSRR, Raw, wrpcap,
    )
except ImportError:
    print("scapy not installed — writing empty placeholder PCAP")
    # Write a valid but empty pcap file header (libpcap format)
    import struct
    PCAP_MAGIC = 0xA1B2C3D4
    with open("tests/pcaps/test.pcap", "wb") as f:
        # Global header: magic, version 2.4, thiszone=0, sigfigs=0,
        # snaplen=65535, network=1 (Ethernet)
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 1))
    print("Wrote empty placeholder: tests/pcaps/test.pcap")
    sys.exit(0)

packets = []

# --- DNS query: A record for example.com ---
dns_query = (
    Ether()
    / IP(src="10.0.0.100", dst="8.8.8.8")
    / UDP(sport=12345, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
)
packets.append(dns_query)

# --- DNS response ---
dns_response = (
    Ether()
    / IP(src="8.8.8.8", dst="10.0.0.100")
    / UDP(sport=53, dport=12345)
    / DNS(
        qr=1, aa=0, rd=1, ra=1,
        qd=DNSQR(qname="example.com", qtype="A"),
        an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=3600),
    )
)
packets.append(dns_response)

# --- TCP 3-way handshake for HTTP ---
syn = Ether() / IP(src="10.0.0.100", dst="93.184.216.34") / TCP(sport=54321, dport=80, flags="S", seq=1000)
syn_ack = Ether() / IP(src="93.184.216.34", dst="10.0.0.100") / TCP(sport=80, dport=54321, flags="SA", seq=2000, ack=1001)
ack = Ether() / IP(src="10.0.0.100", dst="93.184.216.34") / TCP(sport=54321, dport=80, flags="A", seq=1001, ack=2001)
packets.extend([syn, syn_ack, ack])

# --- HTTP GET request ---
http_req = (
    Ether()
    / IP(src="10.0.0.100", dst="93.184.216.34")
    / TCP(sport=54321, dport=80, flags="PA", seq=1001, ack=2001)
    / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: AkesoNDR-Test/1.0\r\nAccept: */*\r\n\r\n")
)
packets.append(http_req)

# --- HTTP 200 response ---
http_resp = (
    Ether()
    / IP(src="93.184.216.34", dst="10.0.0.100")
    / TCP(sport=80, dport=54321, flags="PA", seq=2001, ack=1001 + len(http_req[Raw].load))
    / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!")
)
packets.append(http_resp)

# --- TCP FIN ---
fin = Ether() / IP(src="10.0.0.100", dst="93.184.216.34") / TCP(sport=54321, dport=80, flags="FA", seq=1001 + len(http_req[Raw].load), ack=2001 + len(http_resp[Raw].load))
packets.append(fin)

wrpcap("tests/pcaps/test.pcap", packets)
print(f"Wrote {len(packets)} packets to tests/pcaps/test.pcap")
