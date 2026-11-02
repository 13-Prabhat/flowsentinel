"""Generate an anonymised synthetic web traffic pcap fixture for testing.

Satisfies FR-DEV-05, Appendix A.8, and tests/test_fixture.py.
"""

import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        import scapy.libs.winpcapy

        scapy.libs.winpcapy.pcap_findalldevs = lambda *a, **k: -1
    except (ImportError, AttributeError):
        pass

from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

FIXTURE_PATH = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "sample_web.pcap"


def generate() -> Path:
    FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    mac1 = "02:00:00:00:00:01"
    mac2 = "02:00:00:00:00:02"
    mac_dns = "02:00:00:00:00:03"

    client_ip = "10.0.0.1"
    server_ip = "93.184.216.34"
    dns_ip = "10.0.0.53"

    packets = []
    t = 1700000000.0

    # 1. DNS Query & Response (UDP)
    dns_query = (
        Ether(src=mac1, dst=mac_dns)
        / IP(src=client_ip, dst=dns_ip, ttl=64)
        / UDP(sport=53000, dport=53)
        / Raw(
            load=(
                b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x07example\x03com\x00\x00\x01\x00\x01"
            )
        )
    )
    dns_query.time = t
    packets.append(dns_query)
    t += 0.015

    dns_resp = (
        Ether(src=mac_dns, dst=mac1)
        / IP(src=dns_ip, dst=client_ip, ttl=64)
        / UDP(sport=53, dport=53000)
        / Raw(
            load=(
                b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
                b"\x07example\x03com\x00\x00\x01\x00\x01"
                b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04]\xb8\xd8"'
            )
        )
    )
    dns_resp.time = t
    packets.append(dns_resp)
    t += 0.020

    # 2. HTTP session 1: GET / (TCP port 80)
    c_port = 51000
    s_port = 80
    c_seq = 1000
    s_seq = 5000

    # SYN
    syn = (
        Ether(src=mac1, dst=mac2)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=c_port, dport=s_port, seq=c_seq, ack=0, flags="S", window=64240)
    )
    syn.time = t
    packets.append(syn)
    t += 0.025

    # SYN-ACK
    syn_ack = (
        Ether(src=mac2, dst=mac1)
        / IP(src=server_ip, dst=client_ip, ttl=56)
        / TCP(sport=s_port, dport=c_port, seq=s_seq, ack=c_seq + 1, flags="SA", window=65535)
    )
    syn_ack.time = t
    packets.append(syn_ack)
    t += 0.025
    c_seq += 1
    s_seq += 1

    # ACK
    ack1 = (
        Ether(src=mac1, dst=mac2)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=c_port, dport=s_port, seq=c_seq, ack=s_seq, flags="A", window=64240)
    )
    ack1.time = t
    packets.append(ack1)
    t += 0.005

    # HTTP Request
    req_payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: FlowSentinel-Test\r\n"
        b"Accept: */*\r\n\r\n"
    )
    http_req = (
        Ether(src=mac1, dst=mac2)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=c_port, dport=s_port, seq=c_seq, ack=s_seq, flags="PA", window=64240)
        / Raw(load=req_payload)
    )
    http_req.time = t
    packets.append(http_req)
    t += 0.030
    c_seq += len(req_payload)

    # Server ACK for request
    ack_req = (
        Ether(src=mac2, dst=mac1)
        / IP(src=server_ip, dst=client_ip, ttl=56)
        / TCP(sport=s_port, dport=c_port, seq=s_seq, ack=c_seq, flags="A", window=65535)
    )
    ack_req.time = t
    packets.append(ack_req)
    t += 0.010

    # Server Response Chunks (2 chunks)
    resp_chunk1 = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 120\r\n\r\n"
        b"<!doctype html><html><head><title>Example</title></head>"
    )
    http_resp1 = (
        Ether(src=mac2, dst=mac1)
        / IP(src=server_ip, dst=client_ip, ttl=56)
        / TCP(sport=s_port, dport=c_port, seq=s_seq, ack=c_seq, flags="A", window=65535)
        / Raw(load=resp_chunk1)
    )
    http_resp1.time = t
    packets.append(http_resp1)
    t += 0.002
    s_seq += len(resp_chunk1)

    resp_chunk2 = (
        b"<body><h1>Example Domain</h1><p>FlowSentinel test fixture payload.</p></body></html>\n"
    )
    http_resp2 = (
        Ether(src=mac2, dst=mac1)
        / IP(src=server_ip, dst=client_ip, ttl=56)
        / TCP(sport=s_port, dport=c_port, seq=s_seq, ack=c_seq, flags="PA", window=65535)
        / Raw(load=resp_chunk2)
    )
    http_resp2.time = t
    packets.append(http_resp2)
    t += 0.020
    s_seq += len(resp_chunk2)

    # Client ACK for response
    ack_resp = (
        Ether(src=mac1, dst=mac2)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=c_port, dport=s_port, seq=c_seq, ack=s_seq, flags="A", window=64240)
    )
    ack_resp.time = t
    packets.append(ack_resp)
    t += 0.050

    # Server FIN-ACK
    fin_s = (
        Ether(src=mac2, dst=mac1)
        / IP(src=server_ip, dst=client_ip, ttl=56)
        / TCP(sport=s_port, dport=c_port, seq=s_seq, ack=c_seq, flags="FA", window=65535)
    )
    fin_s.time = t
    packets.append(fin_s)
    t += 0.010
    s_seq += 1

    # Client ACK of Server FIN
    ack_fin_s = (
        Ether(src=mac1, dst=mac2)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=c_port, dport=s_port, seq=c_seq, ack=s_seq, flags="A", window=64240)
    )
    ack_fin_s.time = t
    packets.append(ack_fin_s)
    t += 0.005

    # Client FIN-ACK
    fin_c = (
        Ether(src=mac1, dst=mac2)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=c_port, dport=s_port, seq=c_seq, ack=s_seq, flags="FA", window=64240)
    )
    fin_c.time = t
    packets.append(fin_c)
    t += 0.010
    c_seq += 1

    # Server ACK of Client FIN
    ack_fin_c = (
        Ether(src=mac2, dst=mac1)
        / IP(src=server_ip, dst=client_ip, ttl=56)
        / TCP(sport=s_port, dport=c_port, seq=s_seq, ack=c_seq, flags="A", window=65535)
    )
    ack_fin_c.time = t
    packets.append(ack_fin_c)
    t += 0.500

    # 3. HTTP session 2: GET /style.css (10 packets)
    c_port2 = 51001
    c_seq2 = 2000
    s_seq2 = 7000

    # SYN
    packets.append(
        Ether(src=mac1, dst=mac2)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=c_port2, dport=s_port, seq=c_seq2, ack=0, flags="S", window=64240)
    )
    packets[-1].time = t
    t += 0.020
    c_seq2 += 1

    # SYN-ACK
    packets.append(
        Ether(src=mac2, dst=mac1)
        / IP(src=server_ip, dst=client_ip, ttl=56)
        / TCP(sport=s_port, dport=c_port2, seq=s_seq2, ack=c_seq2, flags="SA", window=65535)
    )
    packets[-1].time = t
    t += 0.020
    s_seq2 += 1

    # ACK
    packets.append(
        Ether(src=mac1, dst=mac2)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=c_port2, dport=s_port, seq=c_seq2, ack=s_seq2, flags="A", window=64240)
    )
    packets[-1].time = t
    t += 0.005

    # Request
    req_css = b"GET /style.css HTTP/1.1\r\nHost: example.com\r\n\r\n"
    packets.append(
        Ether(src=mac1, dst=mac2)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=c_port2, dport=s_port, seq=c_seq2, ack=s_seq2, flags="PA", window=64240)
        / Raw(load=req_css)
    )
    packets[-1].time = t
    t += 0.025
    c_seq2 += len(req_css)

    # Server ACK
    packets.append(
        Ether(src=mac2, dst=mac1)
        / IP(src=server_ip, dst=client_ip, ttl=56)
        / TCP(sport=s_port, dport=c_port2, seq=s_seq2, ack=c_seq2, flags="A", window=65535)
    )
    packets[-1].time = t
    t += 0.010

    # Server response
    resp_css = b"HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\nbody { background: #fff; }\n"
    packets.append(
        Ether(src=mac2, dst=mac1)
        / IP(src=server_ip, dst=client_ip, ttl=56)
        / TCP(sport=s_port, dport=c_port2, seq=s_seq2, ack=c_seq2, flags="PA", window=65535)
        / Raw(load=resp_css)
    )
    packets[-1].time = t
    t += 0.015
    s_seq2 += len(resp_css)

    # Client ACK
    packets.append(
        Ether(src=mac1, dst=mac2)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=c_port2, dport=s_port, seq=c_seq2, ack=s_seq2, flags="A", window=64240)
    )
    packets[-1].time = t
    t += 0.020

    # Server FIN-ACK
    packets.append(
        Ether(src=mac2, dst=mac1)
        / IP(src=server_ip, dst=client_ip, ttl=56)
        / TCP(sport=s_port, dport=c_port2, seq=s_seq2, ack=c_seq2, flags="FA", window=65535)
    )
    packets[-1].time = t
    t += 0.010
    s_seq2 += 1

    # Client ACK of FIN
    packets.append(
        Ether(src=mac1, dst=mac2)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=c_port2, dport=s_port, seq=c_seq2, ack=s_seq2, flags="A", window=64240)
    )
    packets[-1].time = t
    t += 0.005

    # Client FIN-ACK
    packets.append(
        Ether(src=mac1, dst=mac2)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=c_port2, dport=s_port, seq=c_seq2, ack=s_seq2, flags="FA", window=64240)
    )
    packets[-1].time = t
    t += 0.010
    c_seq2 += 1

    # Server ACK of FIN
    packets.append(
        Ether(src=mac2, dst=mac1)
        / IP(src=server_ip, dst=client_ip, ttl=56)
        / TCP(sport=s_port, dport=c_port2, seq=s_seq2, ack=c_seq2, flags="A", window=65535)
    )
    packets[-1].time = t

    wrpcap(str(FIXTURE_PATH), packets)
    print(f"Generated {len(packets)} packets in {FIXTURE_PATH}")
    return FIXTURE_PATH


if __name__ == "__main__":
    generate()
