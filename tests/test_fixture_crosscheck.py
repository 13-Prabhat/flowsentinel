"""Cross-check the hand-written parser against scapy on the real fixture."""

from pathlib import Path

import pytest
from scapy.all import IP, TCP, UDP, rdpcap

from flowsentinel.parser.packet import TcpFlags
from flowsentinel.parser.pcap import read_pcap

FIXTURE = Path(__file__).parent / "fixtures" / "sample_web.pcap"


def scapy_ipv4_packets():
    return [p for p in rdpcap(str(FIXTURE)) if IP in p]


def test_packet_count_matches_scapy():
    assert len(list(read_pcap(FIXTURE))) == len(scapy_ipv4_packets())


def test_ip_fields_match_scapy():
    for mine, ref in zip(read_pcap(FIXTURE), scapy_ipv4_packets(), strict=True):
        ip = ref[IP]
        assert mine.src_ip == ip.src
        assert mine.dst_ip == ip.dst
        assert mine.ttl == ip.ttl
        assert mine.protocol == ip.proto
        assert mine.timestamp == pytest.approx(float(ref.time), abs=1e-5)


def test_tcp_and_udp_fields_match_scapy():
    for mine, ref in zip(read_pcap(FIXTURE), scapy_ipv4_packets(), strict=True):
        if TCP in ref:
            tcp = ref[TCP]
            assert (mine.src_port, mine.dst_port) == (tcp.sport, tcp.dport)
            assert (mine.seq, mine.ack, mine.window) == (tcp.seq, tcp.ack, tcp.window)
            assert mine.tcp_flags == TcpFlags(int(tcp.flags))
        elif UDP in ref:
            assert (mine.src_port, mine.dst_port) == (ref[UDP].sport, ref[UDP].dport)


def test_payload_lengths_match_header_arithmetic():
    for mine, ref in zip(read_pcap(FIXTURE), scapy_ipv4_packets(), strict=True):
        ip = ref[IP]
        if ip.len == 0:  # segmentation offload on the capturing host
            continue
        l4_len = ip.len - ip.ihl * 4
        if TCP in ref:
            assert mine.payload_len == l4_len - ref[TCP].dataofs * 4
        elif UDP in ref:
            assert mine.payload_len == l4_len - 8
