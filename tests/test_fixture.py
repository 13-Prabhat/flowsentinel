from ipaddress import ip_address
from pathlib import Path

from scapy.all import IP, TCP, rdpcap

FIXTURE = Path(__file__).parent / "fixtures" / "sample_web.pcap"


def test_fixture_is_under_one_megabyte():
    assert FIXTURE.stat().st_size < 1_000_000


def test_fixture_contains_tcp_traffic():
    packets = rdpcap(str(FIXTURE))
    assert len(packets) > 20
    assert any(TCP in p for p in packets)


def test_fixture_has_no_real_private_addresses():
    packets = rdpcap(str(FIXTURE))
    for p in packets:
        if IP in p:
            for ip in (p[IP].src, p[IP].dst):
                addr = ip_address(ip)
                if addr.is_private and not addr.is_multicast:
                    assert ip.startswith("10.0.0."), f"unscrubbed address: {ip}"
