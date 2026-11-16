from __future__ import annotations

from collections import Counter

import pytest

from flowsentinel.features.window import (
    HostWindowManager,
    compute_shannon_entropy,
)
from flowsentinel.parser.packet import PROTO_TCP, Packet, TcpFlags


def _make_pkt(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "93.184.216.34",
    src_port: int | None = 51000,
    dst_port: int | None = 80,
    proto: int = PROTO_TCP,
    ts: float = 0.0,
    flags: int = 0x02,
) -> Packet:
    return Packet(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=proto,
        ttl=64,
        ip_length=40,
        payload_len=0,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=TcpFlags(flags) if proto == PROTO_TCP else None,
        window=64240,
    )
def test_shannon_entropy_appendix_a2_numerical_examples():
    # 1. Normal host: 90 connections to 443, 10 to 53 -> ~0.47 bits
    normal_counts = Counter({443: 90, 53: 10})
    normal_entropy = compute_shannon_entropy(normal_counts)
    assert pytest.approx(normal_entropy, abs=0.01) == 0.47

    # 2. Scanner: 100 connections, each to a different port -> ~6.64 bits
    scanner_counts = Counter({p: 1 for p in range(1, 101)})
    scanner_entropy = compute_shannon_entropy(scanner_counts)
    assert pytest.approx(scanner_entropy, abs=0.01) == 6.64

    # 3. Smaller scan: 50 connections, each to a different port -> ~5.64 bits
    small_scan_counts = Counter({p: 1 for p in range(1, 51)})
    small_scan_entropy = compute_shannon_entropy(small_scan_counts)
    assert pytest.approx(small_scan_entropy, abs=0.01) == 5.64

    # 4. Single port or empty -> 0.0 bits
    assert compute_shannon_entropy(Counter({80: 100})) == 0.0
    assert compute_shannon_entropy(Counter()) == 0.0


def test_host_window_sliding_expiry():
    """FR-FEA-07: Discard events older than the 10s sliding window."""
    manager = HostWindowManager(window_s=10.0)

    # Packet at t=0.0
    manager.update_from_packet(_make_pkt(src_ip="10.0.0.5", dst_port=80, ts=0.0))
    feats_t0 = manager.get_features("10.0.0.5")
    assert feats_t0.h_unique_dst_ports == 1

    # Packet at t=5.0 to port 443
    manager.update_from_packet(_make_pkt(src_ip="10.0.0.5", dst_port=443, ts=5.0))
    feats_t5 = manager.get_features("10.0.0.5")
    assert feats_t5.h_unique_dst_ports == 2

    # Packet at t=12.0 (t=0.0 has expired because 12.0 - 10.0 = 2.0 > 0.0)
    manager.update_from_packet(_make_pkt(src_ip="10.0.0.5", dst_port=8080, ts=12.0))
    feats_t12 = manager.get_features("10.0.0.5")
    # Ports in window are now 443 (t=5.0) and 8080 (t=12.0)
    assert feats_t12.h_unique_dst_ports == 2


def test_host_window_features_metrics():
    """FR-FEA-03: Compute unique dst hosts/ports, SYN ratio, and connection rate."""
    manager = HostWindowManager(window_s=10.0)

    # 3 SYN packets to 3 distinct destination IPs on different ports
    p1 = _make_pkt(src_ip="10.0.0.2", dst_ip="192.168.1.1", dst_port=22, flags=0x02, ts=1.0)
    p2 = _make_pkt(src_ip="10.0.0.2", dst_ip="192.168.1.2", dst_port=80, flags=0x02, ts=2.0)
    p3 = _make_pkt(src_ip="10.0.0.2", dst_ip="192.168.1.3", dst_port=443, flags=0x02, ts=3.0)

    # 1 ACK packet (no SYN)
    p4 = _make_pkt(src_ip="10.0.0.2", dst_ip="192.168.1.1", dst_port=22, flags=0x10, ts=4.0)

    for p in (p1, p2, p3, p4):
        manager.update_from_packet(p)

    feats = manager.get_features("10.0.0.2")
    assert feats.h_unique_dst_hosts == 3
    assert feats.h_unique_dst_ports == 3
    # 3 new connections (SYNs) in 10s window -> rate = 0.3 conn/s
    assert pytest.approx(feats.h_new_conn_rate) == 0.3
    # 3 SYN-only packets out of 4 total TCP packets -> 0.75
    assert pytest.approx(feats.h_syn_only_ratio) == 0.75
    assert feats.h_port_entropy_bits > 0.0


def test_host_window_failed_connection_ratio():
    """FR-FEA-03: Compute failed connection ratio."""
    manager = HostWindowManager(window_s=10.0)

    manager.record_connection_result("10.0.0.3", "192.168.1.1", 22, timestamp=1.0, failed=True)
    manager.record_connection_result("10.0.0.3", "192.168.1.1", 22, timestamp=2.0, failed=False)

    feats = manager.get_features("10.0.0.3")
    # 1 failed out of 2 total connections -> 0.5
    assert pytest.approx(feats.h_failed_ratio) == 0.5


def test_host_window_manager_lru_bounding():
    """FR-FEA-07: Bounded host table evicts LRU host when capacity is reached."""
    manager = HostWindowManager(window_s=10.0, max_hosts=2)

    manager.update_from_packet(_make_pkt(src_ip="10.0.0.1", ts=1.0))
    manager.update_from_packet(_make_pkt(src_ip="10.0.0.2", ts=2.0))
    assert manager.host_count == 2

    # Accessing 10.0.0.1 makes it MRU
    manager.get_features("10.0.0.1")

    # Adding a 3rd host evicts the LRU host (10.0.0.2)
    manager.update_from_packet(_make_pkt(src_ip="10.0.0.3", ts=3.0))
    assert manager.host_count == 2

    # 10.0.0.2 was evicted, returns default 0 features
    evicted_feats = manager.get_features("10.0.0.2")
    assert evicted_feats.h_unique_dst_ports == 0
    assert evicted_feats.h_unique_dst_hosts == 0

    # 10.0.0.1 was retained
    retained_feats = manager.get_features("10.0.0.1")
    assert retained_feats.h_unique_dst_ports == 1