"""Comprehensive tests for bidirectional flow assembly, timeouts, and table bounds.

Verifies: FR-FLW-01, FR-FLW-02, FR-FLW-03, FR-FLW-04, FR-FLW-05,
          FR-FLW-06, FR-FLW-07, FR-FLW-08, FR-FLW-09, Appendix A.9.
"""

import pytest

from flowsentinel.flows.key import FlowKey, make_flow_key
from flowsentinel.flows.record import EndReason, FlowRecord
from flowsentinel.flows.table import FlowTable
from flowsentinel.parser.packet import PROTO_ICMP, PROTO_TCP, PROTO_UDP, Packet, TcpFlags


def _make_pkt(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "93.184.216.34",
    src_port: int | None = 51000,
    dst_port: int | None = 80,
    proto: int = PROTO_TCP,
    ts: float = 0.0,
    flags: int = 0x02,
    length: int = 40,
    payload_len: int = 0,
    window: int | None = 64240,
) -> Packet:
    return Packet(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=proto,
        ttl=64,
        ip_length=length,
        payload_len=payload_len,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=TcpFlags(flags),
        window=window,
    )


def test_canonical_key_ordering_matches_appendix_a9():
    """FR-FLW-01: Endpoints are ordered by numeric address then port; both directions match."""
    p_fwd = _make_pkt(src_ip="10.0.0.1", dst_ip="93.184.216.34", src_port=51000, dst_port=80)
    p_bwd = _make_pkt(src_ip="93.184.216.34", dst_ip="10.0.0.1", src_port=80, dst_port=51000)

    key_fwd = make_flow_key(p_fwd)
    key_bwd = make_flow_key(p_bwd)

    assert key_fwd == key_bwd
    assert key_fwd == FlowKey(
        protocol=PROTO_TCP,
        endpoint_a=("10.0.0.1", 51000),
        endpoint_b=("93.184.216.34", 80),
    )


def test_flow_initiator_and_directional_counters():
    """FR-FLW-02: Flow records initiator and labels packets forward/backward."""
    table = FlowTable()

    # Packet 1 (fwd from client): SYN
    emitted = table.process_packet(
        _make_pkt(src_ip="10.0.0.1", dst_ip="93.184.216.34", src_port=51000, dst_port=80, ts=1.0)
    )
    assert not emitted
    assert table.active_count == 1

    # Packet 2 (bwd from server): SYN-ACK
    emitted = table.process_packet(
        _make_pkt(
            src_ip="93.184.216.34",
            dst_ip="10.0.0.1",
            src_port=80,
            dst_port=51000,
            ts=1.05,
            flags=0x12,
            window=65535,
        )
    )
    assert not emitted

    # Packet 3 (fwd from client with payload)
    table.process_packet(
        _make_pkt(
            src_ip="10.0.0.1",
            dst_ip="93.184.216.34",
            src_port=51000,
            dst_port=80,
            ts=1.1,
            flags=0x18,
            length=150,
            payload_len=110,
        )
    )

    flows = list(table.flush())
    assert len(flows) == 1
    f = flows[0]
    assert f.initiator == ("10.0.0.1", 51000)
    assert f.pkts_fwd == 2
    assert f.pkts_bwd == 1
    assert f.bytes_fwd == 190  # 40 + 150
    assert f.bytes_bwd == 40
    assert f.payload_pkts == 1
    assert f.win_fwd == 64240
    assert f.win_bwd == 65535
    assert f.f_syn == 2
    assert f.f_ack == 2
    assert f.f_psh == 1
    assert f.duration_s == pytest.approx(0.1)
    assert f.end_reason == EndReason.EOF


def test_idle_timeout_matches_appendix_a9():
    """FR-FLW-03: Packets arriving at t=0, 1, 2 and 70 with 60s idle timeout."""
    table = FlowTable(idle_timeout_s=60.0, active_timeout_s=120.0)

    # Arrive at t=0, 1, 2
    table.process_packet(_make_pkt(ts=0.0))
    table.process_packet(_make_pkt(ts=1.0))
    table.process_packet(_make_pkt(ts=2.0))

    # Packet arrives at t=70: gap 70 - 2 = 68 > 60s
    emitted = table.process_packet(_make_pkt(ts=70.0))
    assert len(emitted) == 1
    flow1 = emitted[0]
    assert flow1.end_reason == EndReason.IDLE
    assert flow1.total_packets == 3
    assert flow1.duration_s == 2.0

    # Flow 2 is currently active in table
    assert table.active_count == 1
    flow2 = list(table.flush())[0]
    assert flow2.start_ts == 70.0
    assert flow2.total_packets == 1


def test_active_timeout():
    """FR-FLW-03: Long running flow closed after active_timeout_s."""
    table = FlowTable(idle_timeout_s=60.0, active_timeout_s=120.0)

    table.process_packet(_make_pkt(ts=0.0))
    table.process_packet(_make_pkt(ts=50.0))
    table.process_packet(_make_pkt(ts=100.0))

    # At t=125, active timeout 125 - 0 >= 120s triggers
    emitted = table.process_packet(_make_pkt(ts=125.0))
    assert len(emitted) == 1
    assert emitted[0].end_reason == EndReason.ACTIVE
    assert emitted[0].start_ts == 0.0
    assert emitted[0].total_packets == 3


def test_tcp_teardown_fin_both_directions():
    """FR-FLW-04: Closed when FIN has been seen in both directions."""
    table = FlowTable()

    table.process_packet(
        _make_pkt(src_ip="10.0.0.1", dst_ip="93.184.216.34", src_port=51000, dst_port=80, ts=1.0)
    )
    # Server sends FIN
    table.process_packet(
        _make_pkt(
            src_ip="93.184.216.34",
            dst_ip="10.0.0.1",
            src_port=80,
            dst_port=51000,
            ts=1.1,
            flags=0x11,
        )
    )
    assert table.active_count == 1

    # Client sends FIN: now both directions have seen FIN
    emitted = table.process_packet(
        _make_pkt(
            src_ip="10.0.0.1",
            dst_ip="93.184.216.34",
            src_port=51000,
            dst_port=80,
            ts=1.2,
            flags=0x11,
        )
    )
    assert len(emitted) == 1
    assert emitted[0].end_reason == EndReason.FIN
    assert table.active_count == 0


def test_tcp_teardown_rst():
    """FR-FLW-04: Closed immediately when an RST is seen."""
    table = FlowTable()

    table.process_packet(
        _make_pkt(src_ip="10.0.0.1", dst_ip="93.184.216.34", src_port=51000, dst_port=80, ts=1.0)
    )
    emitted = table.process_packet(
        _make_pkt(
            src_ip="93.184.216.34",
            dst_ip="10.0.0.1",
            src_port=80,
            dst_port=51000,
            ts=1.05,
            flags=0x04,
        )
    )
    assert len(emitted) == 1
    assert emitted[0].end_reason == EndReason.RST
    assert table.active_count == 0


def test_bounded_table_and_lru_eviction():
    """FR-FLW-06: Bounded flow table evicts least recently active flow with reason 'evicted'."""
    table = FlowTable(max_active_flows=2)

    # Flow 1 (port 5001)
    table.process_packet(_make_pkt(src_port=5001, ts=1.0))
    # Flow 2 (port 5002)
    table.process_packet(_make_pkt(src_port=5002, ts=2.0))
    # Update Flow 1 so Flow 2 becomes LRU
    table.process_packet(_make_pkt(src_port=5001, ts=3.0))

    # Flow 3 (port 5003) causes eviction of LRU (Flow 2)
    emitted = table.process_packet(_make_pkt(src_port=5003, ts=4.0))
    assert len(emitted) == 1
    evicted = emitted[0]
    assert evicted.end_reason == EndReason.EVICTED
    assert evicted.key.endpoint_a == ("10.0.0.1", 5002)
    assert table.evictions_count == 1
    assert table.active_count == 2


def test_deterministic_flow_identifier():
    """FR-FLW-07: Deterministic ID derived from key and start time."""
    p1 = _make_pkt(src_ip="10.0.0.1", dst_ip="93.184.216.34", src_port=51000, dst_port=80, ts=10.0)
    key = make_flow_key(p1)

    id1 = FlowRecord._generate_flow_id(key, 10.0)
    id2 = FlowRecord._generate_flow_id(key, 10.0)
    id3 = FlowRecord._generate_flow_id(key, 10.000001)

    assert id1 == id2
    assert id1 != id3
    assert len(id1) == 16


def test_monotonic_clock_and_out_of_order_packets():
    """FR-FLW-08: Clock does not move backwards; out of order packets are counted."""
    table = FlowTable()

    table.process_packet(_make_pkt(ts=10.0))
    assert table.current_clock == 10.0
    assert table.out_of_order_count == 0

    table.process_packet(_make_pkt(ts=9.5))
    # Clock stays at 10.0
    assert table.current_clock == 10.0
    assert table.out_of_order_count == 1

    table.process_packet(_make_pkt(ts=12.0))
    assert table.current_clock == 12.0
    assert table.out_of_order_count == 1


def test_udp_and_icmp_flows_support():
    """FR-FLW-09: UDP and ICMP flows supported using timeouts only."""
    table = FlowTable(idle_timeout_s=30.0)

    # UDP DNS
    table.process_packet(_make_pkt(proto=PROTO_UDP, src_port=53000, dst_port=53, ts=1.0))
    # ICMP Ping
    table.process_packet(_make_pkt(proto=PROTO_ICMP, src_port=None, dst_port=None, flags=0, ts=2.0))

    assert table.active_count == 2
    flows = list(table.flush())
    assert len(flows) == 2
    protos = {f.key.protocol for f in flows}
    assert protos == {PROTO_UDP, PROTO_ICMP}
