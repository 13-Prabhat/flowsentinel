import dataclasses

import pytest

from flowsentinel.parser.packet import (
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
    Packet,
    TcpFlags,
    format_flags,
)

def make_packet(**overrides) -> Packet:
    fields = {
        "timestamp": 1.5,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": PROTO_TCP,
        "ttl": 64,
        "ip_length": 40,
        "payload_len": 0,
    }
    fields.update(overrides)
    return Packet(**fields)

def test_syn_ack_is_0x12():
    # 0x12 = 0001 0010 -> ACK (0x10) + SYN (0x02)
    assert int(TcpFlags.SYN | TcpFlags.ACK) == 0x12
    assert TcpFlags(0x12) == TcpFlags.SYN | TcpFlags.ACK

def test_format_flags():
    assert format_flags(TcpFlags.SYN | TcpFlags.ACK) == "SYN|ACK"
    assert format_flags(TcpFlags.FIN | TcpFlags.PSH | TcpFlags.ACK) == "FIN|PSH|ACK"
    assert format_flags(TcpFlags(0)) == "NONE"

def test_protocol_helpers():
    assert make_packet(protocol=PROTO_TCP).is_tcp
    assert make_packet(protocol=PROTO_UDP).is_udp
    assert make_packet(protocol=PROTO_ICMP).is_icmp
    assert not make_packet(protocol=PROTO_UDP).is_tcp

def test_defaults_for_non_tcp_fields():
    packet = make_packet(protocol=PROTO_ICMP)
    assert packet.src_port is None
    assert packet.tcp_flags == TcpFlags(0)
    assert packet.seq is None

def test_packet_is_immutable():
    packet = make_packet()
    with pytest.raises(dataclasses.FrozenInstanceError):
        packet.ttl = 1  # type: ignore[misc]
