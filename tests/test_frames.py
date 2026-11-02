import pytest

from flowsentinel.parser.frames import ParseError, parse_frame
from flowsentinel.parser.packet import PROTO_ICMP, PROTO_TCP, PROTO_UDP, TcpFlags

from .helpers import (
    build_ethernet,
    build_icmp_echo,
    build_ipv4,
    build_tcp,
    build_udp,
)


def tcp_frame(payload: bytes = b"", **tcp_args) -> bytes:
    segment = build_tcp(51000, 80, payload=payload, **tcp_args)
    return build_ethernet(build_ipv4(segment, PROTO_TCP))


def test_tcp_syn_fields():
    # IPv4 header 20 B + TCP header 20 B, no payload -> ip_length 40, payload 0
    packet = parse_frame(tcp_frame(seq=1000, flags=0x02), timestamp=12.5)
    assert packet is not None
    assert packet.timestamp == 12.5
    assert (packet.src_ip, packet.dst_ip) == ("10.0.0.1", "93.184.216.34")
    assert packet.protocol == PROTO_TCP and packet.is_tcp
    assert (packet.src_port, packet.dst_port) == (51000, 80)
    assert (packet.seq, packet.ack, packet.window) == (1000, 0, 64240)
    assert packet.tcp_flags == TcpFlags.SYN
    assert (packet.ttl, packet.ip_length, packet.payload_len) == (64, 40, 0)


def test_tcp_payload_length():
    payload = b"GET / HTTP/1.1\r\n\r\n"  # 14 + 4 = 18 bytes
    packet = parse_frame(tcp_frame(payload=payload, flags=0x18))
    assert packet.payload_len == 18
    assert packet.ip_length == 20 + 20 + 18
    assert packet.tcp_flags == TcpFlags.PSH | TcpFlags.ACK


def test_ethernet_padding_is_not_counted_as_payload():
    # A bare ACK is 14 + 20 + 20 = 54 bytes; Ethernet pads it to 60 with 6 zero bytes.
    frame = tcp_frame(flags=0x10) + b"\x00" * 6
    packet = parse_frame(frame)
    assert packet.payload_len == 0
    assert packet.ip_length == 40


def test_tcp_options_are_skipped():
    # data offset 8 words = 32-byte TCP header (12 option bytes) + 5 payload bytes
    packet = parse_frame(tcp_frame(payload=b"hello", data_offset_words=8))
    assert packet.ip_length == 20 + 32 + 5
    assert packet.payload_len == 5


def test_udp_fields():
    payload = b"x" * 29
    ip = build_ipv4(build_udp(53000, 53, payload), PROTO_UDP)
    packet = parse_frame(build_ethernet(ip))
    assert packet.is_udp
    assert (packet.src_port, packet.dst_port) == (53000, 53)
    assert packet.payload_len == 29
    assert packet.tcp_flags == TcpFlags(0)


def test_icmp_echo():
    ip = build_ipv4(build_icmp_echo(b"p" * 32), PROTO_ICMP)
    packet = parse_frame(build_ethernet(ip))
    assert packet.is_icmp
    assert packet.src_port is None
    assert packet.payload_len == 32


def test_unknown_protocol_keeps_ip_payload_length():
    ip = build_ipv4(b"z" * 40, 47)  # GRE
    packet = parse_frame(build_ethernet(ip))
    assert packet.protocol == 47
    assert packet.payload_len == 40
    assert packet.src_port is None


def test_vlan_tagged_frame():
    ip = build_ipv4(build_tcp(51000, 80), PROTO_TCP)
    tagged = build_ethernet(b"\x00\x64\x08\x00" + ip, ethertype=0x8100)
    packet = parse_frame(tagged)
    assert packet is not None
    assert packet.dst_port == 80


@pytest.mark.parametrize("ethertype", [0x0806, 0x86DD])  # ARP, IPv6
def test_non_ipv4_returns_none(ethertype):
    assert parse_frame(build_ethernet(b"\x00" * 28, ethertype=ethertype)) is None


def test_non_first_fragment_has_no_ports():
    ip = build_ipv4(b"\xab" * 30, PROTO_TCP, flags_frag=0x0010)  # fragment offset 16
    packet = parse_frame(build_ethernet(ip))
    assert packet.src_port is None
    assert packet.payload_len == 30


def test_zero_total_length_uses_captured_length():
    # Hosts using TCP segmentation offload record total length 0.
    segment = build_tcp(51000, 80, payload=b"d" * 100)
    ip = build_ipv4(segment, PROTO_TCP, total_len=0)
    packet = parse_frame(build_ethernet(ip))
    assert packet.ip_length == 140
    assert packet.payload_len == 100


def test_ip_header_options_are_skipped():
    segment = build_tcp(51000, 80, payload=b"abc")
    ip = build_ipv4(segment, PROTO_TCP, ihl_words=6)  # 24-byte IP header
    packet = parse_frame(build_ethernet(ip))
    assert packet.ip_length == 24 + 20 + 3
    assert packet.payload_len == 3


def test_header_bytes_match_hand_decoding():
    # IPv4: 45 = version 4 / IHL 5, 0028 = length 40, 4000 = DF flag, 40 = TTL 64, 06 = TCP,
    #       0a000001 = 10.0.0.1, 5db8d822 = 93.184.216.34
    # TCP:  c738 = port 51000, 0050 = port 80, 000003e8 = seq 1000, 5002 = offset 5 + SYN,
    #       faf0 = window 64240
    ip = build_ipv4(build_tcp(51000, 80, seq=1000), PROTO_TCP)
    assert ip[:20].hex() == "4500002800004000400600000a0000015db8d822"
    assert ip[20:].hex() == "c7380050000003e8000000005002faf000000000"


@pytest.mark.parametrize(
    "frame",
    [
        b"\x00" * 10,  # shorter than Ethernet header
        build_ethernet(b"\x45\x00\x00"),  # truncated IPv4 header
        build_ethernet(build_ipv4(b"\x00" * 20, PROTO_TCP, version=6)),  # wrong version
        build_ethernet(build_ipv4(b"\x00" * 20, PROTO_TCP, ihl_words=4)),  # IHL below minimum
        build_ethernet(build_ipv4(b"\x00" * 10, PROTO_TCP)),  # truncated TCP header
        build_ethernet(build_ipv4(build_tcp(1, 2, data_offset_words=3), PROTO_TCP)),  # bad offset
        build_ethernet(build_ipv4(b"\x00" * 4, PROTO_UDP)),  # truncated UDP header
        build_ethernet(build_ipv4(b"\x00" * 4, PROTO_ICMP)),  # truncated ICMP header
        build_ethernet(build_ipv4(b"", PROTO_TCP, total_len=10)),  # total length < header
    ],
)
def test_malformed_frames_raise_parse_error(frame):
    with pytest.raises(ParseError):
        parse_frame(frame)
