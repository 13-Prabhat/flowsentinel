"""Parse raw Ethernet frames into Packet objects (IPv4 only)."""

from __future__ import annotations

import socket
import struct

from flowsentinel.parser.packet import (
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
    Packet,
    TcpFlags,
)

ETH_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = 0x8100
IPV4_MIN_HEADER_LEN = 20
TCP_MIN_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8

_ETH = struct.Struct("!6s6sH")
_IPV4 = struct.Struct("!BBHHHBBH4s4s")
_TCP = struct.Struct("!HHIIBBHHH")
_UDP = struct.Struct("!HHHH")


class ParseError(ValueError):
    """Raised when a frame is truncated or structurally invalid."""


def parse_frame(frame: bytes, timestamp: float = 0.0) -> Packet | None:
    """Parse an Ethernet frame.

    Returns None for anything that is not IPv4 (ARP, IPv6, ...).
    Raises ParseError when the frame claims to be IPv4 but is malformed.
    """
    if len(frame) < ETH_HEADER_LEN:
        raise ParseError("frame shorter than Ethernet header")
    ethertype = _ETH.unpack_from(frame)[2]
    offset = ETH_HEADER_LEN
    if ethertype == ETHERTYPE_VLAN:  # skip one 802.1Q tag
        if len(frame) < offset + 4:
            raise ParseError("truncated VLAN tag")
        ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if ethertype != ETHERTYPE_IPV4:
        return None
    return parse_ipv4(frame[offset:], timestamp)


def parse_ipv4(data: bytes, timestamp: float = 0.0) -> Packet:
    """Parse an IPv4 packet (starting at the IP header) and its TCP/UDP/ICMP header."""
    if len(data) < IPV4_MIN_HEADER_LEN:
        raise ParseError("truncated IPv4 header")
    ver_ihl, _tos, total_len, _ident, flags_frag, ttl, proto, _csum, src, dst = _IPV4.unpack_from(
        data
    )
    version = ver_ihl >> 4
    header_len = (ver_ihl & 0x0F) * 4
    if version != 4:
        raise ParseError(f"not IPv4: version field is {version}")
    if header_len < IPV4_MIN_HEADER_LEN or len(data) < header_len:
        raise ParseError(f"invalid IPv4 header length {header_len}")
    if total_len == 0:  # TCP segmentation offload on the capturing host
        total_len = len(data)
    if total_len < header_len:
        raise ParseError("IPv4 total length smaller than header length")

    # Ethernet pads short frames: trust total_len, not the bytes on the wire.
    l4 = data[header_len : min(total_len, len(data))]
    l4_declared = total_len - header_len
    fragment_offset = flags_frag & 0x1FFF

    src_port = dst_port = seq = ack = window = None
    tcp_flags = TcpFlags(0)
    payload_len = l4_declared

    if fragment_offset == 0:  # non-first fragments carry no L4 header
        if proto == PROTO_TCP:
            if len(l4) < TCP_MIN_HEADER_LEN:
                raise ParseError("truncated TCP header")
            src_port, dst_port, seq, ack, off_res, flags, window, _c, _u = _TCP.unpack_from(l4)
            tcp_header_len = (off_res >> 4) * 4
            if tcp_header_len < TCP_MIN_HEADER_LEN or tcp_header_len > len(l4):
                raise ParseError(f"invalid TCP data offset {tcp_header_len}")
            tcp_flags = TcpFlags(flags)
            payload_len = l4_declared - tcp_header_len
        elif proto == PROTO_UDP:
            if len(l4) < UDP_HEADER_LEN:
                raise ParseError("truncated UDP header")
            src_port, dst_port, _length, _c = _UDP.unpack_from(l4)
            payload_len = l4_declared - UDP_HEADER_LEN
        elif proto == PROTO_ICMP:
            if len(l4) < ICMP_HEADER_LEN:
                raise ParseError("truncated ICMP header")
            payload_len = l4_declared - ICMP_HEADER_LEN

    return Packet(
        timestamp=timestamp,
        src_ip=socket.inet_ntoa(src),
        dst_ip=socket.inet_ntoa(dst),
        protocol=proto,
        ttl=ttl,
        ip_length=total_len,
        payload_len=payload_len,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        seq=seq,
        ack=ack,
        window=window,
    )
