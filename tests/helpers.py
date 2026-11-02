"""Helpers that build raw frames and pcap bytes for tests."""

import socket
import struct

SRC_MAC = bytes.fromhex("020000000001")
DST_MAC = bytes.fromhex("020000000002")


def build_ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return DST_MAC + SRC_MAC + struct.pack("!H", ethertype) + payload


def build_ipv4(
    payload: bytes,
    proto: int,
    src: str = "10.0.0.1",
    dst: str = "93.184.216.34",
    ttl: int = 64,
    total_len: int | None = None,
    flags_frag: int = 0x4000,  # Don't Fragment, offset 0
    ihl_words: int = 5,
    version: int = 4,
) -> bytes:
    options = b"\x00" * max(0, (ihl_words - 5) * 4)
    if total_len is None:
        total_len = 20 + len(options) + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (version << 4) | ihl_words,
        0,
        total_len,
        0,
        flags_frag,
        ttl,
        proto,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return header + options + payload


def build_tcp(
    sport: int,
    dport: int,
    seq: int = 0,
    ack: int = 0,
    flags: int = 0x02,
    window: int = 64240,
    payload: bytes = b"",
    data_offset_words: int = 5,
) -> bytes:
    options = b"\x00" * max(0, (data_offset_words - 5) * 4)
    header = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, ack, data_offset_words << 4, flags, window, 0, 0
    )
    return header + options + payload


def build_udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def build_icmp_echo(payload: bytes = b"") -> bytes:
    return struct.pack("!BBHHH", 8, 0, 0, 1, 1) + payload


def build_pcap(
    records: list[tuple[int, int, bytes]],
    *,
    big_endian: bool = False,
    nano: bool = False,
    linktype: int = 1,
) -> bytes:
    """Build classic pcap bytes from (seconds, fraction, frame) records."""
    order = ">" if big_endian else "<"
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack(f"{order}IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for seconds, fraction, frame in records:
        out += struct.pack(f"{order}IIII", seconds, fraction, len(frame), len(frame))
        out += frame
    return out
