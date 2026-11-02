"""Core data types for parsed network packets."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntFlag

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17


class TcpFlags(IntFlag):
    """TCP control bits, in the order they appear in the header byte."""

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


def format_flags(flags: TcpFlags) -> str:
    """Return flag names joined by '|', e.g. 'SYN|ACK'; 'NONE' when no bit is set."""
    names = [member.name for member in TcpFlags if member in flags and member.name]
    return "|".join(names) or "NONE"


@dataclass(frozen=True, slots=True)
class Packet:
    """One IPv4 packet reduced to the fields detection logic needs.

    Ports, flags, seq, ack and window are only meaningful for TCP/UDP;
    they stay None (or empty) for other protocols and for non-first fragments.
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: int
    ttl: int
    ip_length: int
    payload_len: int
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: TcpFlags = TcpFlags(0)
    seq: int | None = None
    ack: int | None = None
    window: int | None = None

    @property
    def is_tcp(self) -> bool:
        return self.protocol == PROTO_TCP

    @property
    def is_udp(self) -> bool:
        return self.protocol == PROTO_UDP

    @property
    def is_icmp(self) -> bool:
        return self.protocol == PROTO_ICMP
