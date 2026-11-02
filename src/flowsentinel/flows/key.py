"""Canonical 5-tuple key definition and comparison for bidirectional flows.

Reference: FlowSentinel SRS v1.0 Section 7.2 & Appendix A.9.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flowsentinel.parser.packet import Packet

Endpoint = tuple[str, int]


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Canonical 5-tuple key where endpoints are deterministically ordered."""

    protocol: int
    endpoint_a: Endpoint
    endpoint_b: Endpoint

    def to_tuple(self) -> tuple[int, Endpoint, Endpoint]:
        return (self.protocol, self.endpoint_a, self.endpoint_b)

    def __repr__(self) -> str:
        proto_str = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(self.protocol, str(self.protocol))
        return (
            f"FlowKey({proto_str}, {self.endpoint_a[0]}:{self.endpoint_a[1]} <-> "
            f"{self.endpoint_b[0]}:{self.endpoint_b[1]})"
        )


def _ip_to_int(ip: str) -> int:
    """Convert dotted-decimal IPv4 string to integer for numerical ordering."""
    return int(ipaddress.IPv4Address(ip))


def make_flow_key(packet: Packet) -> FlowKey:
    """Generate the canonical 5-tuple FlowKey from an IPv4 Packet.

    Endpoints are ordered by numeric IPv4 address first, then port number.
    Packets in both directions map to the exact same FlowKey (FR-FLW-01).
    """
    src_port = packet.src_port or 0
    dst_port = packet.dst_port or 0

    src_int = _ip_to_int(packet.src_ip)
    dst_int = _ip_to_int(packet.dst_ip)

    ep_src: Endpoint = (packet.src_ip, src_port)
    ep_dst: Endpoint = (packet.dst_ip, dst_port)

    if (src_int, src_port) <= (dst_int, dst_port):
        return FlowKey(packet.protocol, ep_src, ep_dst)
    return FlowKey(packet.protocol, ep_dst, ep_src)
