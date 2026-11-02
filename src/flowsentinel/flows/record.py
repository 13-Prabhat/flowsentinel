"""FlowRecord and EndReason definitions for bidirectional conversations.

Reference: FlowSentinel SRS v1.0 Section 7.2 & Appendix A.9.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from flowsentinel.flows.key import Endpoint, FlowKey
from flowsentinel.flows.stats import RunningStats
from flowsentinel.parser.packet import TcpFlags

if TYPE_CHECKING:
    from flowsentinel.parser.packet import Packet


class EndReason(str, Enum):
    """Reason a flow was closed and emitted."""

    FIN = "fin"
    RST = "rst"
    IDLE = "idle"
    ACTIVE = "active"
    EVICTED = "evicted"
    EOF = "eof"


@dataclass
class FlowRecord:
    """Internal mutable tracking state and final emitted record for a bidirectional flow."""

    key: FlowKey
    initiator: Endpoint
    start_ts: float
    end_ts: float
    flow_id: str = ""
    end_reason: EndReason | None = None

    # Packet & byte volume counters
    pkts_fwd: int = 0
    pkts_bwd: int = 0
    bytes_fwd: int = 0
    bytes_bwd: int = 0
    payload_pkts: int = 0

    # TCP flag counters
    f_syn: int = 0
    f_fin: int = 0
    f_rst: int = 0
    f_psh: int = 0
    f_ack: int = 0
    f_urg: int = 0

    # Initial TCP window seen per direction
    win_fwd: int = 0
    win_bwd: int = 0
    _win_fwd_set: bool = False
    _win_bwd_set: bool = False

    # TCP teardown state
    fin_fwd: bool = False
    fin_bwd: bool = False

    # Running statistics for sizes and inter-arrival times
    size_stats: RunningStats = field(default_factory=RunningStats)
    iat_stats: RunningStats = field(default_factory=RunningStats)
    _last_pkt_ts: float = 0.0

    def __post_init__(self) -> None:
        if not self.flow_id:
            self.flow_id = self._generate_flow_id(self.key, self.start_ts)
        self._last_pkt_ts = self.start_ts

    @staticmethod
    def _generate_flow_id(key: FlowKey, start_ts: float) -> str:
        """Derive deterministic flow identifier from key and start time (FR-FLW-07)."""
        raw = (
            f"{key.protocol}:"
            f"{key.endpoint_a[0]}:{key.endpoint_a[1]}:"
            f"{key.endpoint_b[0]}:{key.endpoint_b[1]}:"
            f"{start_ts:.6f}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @property
    def total_packets(self) -> int:
        return self.pkts_fwd + self.pkts_bwd

    @property
    def total_bytes(self) -> int:
        return self.bytes_fwd + self.bytes_bwd

    @property
    def duration_s(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)

    def is_forward(self, packet: Packet) -> bool:
        """Check if packet source matches flow initiator (FR-FLW-02)."""
        src_port = packet.src_port or 0
        return (packet.src_ip, src_port) == self.initiator

    def add_packet(self, packet: Packet) -> None:
        """Update flow state with an incoming packet."""
        fwd = self.is_forward(packet)

        # Update timestamps and IAT
        if self.total_packets > 0:
            iat = max(0.0, packet.timestamp - self._last_pkt_ts)
            self.iat_stats.update(iat)
        self.end_ts = max(self.end_ts, packet.timestamp)
        self._last_pkt_ts = packet.timestamp

        # Update packet size statistics
        self.size_stats.update(packet.ip_length)

        # Update directional volume
        if fwd:
            self.pkts_fwd += 1
            self.bytes_fwd += packet.ip_length
        else:
            self.pkts_bwd += 1
            self.bytes_bwd += packet.ip_length

        if packet.payload_len > 0:
            self.payload_pkts += 1

        # Protocol-specific TCP tracking
        if packet.is_tcp:
            flags = packet.tcp_flags
            if TcpFlags.SYN in flags:
                self.f_syn += 1
            if TcpFlags.FIN in flags:
                self.f_fin += 1
                if fwd:
                    self.fin_fwd = True
                else:
                    self.fin_bwd = True
            if TcpFlags.RST in flags:
                self.f_rst += 1
            if TcpFlags.PSH in flags:
                self.f_psh += 1
            if TcpFlags.ACK in flags:
                self.f_ack += 1
            if TcpFlags.URG in flags:
                self.f_urg += 1

            if packet.window is not None:
                if fwd and not self._win_fwd_set:
                    self.win_fwd = packet.window
                    self._win_fwd_set = True
                elif not fwd and not self._win_bwd_set:
                    self.win_bwd = packet.window
                    self._win_bwd_set = True
