"""Bounded flow table with bidirectional tracking, timeouts, and LRU eviction.

Reference: FlowSentinel SRS v1.0 Section 5.3 (FR-FLW-01..09) & Appendix A.9.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterator
from typing import TYPE_CHECKING

from flowsentinel.flows.key import make_flow_key
from flowsentinel.flows.record import EndReason, FlowRecord
from flowsentinel.parser.packet import TcpFlags

if TYPE_CHECKING:
    from flowsentinel.flows.key import FlowKey
    from flowsentinel.parser.packet import Packet


class FlowTable:
    """Maintains active network conversations with bounded memory and timeout eviction."""

    def __init__(
        self,
        idle_timeout_s: float = 60.0,
        active_timeout_s: float = 120.0,
        max_active_flows: int = 100_000,
    ) -> None:
        if idle_timeout_s <= 0:
            raise ValueError(f"idle_timeout_s must be positive, got {idle_timeout_s}")
        if active_timeout_s <= 0:
            raise ValueError(f"active_timeout_s must be positive, got {active_timeout_s}")
        if max_active_flows < 1:
            raise ValueError(f"max_active_flows must be >= 1, got {max_active_flows}")

        self.idle_timeout_s = float(idle_timeout_s)
        self.active_timeout_s = float(active_timeout_s)
        self.max_active_flows = int(max_active_flows)

        self._active_flows: OrderedDict[FlowKey, FlowRecord] = OrderedDict()
        self._clock: float = 0.0

        # Telemetry counters (FR-MON-01, FR-FLW-06, FR-FLW-08)
        self.packets_processed: int = 0
        self.out_of_order_count: int = 0
        self.evictions_count: int = 0
        self.flows_completed: int = 0

    @property
    def active_count(self) -> int:
        """Current number of open flows in the table."""
        return len(self._active_flows)

    @property
    def current_clock(self) -> float:
        """Monotonic timestamp tracking latest packet time seen."""
        return self._clock

    def process_packet(self, packet: Packet) -> list[FlowRecord]:
        """Ingest one packet, update flow state, and return any flows completed by this packet."""
        self.packets_processed += 1
        emitted: list[FlowRecord] = []

        # Monotonic clock defense (FR-FLW-08)
        if self.packets_processed > 1 and packet.timestamp < self._clock:
            self.out_of_order_count += 1
        else:
            self._clock = max(self._clock, packet.timestamp)

        key = make_flow_key(packet)

        # Periodic check for idle timeouts from the front of the LRU table
        emitted.extend(self._sweep_idle_flows(self._clock))

        if key in self._active_flows:
            flow = self._active_flows[key]

            # Check if existing flow timed out before this packet arrived (FR-FLW-03)
            is_idle = (packet.timestamp - flow.end_ts) > self.idle_timeout_s
            is_active = (packet.timestamp - flow.start_ts) >= self.active_timeout_s

            if is_idle or is_active:
                flow.end_reason = EndReason.IDLE if is_idle else EndReason.ACTIVE
                del self._active_flows[key]
                self.flows_completed += 1
                emitted.append(flow)

                # Start a fresh flow with this packet
                new_flow = self._create_flow(key, packet)
                if new_flow.end_reason is not None:
                    emitted.append(new_flow)
                else:
                    self._insert_flow(key, new_flow, emitted)
            else:
                # Add packet to existing active flow
                flow.add_packet(packet)
                self._active_flows.move_to_end(key)

                # Check TCP termination (FR-FLW-04)
                if packet.is_tcp:
                    if TcpFlags.RST in packet.tcp_flags:
                        flow.end_reason = EndReason.RST
                        del self._active_flows[key]
                        self.flows_completed += 1
                        emitted.append(flow)
                    elif flow.fin_fwd and flow.fin_bwd:
                        flow.end_reason = EndReason.FIN
                        del self._active_flows[key]
                        self.flows_completed += 1
                        emitted.append(flow)
        else:
            # Create a brand new flow
            new_flow = self._create_flow(key, packet)
            if new_flow.end_reason is not None:
                emitted.append(new_flow)
            else:
                self._insert_flow(key, new_flow, emitted)

        return emitted

    def _create_flow(self, key: FlowKey, packet: Packet) -> FlowRecord:
        """Instantiate a new FlowRecord and record its initiator."""
        src_port = packet.src_port or 0
        initiator = (packet.src_ip, src_port)
        flow = FlowRecord(
            key=key,
            initiator=initiator,
            start_ts=packet.timestamp,
            end_ts=packet.timestamp,
        )
        flow.add_packet(packet)

        # Single-packet RST immediate close
        if packet.is_tcp and (TcpFlags.RST in packet.tcp_flags):
            flow.end_reason = EndReason.RST
            self.flows_completed += 1

        return flow

    def _insert_flow(self, key: FlowKey, flow: FlowRecord, emitted: list[FlowRecord]) -> None:
        """Insert flow into active table, enforcing bounded capacity LRU eviction (FR-FLW-06)."""
        if len(self._active_flows) >= self.max_active_flows:
            # Evict least recently active flow (first in OrderedDict)
            _evicted_key, evicted_flow = self._active_flows.popitem(last=False)
            evicted_flow.end_reason = EndReason.EVICTED
            self.evictions_count += 1
            self.flows_completed += 1
            emitted.append(evicted_flow)

        self._active_flows[key] = flow

    def _sweep_idle_flows(self, current_ts: float) -> list[FlowRecord]:
        """Sweep expired idle flows from front of LRU table (O(1) amortized)."""
        expired: list[FlowRecord] = []
        for key, flow in list(self._active_flows.items()):
            if (current_ts - flow.end_ts) > self.idle_timeout_s:
                flow.end_reason = EndReason.IDLE
                del self._active_flows[key]
                self.flows_completed += 1
                expired.append(flow)
            else:
                # Since items are ordered by most recently updated at the back,
                # encountering a non-idle flow means subsequent flows are also not idle.
                break
        return expired

    def flush(self) -> Iterator[FlowRecord]:
        """Flush and return all remaining open flows at end of stream (FR-FLW-05)."""
        while self._active_flows:
            _key, flow = self._active_flows.popitem(last=False)
            flow.end_reason = EndReason.EOF
            self.flows_completed += 1
            yield flow
