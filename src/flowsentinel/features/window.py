from __future__ import annotations

import math
from collections import Counter, OrderedDict, deque
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from flowsentinel.parser.packet import Packet
DEFAULT_WINDOW_S: Final[float] = 10.0
DEFAULT_MAX_HOSTS: Final[int] = 50_000


def compute_shannon_entropy(counts: Counter[int] | dict[int, int]) -> float:
    """Compute Shannon entropy in bits for an empirical distribution (Appendix A.2).

    Formula: H = - sum(p * log2(p)).
    Returns 0.0 if there is 1 or fewer distinct values or total is 0.
    """
    total = sum(counts.values())
    if total <= 0 or len(counts) <= 1:
        return 0.0

    entropy = 0.0
    for count in counts.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)

    return max(0.0, float(entropy))


@dataclass(slots=True)
class HostWindowFeatures:
    """Features extracted over a sliding time window for a single source IP."""

    src_ip: str
    window_s: float
    h_unique_dst_ports: int
    h_unique_dst_hosts: int
    h_new_conn_rate: float
    h_syn_only_ratio: float
    h_failed_ratio: float
    h_port_entropy_bits: float

    def to_dict(self) -> dict[str, Any]:
        """Convert features to dictionary."""
        return asdict(self)


@dataclass(slots=True)
class _HostEvent:
    """Internal event record tracked in the sliding window."""

    timestamp: float
    dst_ip: str
    dst_port: int
    is_tcp: bool
    is_syn_only: bool
    is_new_conn: bool
    is_failed: bool


class HostWindow:
    """Sliding-window buffer for a single source host (FR-FEA-03, FR-FEA-07)."""

    def __init__(self, src_ip: str, window_s: float = DEFAULT_WINDOW_S) -> None:
        self.src_ip = src_ip
        self.window_s = float(window_s)
        self._events: deque[_HostEvent] = deque()
        self._last_ts: float = 0.0

    def add_event(self, event: _HostEvent) -> None:
        """Add an event and prune expired entries older than window_s (FR-FEA-07)."""
        self._events.append(event)
        self._last_ts = max(self._last_ts, event.timestamp)
        self.prune(self._last_ts)

    def prune(self, current_time: float) -> None:
        """Discard events older than current_time - window_s."""
        cutoff = current_time - self.window_s
        while self._events and self._events[0].timestamp < cutoff:
            self._events.popleft()

    @property
    def is_empty(self) -> bool:
        return len(self._events) == 0

    def compute_features(self, current_time: float | None = None) -> HostWindowFeatures:
        """Compute host features over the current sliding window (FR-FEA-03)."""
        ref_time = self._last_ts if current_time is None else current_time
        self.prune(ref_time)

        if not self._events:
            return HostWindowFeatures(
                src_ip=self.src_ip,
                window_s=self.window_s,
                h_unique_dst_ports=0,
                h_unique_dst_hosts=0,
                h_new_conn_rate=0.0,
                h_syn_only_ratio=0.0,
                h_failed_ratio=0.0,
                h_port_entropy_bits=0.0,
            )

        dst_ports: Counter[int] = Counter()
        dst_hosts: set[str] = set()
        total_tcp = 0
        syn_only = 0
        new_conns = 0
        failed_conns = 0

        for ev in self._events:
            dst_hosts.add(ev.dst_ip)
            if ev.dst_port > 0:
                dst_ports[ev.dst_port] += 1
            if ev.is_tcp:
                total_tcp += 1
                if ev.is_syn_only:
                    syn_only += 1
            if ev.is_new_conn:
                new_conns += 1
                if ev.is_failed:
                    failed_conns += 1

        new_conn_rate = new_conns / self.window_s if self.window_s > 0 else 0.0
        syn_only_ratio = syn_only / total_tcp if total_tcp > 0 else 0.0
        failed_ratio = failed_conns / new_conns if new_conns > 0 else 0.0
        entropy = compute_shannon_entropy(dst_ports)

        return HostWindowFeatures(
            src_ip=self.src_ip,
            window_s=self.window_s,
            h_unique_dst_ports=len(dst_ports),
            h_unique_dst_hosts=len(dst_hosts),
            h_new_conn_rate=float(new_conn_rate),
            h_syn_only_ratio=float(syn_only_ratio),
            h_failed_ratio=float(failed_ratio),
            h_port_entropy_bits=round(entropy, 4),
        )


class HostWindowManager:
    """Manages sliding windows across multiple source hosts with LRU bounding (FR-FEA-07)."""

    def __init__(
        self,
        window_s: float = DEFAULT_WINDOW_S,
        max_hosts: int = DEFAULT_MAX_HOSTS,
    ) -> None:
        self.window_s = float(window_s)
        self.max_hosts = int(max_hosts)
        self._hosts: OrderedDict[str, HostWindow] = OrderedDict()
        self._clock: float = 0.0

    @property
    def host_count(self) -> int:
        return len(self._hosts)

    def _get_or_create_host(self, src_ip: str) -> HostWindow:
        if src_ip in self._hosts:
            self._hosts.move_to_end(src_ip)
            return self._hosts[src_ip]

        if len(self._hosts) >= self.max_hosts:
            self._hosts.popitem(last=False)

        window = HostWindow(src_ip, window_s=self.window_s)
        self._hosts[src_ip] = window
        return window

    def update_from_packet(self, packet: Packet) -> HostWindowFeatures:
        """Update window state with an observed packet and return current host features."""
        self._clock = max(self._clock, packet.timestamp)
        window = self._get_or_create_host(packet.src_ip)

        is_tcp = packet.is_tcp
        is_syn_only = False
        is_new_conn = False

        if is_tcp and packet.tcp_flags is not None:
            from flowsentinel.parser.packet import TcpFlags

            is_syn = bool(packet.tcp_flags & TcpFlags.SYN)
            is_ack = bool(packet.tcp_flags & TcpFlags.ACK)
            if is_syn and not is_ack:
                is_syn_only = True
                is_new_conn = True

        event = _HostEvent(
            timestamp=packet.timestamp,
            dst_ip=packet.dst_ip,
            dst_port=packet.dst_port or 0,
            is_tcp=is_tcp,
            is_syn_only=is_syn_only,
            is_new_conn=is_new_conn,
            is_failed=False,
        )
        window.add_event(event)
        return window.compute_features(self._clock)

    def record_connection_result(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: float,
        failed: bool,
    ) -> None:
        """Record completed or failed connection for ratio tracking."""
        self._clock = max(self._clock, timestamp)
        window = self._get_or_create_host(src_ip)
        event = _HostEvent(
            timestamp=timestamp,
            dst_ip=dst_ip,
            dst_port=dst_port,
            is_tcp=True,
            is_syn_only=False,
            is_new_conn=True,
            is_failed=failed,
        )
        window.add_event(event)

    def get_features(self, src_ip: str) -> HostWindowFeatures:
        """Retrieve current features for a given source host."""
        if src_ip not in self._hosts:
            return HostWindowFeatures(
                src_ip=src_ip,
                window_s=self.window_s,
                h_unique_dst_ports=0,
                h_unique_dst_hosts=0,
                h_new_conn_rate=0.0,
                h_syn_only_ratio=0.0,
                h_failed_ratio=0.0,
                h_port_entropy_bits=0.0,
            )
        self._hosts.move_to_end(src_ip)
        return self._hosts[src_ip].compute_features(self._clock)