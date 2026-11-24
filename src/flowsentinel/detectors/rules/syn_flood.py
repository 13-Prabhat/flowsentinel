from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Final

from flowsentinel.detectors.base import Alert, BaseDetector
from flowsentinel.parser.packet import Packet, TcpFlags

DEFAULT_SYN_RATE: Final[float] = 200.0
DEFAULT_MAX_COMPLETION: Final[float] = 0.10
DEFAULT_WINDOW_S: Final[float] = 10.0


@dataclass(slots=True)
class _SynRecord:
    timestamp: float
    src_ip: str
    is_completed: bool


class SynFloodDetector(BaseDetector):
    """Detects SYN-flood denial of service attacks directed at destination hosts (FR-DET-02).

    Fires an alert when SYN-only packets toward a destination exceed syn_rate_per_s (default 200)
    and fewer than max_completion_ratio (default 10%) of attempts complete the handshake.
    """

    def __init__(
        self,
        syn_rate_per_s: float = DEFAULT_SYN_RATE,
        max_completion_ratio: float = DEFAULT_MAX_COMPLETION,
        window_s: float = DEFAULT_WINDOW_S,
        severity: str = "critical",
        enabled: bool = True,
    ) -> None:
        super().__init__(name="syn_flood", enabled=enabled)
        self.validate_range("syn_rate_per_s", syn_rate_per_s, 1.0, 100_000.0)
        self.validate_range("max_completion_ratio", max_completion_ratio, 0.0, 1.0)
        self.validate_range("window_s", window_s, 1.0, 3600.0)

        self.syn_rate_per_s = float(syn_rate_per_s)
        self.max_completion_ratio = float(max_completion_ratio)
        self.window_s = float(window_s)
        self.severity = severity
        self._dst_syns: defaultdict[str, deque[_SynRecord]] = defaultdict(deque)

    def prune(self, current_time: float) -> None:
        """Discard expired SYN records older than window_s."""
        cutoff = current_time - self.window_s
        for dst_ip in list(self._dst_syns.keys()):
            queue = self._dst_syns[dst_ip]
            while queue and queue[0].timestamp < cutoff:
                queue.popleft()
            if not queue:
                del self._dst_syns[dst_ip]

    def evaluate_packet(self, packet: Packet) -> list[Alert]:
        """Evaluate an observed TCP packet for SYN flood evidence against dst_ip."""
        if not self.enabled or not packet.is_tcp or packet.tcp_flags is None:
            return []

        self.prune(packet.timestamp)

        flags = packet.tcp_flags
        is_syn = bool(flags & TcpFlags.SYN)
        is_ack = bool(flags & TcpFlags.ACK)

        # Record incoming SYN request
        if is_syn and not is_ack:
            rec = _SynRecord(
                timestamp=packet.timestamp,
                src_ip=packet.src_ip,
                is_completed=False,
            )
            self._dst_syns[packet.dst_ip].append(rec)

        # Handshake completion: ACK without SYN
        elif is_ack and not is_syn:
            queue = self._dst_syns.get(packet.src_ip)  # Inverted endpoints for response
            if queue:
                for entry in reversed(queue):
                    if entry.src_ip == packet.dst_ip and not entry.is_completed:
                        entry.is_completed = True
                        break

        # Check threshold on destination target
        queue = self._dst_syns.get(packet.dst_ip)
        if not queue:
            return []

        total_syns = len(queue)
        rate = total_syns / self.window_s
        if rate > self.syn_rate_per_s:
            completed = sum(1 for r in queue if r.is_completed)
            completion_ratio = completed / total_syns if total_syns > 0 else 0.0

            if completion_ratio < self.max_completion_ratio:
                reasons = [
                    f"SYN packet rate = {rate:.1f}/s (threshold > {self.syn_rate_per_s:.1f}/s) "
                    f"in {int(self.window_s)} s",
                    f"handshake completion ratio = {completion_ratio:.1%} "
                    f"(threshold < {self.max_completion_ratio:.1%})",
                ]
                alert = Alert(
                    type="syn_flood",
                    severity=self.severity,
                    detector="rule",
                    src_ip="multiple",
                    dst_ip=packet.dst_ip,
                    dst_port=packet.dst_port,
                    protocol="tcp",
                    reasons=reasons,
                )
                return [alert]

        return []

    def evaluate(self, *args: Any, **kwargs: Any) -> list[Alert]:
        """Generic evaluate method delegating to evaluate_packet."""
        packet = kwargs.get("packet") or (args[0] if args else None)
        if isinstance(packet, Packet):
            return self.evaluate_packet(packet)
        return []