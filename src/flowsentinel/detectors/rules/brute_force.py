from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Final

from flowsentinel.detectors.base import Alert, BaseDetector
from flowsentinel.parser.packet import Packet, TcpFlags

DEFAULT_MIN_CONNECTIONS: Final[int] = 20
DEFAULT_WINDOW_S: Final[float] = 60.0
DEFAULT_MONITORED_PORTS: Final[tuple[int, ...]] = (21, 22, 23, 3389)
SERVICE_NAMES: Final[dict[int, str]] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
}


class BruteForceDetector(BaseDetector):
    """Detects repeated connection attempts targeting authentication services (FR-DET-03).

    Fires an alert when a single source host initiates >= min_connections (default 20)
    to the same destination and service port within window_s (default 60s).
    """

    def __init__(
        self,
        min_connections: int = DEFAULT_MIN_CONNECTIONS,
        window_s: float = DEFAULT_WINDOW_S,
        monitored_ports: tuple[int, ...] = DEFAULT_MONITORED_PORTS,
        severity: str = "high",
        enabled: bool = True,
    ) -> None:
        super().__init__(name="brute_force", enabled=enabled)
        self.validate_range("min_connections", min_connections, 1, 10_000)
        self.validate_range("window_s", window_s, 1.0, 3600.0)

        self.min_connections = int(min_connections)
        self.window_s = float(window_s)
        self.monitored_ports = set(monitored_ports)
        self.severity = severity
        self._target_history: defaultdict[tuple[str, str, int], deque[float]] = defaultdict(deque)

    def prune(self, current_time: float) -> None:
        """Discard connection timestamps older than window_s."""
        cutoff = current_time - self.window_s
        for key in list(self._target_history.keys()):
            queue = self._target_history[key]
            while queue and queue[0] < cutoff:
                queue.popleft()
            if not queue:
                del self._target_history[key]

    def evaluate_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: float,
    ) -> list[Alert]:
        """Record and evaluate a newly initiated connection."""
        if not self.enabled or dst_port not in self.monitored_ports:
            return []

        self.prune(timestamp)

        key = (src_ip, dst_ip, dst_port)
        queue = self._target_history[key]
        queue.append(timestamp)

        count = len(queue)
        if count >= self.min_connections:
            service = SERVICE_NAMES.get(dst_port, f"port {dst_port}")
            reasons = [
                f"new connections to {service} (port {dst_port}) = {count} "
                f"(threshold >= {self.min_connections}) in {int(self.window_s)} s",
            ]
            alert = Alert(
                type="brute_force",
                severity=self.severity,
                detector="rule",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="tcp",
                reasons=reasons,
            )
            return [alert]

        return []

    def evaluate_packet(self, packet: Packet) -> list[Alert]:
        """Evaluate an observed TCP packet for connection initiation (SYN without ACK)."""
        if not self.enabled or not packet.is_tcp or packet.tcp_flags is None:
            return []

        is_syn = bool(packet.tcp_flags & TcpFlags.SYN)
        is_ack = bool(packet.tcp_flags & TcpFlags.ACK)
        if is_syn and not is_ack and packet.dst_port is not None:
            return self.evaluate_connection(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
                timestamp=packet.timestamp,
            )
        return []

    def evaluate(self, *args: Any, **kwargs: Any) -> list[Alert]:
        """Generic evaluate method handling either Packet or explicit connection parameters."""
        packet = kwargs.get("packet") or (args[0] if args and isinstance(args[0], Packet) else None)
        if isinstance(packet, Packet):
            return self.evaluate_packet(packet)

        src_ip = kwargs.get("src_ip")
        dst_ip = kwargs.get("dst_ip")
        dst_port = kwargs.get("dst_port")
        timestamp = kwargs.get("timestamp")
        if all(v is not None for v in (src_ip, dst_ip, dst_port, timestamp)):
            return self.evaluate_connection(
                src_ip=str(src_ip),
                dst_ip=str(dst_ip),
                dst_port=int(dst_port),
                timestamp=float(timestamp),
            )
        return []
