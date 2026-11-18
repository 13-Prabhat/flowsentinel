from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flowsentinel.detectors.base import Alert, BaseDetector

if TYPE_CHECKING:
    from flowsentinel.features.window import HostWindowFeatures


class PortScanDetector(BaseDetector):
    """Detects port scans using destination port count and Shannon entropy (FR-DET-01).

    Fires an alert when a host contacts >= min_unique_ports (default 50) within
    the window and port Shannon entropy is >= min_entropy_bits (default 4.0 bits).
    """

    def __init__(
        self,
        min_unique_ports: int = 50,
        window_s: float = 10.0,
        min_entropy_bits: float = 4.0,
        severity: str = "high",
        enabled: bool = True,
    ) -> None:
        super().__init__(name="port_scan", enabled=enabled)
        self.validate_range("min_unique_ports", min_unique_ports, 1, 65535)
        self.validate_range("window_s", window_s, 1.0, 3600.0)
        self.validate_range("min_entropy_bits", min_entropy_bits, 0.0, 16.0)

        self.min_unique_ports = int(min_unique_ports)
        self.window_s = float(window_s)
        self.min_entropy_bits = float(min_entropy_bits)
        self.severity = severity

    def evaluate(
        self,
        features: HostWindowFeatures,
        target_ip: str = "",
        *args: Any,
        **kwargs: Any,
    ) -> list[Alert]:
        """Evaluate host window features for port scanning behavior."""
        if not self.enabled:
            return []

        # Dual threshold condition from FR-DET-01 & Appendix A.2
        if (
            features.h_unique_dst_ports >= self.min_unique_ports
            and features.h_port_entropy_bits >= self.min_entropy_bits
        ):
            reasons = [
                f"unique destination ports = {features.h_unique_dst_ports} "
                f"(threshold >= {self.min_unique_ports}) in {int(self.window_s)} s",
                f"destination port entropy = {features.h_port_entropy_bits:.2f} bits "
                f"(threshold >= {self.min_entropy_bits:.1f})",
            ]
            if features.h_syn_only_ratio > 0.0:
                reasons.append(f"SYN-only ratio = {features.h_syn_only_ratio:.2f}")

            alert = Alert(
                type="port_scan",
                severity=self.severity,
                detector="rule",
                src_ip=features.src_ip,
                dst_ip=target_ip or "multiple",
                protocol="tcp",
                reasons=reasons,
            )
            return [alert]

        return []
