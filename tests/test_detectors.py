from __future__ import annotations

import pytest

from flowsentinel.detectors.base import Alert
from flowsentinel.detectors.rules.port_scan import PortScanDetector
from flowsentinel.features.window import HostWindowFeatures


def _make_features(
    src_ip: str = "10.0.0.5",
    ports: int = 2,
    entropy: float = 0.47,
    syn_ratio: float = 0.0,
    window_s: float = 10.0,
) -> HostWindowFeatures:
    return HostWindowFeatures(
        src_ip=src_ip,
        window_s=window_s,
        h_unique_dst_ports=ports,
        h_unique_dst_hosts=1,
        h_new_conn_rate=1.0,
        h_syn_only_ratio=syn_ratio,
        h_failed_ratio=0.0,
        h_port_entropy_bits=entropy,
    )


def test_base_detector_threshold_validation():
    """FR-DET-05: Reject invalid threshold configuration at startup."""
    with pytest.raises(ValueError, match="Invalid configuration for 'min_unique_ports'"):
        PortScanDetector(min_unique_ports=0)

    with pytest.raises(ValueError, match="Invalid configuration for 'min_entropy_bits'"):
        PortScanDetector(min_entropy_bits=-1.0)


def test_alert_data_structure():
    """SRS Section 7.4 & Appendix C: Alert data model fields and serialization."""
    alert = Alert(
        type="port_scan",
        severity="high",
        detector="rule",
        src_ip="10.0.0.5",
        dst_ip="10.0.0.20",
        reasons=["unique destination ports = 100", "entropy = 6.64"],
    )
    d = alert.to_dict()
    assert d["type"] == "port_scan"
    assert d["severity"] == "high"
    assert d["detector"] == "rule"
    assert d["src_ip"] == "10.0.0.5"
    assert "timestamp" in d
    assert len(d["reasons"]) == 2


def test_port_scan_detector_normal_host_traffic():
    """Appendix A.2: Normal host (2 ports, entropy 0.47 bits) raises no alert."""
    detector = PortScanDetector()
    normal_feats = _make_features(ports=2, entropy=0.47)
    alerts = detector.evaluate(normal_feats)
    assert len(alerts) == 0


def test_port_scan_detector_busy_client_no_false_positive():
    """Appendix A.2: Busy client (55 ports, but entropy 2.3 < 4.0 bits) raises no alert."""
    detector = PortScanDetector(min_unique_ports=50, min_entropy_bits=4.0)
    busy_feats = _make_features(ports=55, entropy=2.3)
    alerts = detector.evaluate(busy_feats)
    assert len(alerts) == 0


def test_port_scan_detector_fires_on_scanner():
    """FR-DET-01, FR-EXP-02, Appendix A.2: Scanner raises alert with plain reasons."""
    detector = PortScanDetector(min_unique_ports=50, min_entropy_bits=4.0)
    scanner_feats = _make_features(ports=100, entropy=6.64, syn_ratio=0.97)

    alerts = detector.evaluate(scanner_feats, target_ip="10.0.0.20")
    assert len(alerts) == 1

    alert = alerts[0]
    assert alert.type == "port_scan"
    assert alert.severity == "high"
    assert alert.src_ip == "10.0.0.5"
    assert alert.dst_ip == "10.0.0.20"

    reasons_text = " ".join(alert.reasons)
    assert "unique destination ports = 100" in reasons_text
    assert "destination port entropy = 6.64 bits" in reasons_text
    assert "SYN-only ratio = 0.97" in reasons_text


def test_port_scan_detector_disabled_toggle():
    """FR-DET-06: Individual detector enable/disable toggles."""
    detector = PortScanDetector(enabled=False)
    scanner_feats = _make_features(ports=100, entropy=6.64)
    alerts = detector.evaluate(scanner_feats)
    assert len(alerts) == 0
