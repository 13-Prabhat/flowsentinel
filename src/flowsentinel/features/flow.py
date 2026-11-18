from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from flowsentinel.features.schema import FLOW_FEATURE_NAMES

if TYPE_CHECKING:
    from flowsentinel.flows.record import FlowRecord


def _sanitize_float(val: float, default: float = 0.0) -> float:
    """Ensure float value is finite, replacing NaN or inf with default (FR-FEA-04)."""
    if not math.isfinite(val):
        return default
    return float(val)


@dataclass(slots=True)
class FlowFeatures:
    """Computed flow features and metadata for a single bidirectional flow."""

    # Metadata
    flow_id: str
    protocol: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    start_ts: float
    end_ts: float
    end_reason: str

    # Volume & duration features (FR-FEA-01)
    f_duration_s: float
    f_pkts_fwd: int
    f_pkts_bwd: int
    f_bytes_fwd: int
    f_bytes_bwd: int
    f_pps: float
    f_bps: float

    # Packet size running stats (FR-FEA-01)
    f_len_min: float
    f_len_mean: float
    f_len_max: float
    f_len_std: float

    # Inter-arrival time running stats (FR-FEA-01)
    f_iat_min: float
    f_iat_mean: float
    f_iat_max: float
    f_iat_std: float

    # TCP flag counts & initial windows (FR-FEA-02)
    f_syn: int
    f_fin: int
    f_rst: int
    f_psh: int
    f_ack: int
    f_urg: int
    f_win_fwd: int
    f_win_bwd: int
    f_payload_pkts: int

    def to_dict(self) -> dict[str, Any]:
        """Convert features and metadata to dictionary."""
        return asdict(self)

    def to_feature_vector(self) -> list[float]:
        """Extract numeric feature values matching FLOW_FEATURE_NAMES."""
        d = self.to_dict()
        return [float(d[name]) for name in FLOW_FEATURE_NAMES]


def extract_flow_features(record: FlowRecord) -> FlowFeatures:
    """Compute deterministic numerical flow features from a FlowRecord.

    Undefined values (e.g. division by zero on zero duration) default to 0.0,
    guaranteeing no NaN or infinite values (FR-FEA-04).
    """
    duration = max(0.0, record.duration_s)
    total_pkts = record.total_packets
    total_bytes = record.total_bytes

    if duration > 0.0:
        pps = _sanitize_float(total_pkts / duration)
        bps = _sanitize_float(total_bytes / duration)
    else:
        pps = 0.0
        bps = 0.0

    # Size statistics from Welford RunningStats
    size_stats = record.size_stats
    if size_stats.count > 0:
        len_min = _sanitize_float(size_stats.min_val)
        len_mean = _sanitize_float(size_stats.mean_val)
        len_max = _sanitize_float(size_stats.max_val)
        len_std = _sanitize_float(size_stats.std)
    else:
        len_min = len_mean = len_max = len_std = 0.0

    # Inter-arrival time statistics from Welford RunningStats
    iat_stats = record.iat_stats
    if iat_stats.count > 0:
        iat_min = _sanitize_float(iat_stats.min_val)
        iat_mean = _sanitize_float(iat_stats.mean_val)
        iat_max = _sanitize_float(iat_stats.max_val)
        iat_std = _sanitize_float(iat_stats.std)
    else:
        iat_min = iat_mean = iat_max = iat_std = 0.0

    # Endpoints
    src_ip, src_port = record.initiator
    if record.key.endpoint_a == record.initiator:
        dst_ip, dst_port = record.key.endpoint_b
    else:
        dst_ip, dst_port = record.key.endpoint_a

    end_reason_str = record.end_reason.value if record.end_reason is not None else ""

    return FlowFeatures(
        flow_id=record.flow_id,
        protocol=record.key.protocol,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        start_ts=record.start_ts,
        end_ts=record.end_ts,
        end_reason=end_reason_str,
        f_duration_s=_sanitize_float(duration),
        f_pkts_fwd=record.pkts_fwd,
        f_pkts_bwd=record.pkts_bwd,
        f_bytes_fwd=record.bytes_fwd,
        f_bytes_bwd=record.bytes_bwd,
        f_pps=pps,
        f_bps=bps,
        f_len_min=len_min,
        f_len_mean=len_mean,
        f_len_max=len_max,
        f_len_std=len_std,
        f_iat_min=iat_min,
        f_iat_mean=iat_mean,
        f_iat_max=iat_max,
        f_iat_std=iat_std,
        f_syn=record.f_syn,
        f_fin=record.f_fin,
        f_rst=record.f_rst,
        f_psh=record.f_psh,
        f_ack=record.f_ack,
        f_urg=record.f_urg,
        f_win_fwd=record.win_fwd,
        f_win_bwd=record.win_bwd,
        f_payload_pkts=record.payload_pkts,
    )
