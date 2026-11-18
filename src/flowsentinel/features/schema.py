from __future__ import annotations

from dataclasses import dataclass
from typing import Final

FEATURE_SCHEMA_VERSION: Final[int] = 1


@dataclass(frozen=True, slots=True)
class FeatureField:
    """Metadata describing an extracted flow or window feature."""

    name: str
    data_type: str
    unit: str
    description: str


FLOW_FEATURE_FIELDS: Final[tuple[FeatureField, ...]] = (
    FeatureField("f_duration_s", "float", "seconds", "Duration of the flow (end_ts - start_ts)"),
    FeatureField("f_pkts_fwd", "int", "count", "Number of packets in forward direction"),
    FeatureField("f_pkts_bwd", "int", "count", "Number of packets in backward direction"),
    FeatureField("f_bytes_fwd", "int", "bytes", "Total IPv4 length in forward direction"),
    FeatureField("f_bytes_bwd", "int", "bytes", "Total IPv4 length in backward direction"),
    FeatureField("f_pps", "float", "1/s", "Packets per second over flow duration (0 if d=0)"),
    FeatureField("f_bps", "float", "1/s", "Bytes per second over flow duration (0 if d=0)"),
    FeatureField("f_len_min", "float", "bytes", "Minimum packet length"),
    FeatureField("f_len_mean", "float", "bytes", "Mean packet length"),
    FeatureField("f_len_max", "float", "bytes", "Maximum packet length"),
    FeatureField("f_len_std", "float", "bytes", "Sample standard deviation of packet lengths"),
    FeatureField("f_iat_min", "float", "seconds", "Minimum packet inter-arrival time"),
    FeatureField("f_iat_mean", "float", "seconds", "Mean packet inter-arrival time"),
    FeatureField("f_iat_max", "float", "seconds", "Maximum packet inter-arrival time"),
    FeatureField("f_iat_std", "float", "seconds", "Sample std of inter-arrival times"),
    FeatureField("f_syn", "int", "count", "Number of TCP packets with SYN flag set"),
    FeatureField("f_fin", "int", "count", "Number of TCP packets with FIN flag set"),
    FeatureField("f_rst", "int", "count", "Number of TCP packets with RST flag set"),
    FeatureField("f_psh", "int", "count", "Number of TCP packets with PSH flag set"),
    FeatureField("f_ack", "int", "count", "Number of TCP packets with ACK flag set"),
    FeatureField("f_urg", "int", "count", "Number of TCP packets with URG flag set"),
    FeatureField("f_win_fwd", "int", "bytes", "Initial TCP window in forward direction"),
    FeatureField("f_win_bwd", "int", "bytes", "Initial TCP window in backward direction"),
    FeatureField("f_payload_pkts", "int", "count", "Number of packets carrying transport payload"),
)
FLOW_FEATURE_NAMES: Final[tuple[str, ...]] = tuple(f.name for f in FLOW_FEATURE_FIELDS)
