from __future__ import annotations

import csv
import io
import math
import sys
from unittest.mock import MagicMock

import pytest

from flowsentinel.features import (
    FEATURE_SCHEMA_VERSION,
    FLOW_FEATURE_FIELDS,
    FLOW_FEATURE_NAMES,
    export_csv,
    export_dataframe,
    extract_flow_features,
)
from flowsentinel.flows.key import make_flow_key
from flowsentinel.flows.record import EndReason, FlowRecord
from flowsentinel.parser.packet import PROTO_TCP, Packet, TcpFlags


def _make_pkt(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "93.184.216.34",
    src_port: int | None = 51000,
    dst_port: int | None = 80,
    proto: int = PROTO_TCP,
    ts: float = 0.0,
    flags: int = 0x02,
    length: int = 40,
    payload_len: int = 0,
    window: int | None = 64240,
) -> Packet:
    return Packet(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=proto,
        ttl=64,
        ip_length=length,
        payload_len=payload_len,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=TcpFlags(flags),
        window=window,
    )


def test_schema_version_and_field_naming():
    """FR-FEA-05 & SRS 7.3: Feature schema version 1 and f_ prefix."""
    assert FEATURE_SCHEMA_VERSION == 1
    assert len(FLOW_FEATURE_FIELDS) == 24
    assert len(FLOW_FEATURE_NAMES) == 24

    for name in FLOW_FEATURE_NAMES:
        assert name.startswith("f_")


def test_single_packet_flow_feature_extraction():
    """FR-FEA-01, FR-FEA-02, FR-FEA-04: Single-packet flow handling."""
    pkt = _make_pkt(
        src_ip="10.0.0.1",
        dst_ip="93.184.216.34",
        src_port=51000,
        dst_port=80,
        ts=100.0,
        flags=0x02,  # SYN
        length=60,
        payload_len=0,
        window=29200,
    )
    key = make_flow_key(pkt)
    rec = FlowRecord(
        key=key,
        initiator=("10.0.0.1", 51000),
        start_ts=pkt.timestamp,
        end_ts=pkt.timestamp,
        end_reason=EndReason.EOF,
    )
    rec.add_packet(pkt)

    feats = extract_flow_features(rec)

    assert feats.flow_id == rec.flow_id
    assert feats.protocol == PROTO_TCP
    assert feats.src_ip == "10.0.0.1"
    assert feats.src_port == 51000
    assert feats.dst_ip == "93.184.216.34"
    assert feats.dst_port == 80
    assert feats.end_reason == "eof"

    # Volume and duration
    assert feats.f_duration_s == 0.0
    assert feats.f_pkts_fwd == 1
    assert feats.f_pkts_bwd == 0
    assert feats.f_bytes_fwd == 60
    assert feats.f_bytes_bwd == 0
    assert feats.f_pps == 0.0
    assert feats.f_bps == 0.0

    # Size stats
    assert feats.f_len_min == 60.0
    assert feats.f_len_mean == 60.0
    assert feats.f_len_max == 60.0
    assert feats.f_len_std == 0.0

    # IAT stats
    assert feats.f_iat_min == 0.0
    assert feats.f_iat_mean == 0.0
    assert feats.f_iat_max == 0.0
    assert feats.f_iat_std == 0.0

    # Flags and windows
    assert feats.f_syn == 1
    assert feats.f_fin == 0
    assert feats.f_rst == 0
    assert feats.f_psh == 0
    assert feats.f_ack == 0
    assert feats.f_urg == 0
    assert feats.f_win_fwd == 29200
    assert feats.f_win_bwd == 0
    assert feats.f_payload_pkts == 0


def test_bidirectional_multi_packet_flow_features():
    """FR-FEA-01, FR-FEA-02: Feature computation on multi-packet conversation."""
    p1 = _make_pkt(
        src_ip="10.0.0.1",
        dst_ip="93.184.216.34",
        src_port=51000,
        dst_port=80,
        ts=1.0,
        flags=0x02,  # SYN
        length=60,
        window=65535,
    )
    p2 = _make_pkt(
        src_ip="93.184.216.34",
        dst_ip="10.0.0.1",
        src_port=80,
        dst_port=51000,
        ts=1.1,
        flags=0x12,  # SYN+ACK
        length=60,
        window=28960,
    )
    p3 = _make_pkt(
        src_ip="10.0.0.1",
        dst_ip="93.184.216.34",
        src_port=51000,
        dst_port=80,
        ts=1.2,
        flags=0x18,  # PSH+ACK
        length=200,
        payload_len=140,
        window=65535,
    )
    p4 = _make_pkt(
        src_ip="93.184.216.34",
        dst_ip="10.0.0.1",
        src_port=80,
        dst_port=51000,
        ts=2.0,
        flags=0x11,  # FIN+ACK
        length=60,
        window=28960,
    )

    key = make_flow_key(p1)
    rec = FlowRecord(
        key=key,
        initiator=("10.0.0.1", 51000),
        start_ts=p1.timestamp,
        end_ts=p1.timestamp,
        end_reason=EndReason.FIN,
    )
    for p in (p1, p2, p3, p4):
        rec.add_packet(p)

    feats = extract_flow_features(rec)

    # Duration: 2.0 - 1.0 = 1.0 s
    assert pytest.approx(feats.f_duration_s) == 1.0
    assert feats.f_pkts_fwd == 2
    assert feats.f_pkts_bwd == 2
    assert feats.f_bytes_fwd == 260
    assert feats.f_bytes_bwd == 120
    assert pytest.approx(feats.f_pps) == 4.0
    assert pytest.approx(feats.f_bps) == 380.0

    # Size stats: [60, 60, 200, 60] -> mean = 95.0, min=60, max=200
    assert feats.f_len_min == 60.0
    assert feats.f_len_max == 200.0
    assert pytest.approx(feats.f_len_mean) == 95.0
    assert feats.f_len_std > 0.0

    # IAT stats: intervals [0.1, 0.1, 0.8] -> mean = 1.0/3
    assert pytest.approx(feats.f_iat_min) == 0.1
    assert pytest.approx(feats.f_iat_max) == 0.8
    assert pytest.approx(feats.f_iat_mean) == 1.0 / 3.0
    assert feats.f_iat_std > 0.0

    # TCP flags and initial windows
    assert feats.f_syn == 2
    assert feats.f_ack == 3
    assert feats.f_psh == 1
    assert feats.f_fin == 1
    assert feats.f_rst == 0
    assert feats.f_urg == 0
    assert feats.f_win_fwd == 65535
    assert feats.f_win_bwd == 28960
    assert feats.f_payload_pkts == 1


def test_zero_undefined_protection_never_nan_or_inf():
    """FR-FEA-04: Undefined arithmetic defaults to 0 and never returns NaN/inf."""
    pkt = _make_pkt(ts=50.0, length=40)
    key = make_flow_key(pkt)
    rec = FlowRecord(
        key=key,
        initiator=("10.0.0.1", 51000),
        start_ts=50.0,
        end_ts=50.0,
    )
    rec.add_packet(pkt)

    feats = extract_flow_features(rec)
    vec = feats.to_feature_vector()

    assert len(vec) == len(FLOW_FEATURE_NAMES)
    for val in vec:
        assert isinstance(val, (int, float))
        assert math.isfinite(val)
        assert not math.isnan(val)


def test_export_csv_stream_and_file(tmp_path):
    """FR-FEA-06: Export features as CSV."""
    pkt = _make_pkt()
    key = make_flow_key(pkt)
    rec = FlowRecord(key=key, initiator=("10.0.0.1", 51000), start_ts=0.0, end_ts=0.0)
    rec.add_packet(pkt)
    feats = extract_flow_features(rec)

    # 1. In-memory StringIO stream
    buf = io.StringIO()
    export_csv([feats], buf)
    buf.seek(0)
    reader = csv.DictReader(buf)
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["src_ip"] == "10.0.0.1"
    assert rows[0]["f_pkts_fwd"] == "1"

    # 2. Filepath export
    csv_file = tmp_path / "sub" / "features.csv"
    export_csv([feats], csv_file)
    assert csv_file.exists()
    with csv_file.open("r", encoding="utf-8") as f:
        file_rows = list(csv.DictReader(f))
        assert len(file_rows) == 1
        assert file_rows[0]["flow_id"] == feats.flow_id


def test_export_dataframe():
    """FR-FEA-06: Export features as pandas DataFrame."""
    pkt = _make_pkt()
    key = make_flow_key(pkt)
    rec = FlowRecord(key=key, initiator=("10.0.0.1", 51000), start_ts=0.0, end_ts=0.0)
    rec.add_packet(pkt)
    feats = extract_flow_features(rec)

    if "pandas" in sys.modules:
        df = export_dataframe([feats])
        assert len(df) == 1
        assert df["flow_id"].iloc[0] == feats.flow_id
    else:
        with pytest.raises(ImportError, match="pandas is required for export_dataframe"):
            export_dataframe([feats])

        mock_pd = MagicMock()
        mock_pd.DataFrame.from_records.return_value = "mock_df"
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "pandas", mock_pd)
            res = export_dataframe([feats])
            assert res == "mock_df"
            mock_pd.DataFrame.from_records.assert_called_once()
