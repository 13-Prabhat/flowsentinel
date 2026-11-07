import pytest

from flowsentinel.features import PacketSample, extract_flow_features


def test_extract_flow_features():
    packets = [
        PacketSample(timestamp=10.0, length=100, direction=1),
        PacketSample(timestamp=12.0, length=200, direction=-1),
    ]

    features = extract_flow_features(packets)

    assert features["packet_count"] == 2
    assert features["total_bytes"] == 300
    assert features["duration_seconds"] == 2.0
    assert features["mean_packet_size_bytes"] == 150
    assert features["packets_per_second"] == 1.0
    assert features["forward_packet_count"] == 1
    assert features["reverse_packet_count"] == 1


def test_empty_flow_is_rejected():
    with pytest.raises(ValueError, match="at least one packet"):
        extract_flow_features([])
