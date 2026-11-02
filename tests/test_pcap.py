import logging

import pytest

from flowsentinel.parser.packet import PROTO_TCP, PROTO_UDP
from flowsentinel.parser.pcap import PcapFormatError, read_pcap

from .helpers import build_ethernet, build_ipv4, build_pcap, build_tcp, build_udp

TCP_FRAME = build_ethernet(build_ipv4(build_tcp(51000, 80, seq=1), PROTO_TCP))
UDP_FRAME = build_ethernet(build_ipv4(build_udp(53000, 53, b"q" * 10), PROTO_UDP))
ARP_FRAME = build_ethernet(b"\x00" * 28, ethertype=0x0806)


def write(tmp_path, data: bytes):
    path = tmp_path / "capture.pcap"
    path.write_bytes(data)
    return path


def test_reads_packets_and_timestamps(tmp_path):
    # 500000 microseconds = 0.5 s; 250000 microseconds = 0.25 s
    path = write(
        tmp_path,
        build_pcap([(1_700_000_000, 500_000, TCP_FRAME), (1_700_000_001, 250_000, UDP_FRAME)]),
    )
    packets = list(read_pcap(path))
    assert [p.protocol for p in packets] == [PROTO_TCP, PROTO_UDP]
    assert packets[0].timestamp == pytest.approx(1_700_000_000.5)
    assert packets[1].timestamp == pytest.approx(1_700_000_001.25)


def test_nanosecond_timestamps(tmp_path):
    path = write(tmp_path, build_pcap([(10, 500_000_000, TCP_FRAME)], nano=True))
    assert next(read_pcap(path)).timestamp == pytest.approx(10.5)


def test_big_endian_file(tmp_path):
    path = write(tmp_path, build_pcap([(10, 500_000, TCP_FRAME)], big_endian=True))
    packet = next(read_pcap(path))
    assert packet.dst_port == 80
    assert packet.timestamp == pytest.approx(10.5)


def test_skips_non_ipv4_and_malformed_frames(tmp_path, caplog):
    records = [(1, 0, TCP_FRAME), (2, 0, ARP_FRAME), (3, 0, b"\x00" * 10), (4, 0, UDP_FRAME)]
    path = write(tmp_path, build_pcap(records))
    with caplog.at_level(logging.WARNING):
        packets = list(read_pcap(path))
    assert len(packets) == 2
    assert sum("malformed" in r.message for r in caplog.records) == 1


def test_truncated_last_record_is_ignored(tmp_path, caplog):
    data = build_pcap([(1, 0, TCP_FRAME), (2, 0, UDP_FRAME)])[:-5]
    path = write(tmp_path, data)
    with caplog.at_level(logging.WARNING):
        packets = list(read_pcap(path))
    assert len(packets) == 1
    assert "truncated" in caplog.text


def test_empty_capture_yields_nothing(tmp_path):
    assert list(read_pcap(write(tmp_path, build_pcap([])))) == []


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"\x00" * 10, "too short"),
        (b"\x0a\x0d\x0d\x0a" + b"\x00" * 20, "pcapng"),
        (b"\xde\xad\xbe\xef" + b"\x00" * 20, "magic"),
        (build_pcap([], linktype=113), "link type"),
    ],
)
def test_invalid_files_raise(tmp_path, data, message):
    with pytest.raises(PcapFormatError, match=message):
        list(read_pcap(write(tmp_path, data)))
