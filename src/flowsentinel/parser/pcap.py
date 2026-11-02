"""Minimal reader for classic libpcap capture files (not pcapng)."""

from __future__ import annotations

import logging
import struct
from collections.abc import Iterator
from pathlib import Path

from flowsentinel.parser.frames import ParseError, parse_frame
from flowsentinel.parser.packet import Packet

logger = logging.getLogger(__name__)

LINKTYPE_ETHERNET = 1
_GLOBAL_HEADER_LEN = 24
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
# magic bytes as they appear in the file -> (struct byte order, ticks per second)
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


class PcapFormatError(ValueError):
    """Raised when a file is not a readable classic pcap capture."""


def read_pcap(path: str | Path) -> Iterator[Packet]:
    """Yield an IPv4 Packet for every parsable frame in a pcap file.

    Non-IPv4 frames are skipped silently; malformed frames are skipped with a warning.
    """
    with open(path, "rb") as fh:
        header = fh.read(_GLOBAL_HEADER_LEN)
        if len(header) < _GLOBAL_HEADER_LEN:
            raise PcapFormatError("file is too short to be a pcap capture")
        magic = header[:4]
        if magic == _PCAPNG_MAGIC:
            raise PcapFormatError("pcapng is not supported; save the capture as pcap")
        try:
            order, ticks_per_second = _MAGICS[magic]
        except KeyError:
            raise PcapFormatError(f"unrecognised pcap magic number {magic.hex()}") from None

        linktype = struct.unpack_from(f"{order}I", header, 20)[0] & 0x0FFFFFFF
        if linktype != LINKTYPE_ETHERNET:
            raise PcapFormatError(f"unsupported link type {linktype}; only Ethernet (1)")

        record = struct.Struct(f"{order}IIII")
        while True:
            raw = fh.read(record.size)
            if not raw:
                return
            if len(raw) < record.size:
                logger.warning("truncated record header at end of file")
                return
            ts_sec, ts_frac, incl_len, _orig_len = record.unpack(raw)
            frame = fh.read(incl_len)
            if len(frame) < incl_len:
                logger.warning("truncated packet data at end of file")
                return
            timestamp = ts_sec + ts_frac / ticks_per_second
            try:
                packet = parse_frame(frame, timestamp)
            except ParseError as exc:
                logger.warning("skipping malformed packet at t=%.6f: %s", timestamp, exc)
                continue
            if packet is not None:
                yield packet
