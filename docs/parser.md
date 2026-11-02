# Packet parser

FlowSentinel parses captures with its own small parser (standard library only), so every
detector works on typed `Packet` objects instead of raw bytes.

## Usage

```python
from flowsentinel.parser.packet import format_flags
from flowsentinel.parser.pcap import read_pcap

for packet in read_pcap("tests/fixtures/sample_web.pcap"):
    print(packet.src_ip, packet.dst_ip, packet.protocol, format_flags(packet.tcp_flags))
```

## What is parsed

| Layer | Fields |
|---|---|
| Ethernet | EtherType (one 802.1Q VLAN tag is skipped) |
| IPv4 | source, destination, TTL, protocol, total length, header options skipped |
| TCP | ports, sequence, acknowledgement, window, flags, payload length |
| UDP | ports, payload length |
| ICMP | payload length |

## Design decisions

- **Payload length comes from the IP header, not the frame size.** Ethernet pads short
  frames to 60 bytes, so counting captured bytes would invent payload.
- **Total length 0 is treated as "use the captured length".** Hosts using TCP segmentation
  offload record 0 for large segments.
- **Non-first IP fragments have no ports.** They carry no TCP/UDP header.
- **Non-IPv4 frames are skipped; malformed IPv4 frames raise `ParseError`.** The pcap reader
  logs a warning and continues, so one bad packet never stops an analysis.

## Limits (for now)

- IPv4 only, no IPv6
- Classic pcap only (not pcapng), Ethernet link type only
- No IP fragment reassembly or TCP stream reassembly
- Timestamps are floats, accurate to roughly a microsecond for current dates
