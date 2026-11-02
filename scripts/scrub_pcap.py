"""Anonymise a pcap: remap MAC addresses and private IPv4 addresses.

Usage:
    python scripts/scrub_pcap.py data/raw/raw_web.pcap tests/fixtures/sample_web.pcap
"""

import sys
from ipaddress import ip_address

from scapy.all import IP, TCP, UDP, Ether, PcapReader, PcapWriter


def should_remap(ip: str) -> bool:
    addr = ip_address(ip)
    return addr.is_private and not addr.is_multicast and ip != "255.255.255.255"


def scrub(src: str, dst: str) -> int:
    mac_map: dict[str, str] = {}
    ip_map: dict[str, str] = {}

    def fake_mac(mac: str) -> str:
        if mac not in mac_map:
            mac_map[mac] = f"02:00:00:00:00:{len(mac_map) + 1:02x}"
        return mac_map[mac]

    def fake_ip(ip: str) -> str:
        if not should_remap(ip):
            return ip
        if ip not in ip_map:
            ip_map[ip] = f"10.0.0.{len(ip_map) + 1}"
        return ip_map[ip]

    count = 0
    with PcapReader(src) as reader:
        with PcapWriter(dst, linktype=reader.linktype) as writer:
            for pkt in reader:
                if Ether in pkt:
                    pkt[Ether].src = fake_mac(pkt[Ether].src)
                    pkt[Ether].dst = fake_mac(pkt[Ether].dst)
                if IP in pkt:
                    pkt[IP].src = fake_ip(pkt[IP].src)
                    pkt[IP].dst = fake_ip(pkt[IP].dst)
                    del pkt[IP].chksum  # recalculated when written
                    for layer in (TCP, UDP):
                        if layer in pkt:
                            del pkt[layer].chksum
                writer.write(pkt)
                count += 1
    print(f"Wrote {count} packets to {dst}")
    print(f"MACs remapped: {len(mac_map)}, private IPs remapped: {len(ip_map)}")
    return count


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python scripts/scrub_pcap.py <input.pcap> <output.pcap>")
    scrub(sys.argv[1], sys.argv[2])
