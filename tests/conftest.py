"""Pytest configuration and test environment setup."""

import sys

# On Windows without an active Npcap driver service, scapy's
# winpcapy.pcap_findalldevs() blocks trying to enumerate network adapter GUIDs.
# Intercepting this call allows Scapy packet layers and rdpcap to load cleanly
# in offline/test environments without hanging.
if sys.platform == "win32":
    try:
        import scapy.libs.winpcapy

        scapy.libs.winpcapy.pcap_findalldevs = lambda *a, **k: -1
    except (ImportError, AttributeError):
        pass
