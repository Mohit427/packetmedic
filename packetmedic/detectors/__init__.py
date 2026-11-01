"""Detector registry. Each detector takes the tracker Context and returns Signals."""
from __future__ import annotations

from .arp import detect_arp_conflicts
from .dhcp import detect_dhcp
from .dns import detect_dns_failures, detect_dns_spoofing
from .scan import detect_port_scans
from .tcp import (detect_latency, detect_midstream_resets, detect_mtu, detect_refused_and_unanswered,
                  detect_retransmissions)

DETECTORS = [
    detect_retransmissions,
    detect_refused_and_unanswered,
    detect_midstream_resets,
    detect_mtu,
    detect_latency,
    detect_port_scans,
    detect_arp_conflicts,
    detect_dns_failures,
    detect_dns_spoofing,
    detect_dhcp,
]
