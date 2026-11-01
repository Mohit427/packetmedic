"""All tunable limits and detection thresholds live here.

Limits protect the tool from hostile or huge captures.
Thresholds control sensitivity (and therefore false alarms).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 512 * 1024 * 1024   # refuse files larger than 512 MB
    max_packets: int = 3_000_000              # stop reading after this many packets
    max_packet_bytes: int = 262_144           # a single packet larger than this = corrupt file
    max_block_bytes: int = 16 * 1024 * 1024   # pcapng block sanity limit
    max_flows: int = 200_000                  # TCP conversations tracked at once
    max_hosts: int = 100_000                  # hosts tracked by host-level trackers
    max_dns_pending: int = 100_000            # DNS transactions tracked at once
    max_set_items: int = 5_000                # cap for any per-entity set (ports, segments...)
    max_evidence_frames: int = 200            # evidence frame numbers kept per finding
    max_seconds: float = 600.0                # wall-clock budget for one analysis


@dataclass(frozen=True)
class Thresholds:
    # TCP
    retrans_min_count: int = 5
    retrans_min_rate: float = 0.03            # 3% of data segments re-sent
    refused_min_attempts: int = 3             # SYNs answered by RST for one service
    unanswered_min_attempts: int = 3          # SYNs never answered for one service
    midstream_reset_min_flows: int = 3
    # Port scans
    scan_min_ports: int = 15                  # distinct ports on one host
    scan_min_hosts: int = 15                  # same port on distinct hosts
    scan_max_success_ratio: float = 0.3       # scans mostly fail to carry real data
    # DNS
    dns_timeout_s: float = 2.0
    dns_fail_min_queries: int = 3
    dns_fail_ratio: float = 0.3
    nxdomain_min: int = 5
    dns_slow_s: float = 0.5
    dns_ttl_tolerance: int = 5
    # Latency
    latency_high_s: float = 0.5               # India <-> US is ~300 ms and perfectly normal
    latency_min_samples: int = 3
    # ARP
    arp_unsolicited_min: int = 3
    arp_solicit_window_s: float = 5.0
    # MTU
    mtu_large_segment: int = 1000
    mtu_min_large_retrans: int = 3
    # DHCP
    dhcp_no_response_min: int = 3


@dataclass(frozen=True)
class Settings:
    limits: Limits = field(default_factory=Limits)
    thresholds: Thresholds = field(default_factory=Thresholds)


DEFAULT_SETTINGS = Settings()
