"""Core data structures shared by every layer."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# TCP flag bits
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


# --------------------------------------------------------------------------- packets
@dataclass(slots=True)
class DnsInfo:
    txid: int
    is_response: bool
    rcode: int
    qname: str
    qtype: int
    answers: tuple[tuple[str, int], ...] = ()   # (address, record TTL)


@dataclass(slots=True)
class ArpInfo:
    op: int            # 1 = request, 2 = reply
    hwsrc: str
    psrc: str
    hwdst: str
    pdst: str


@dataclass(slots=True)
class DhcpInfo:
    msg_type: int      # 1 discover, 2 offer, 3 request, 5 ack, 6 nak
    xid: int
    client_mac: str
    server_id: str | None
    yiaddr: str | None
    routers: tuple[str, ...] = ()
    dns_servers: tuple[str, ...] = ()


@dataclass(slots=True)
class IcmpInfo:
    type: int
    code: int
    mtu: int | None = None
    # embedded original packet: (src, dst, proto, sport, dport)
    inner: tuple[str, str, str, int, int] | None = None


@dataclass(slots=True)
class PacketRecord:
    """A flat, Scapy-free view of one packet. Everything downstream uses only this."""
    frame: int
    ts: float
    length: int
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_ttl: int | None = None
    proto: str = "OTHER"           # TCP / UDP / ICMP / ARP / OTHER
    sport: int = 0
    dport: int = 0
    tcp_flags: int = 0
    seq: int = 0
    ack: int = 0
    payload_len: int = 0
    dns: DnsInfo | None = None
    arp: ArpInfo | None = None
    dhcp: DhcpInfo | None = None
    icmp: IcmpInfo | None = None


# --------------------------------------------------------------------------- findings
class Verdict(str, Enum):
    ATTACK = "ATTACK"
    SUSPICIOUS = "SUSPICIOUS"
    FAULT = "FAULT"


@dataclass
class Point:
    """One weighted piece of reasoning for (or against) 'this is an attack'."""
    weight: float
    text: str


@dataclass
class Signal:
    """A raw anomaly produced by a detector, before correlation."""
    kind: str
    key: str                          # signals with same kind+key get merged
    hosts: list[str]
    start: float
    end: float
    frames: list[int]
    metrics: dict[str, Any] = field(default_factory=dict)
    attack_points: list[Point] = field(default_factory=list)
    fault_points: list[Point] = field(default_factory=list)
    severity: str = "medium"          # low / medium / high


@dataclass
class Explanation:
    title: str
    summary: str
    why_it_matters: str
    likely_cause: str
    next_steps: list[str]
    wireshark_filter: str


@dataclass
class Incident:
    id: str
    kind: str
    verdict: Verdict
    confidence: str
    severity: str
    hosts: list[str]
    start: float
    end: float
    frames: list[int]
    metrics: dict[str, Any]
    attack_points: list[Point]
    fault_points: list[Point]
    attack_score: float
    fault_score: float
    symptoms: list[Signal] = field(default_factory=list)
    explanation: Explanation | None = None


@dataclass
class Report:
    file_name: str
    file_size: int
    capture_format: str
    packets: int
    malformed: int
    warnings: list[str]
    start_ts: float
    end_ts: float
    protocols: dict[str, int]
    hosts_seen: int
    incidents: list[Incident]
    health_score: int
    health_label: str
    analysis_seconds: float

    @property
    def duration(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)
