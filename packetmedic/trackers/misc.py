"""DHCP, ICMP, port-scan and whole-capture tracking."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..config import Limits
from ..models import ACK, RST, SYN, PacketRecord
from ..util import BoundedDict, capped_add, capped_append, is_public


# --------------------------------------------------------------------------- DHCP
@dataclass(slots=True)
class DhcpServer:
    server_id: str
    first_ts: float
    macs: set = field(default_factory=set)
    offers: int = 0
    acks: int = 0
    naks: int = 0
    routers: set = field(default_factory=set)
    dns: set = field(default_factory=set)
    clients: set = field(default_factory=set)
    frames: list = field(default_factory=list)
    reply_delays: list = field(default_factory=list)


class DhcpTracker:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.servers: dict[str, DhcpServer] = {}
        self.discovers: BoundedDict = BoundedDict(limits.max_hosts)   # xid -> (ts, frame, mac)
        self.answered_xids: set = set()
        self.discover_frames: list[int] = []

    def observe(self, r: PacketRecord) -> None:
        d = r.dhcp
        if d is None:
            return
        if d.msg_type == 1:
            self.discovers.get_or_create(d.xid, lambda: (r.ts, r.frame, d.client_mac))
            capped_append(self.discover_frames, r.frame, self.limits.max_evidence_frames)
            return
        if d.msg_type not in (2, 5, 6):
            return
        sid = d.server_id or r.src_ip or "unknown"
        if sid not in self.servers:
            if len(self.servers) >= 64:
                return
            self.servers[sid] = DhcpServer(sid, r.ts)
        s = self.servers[sid]
        capped_add(s.macs, r.src_mac, 16)
        capped_add(s.clients, d.client_mac, 1000)
        capped_append(s.frames, r.frame, self.limits.max_evidence_frames)
        s.routers.update(d.routers[:4])
        s.dns.update(d.dns_servers[:4])
        if d.msg_type == 2:
            s.offers += 1
            disc = self.discovers.get(d.xid)
            if disc:
                capped_append(s.reply_delays, r.ts - disc[0], 500)
        elif d.msg_type == 5:
            s.acks += 1
        else:
            s.naks += 1
        if len(self.answered_xids) < self.limits.max_hosts:
            self.answered_xids.add(d.xid)


# --------------------------------------------------------------------------- ICMP
@dataclass(slots=True)
class IcmpEvent:
    ts: float
    frame: int
    src: str
    type: int
    code: int
    mtu: int | None
    inner: tuple | None


class IcmpTracker:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.frag_needed: list[IcmpEvent] = []
        self.unreachable: list[IcmpEvent] = []

    def observe(self, r: PacketRecord) -> None:
        i = r.icmp
        if i is None or i.type != 3:
            return
        ev = IcmpEvent(r.ts, r.frame, r.src_ip, i.type, i.code, i.mtu, i.inner)
        if i.code == 4:
            capped_append(self.frag_needed, ev, 5000)
        else:
            capped_append(self.unreachable, ev, 5000)


# --------------------------------------------------------------------------- scans
@dataclass(slots=True)
class ScanState:
    first: float
    last: float
    syns: int = 0
    targets: dict = field(default_factory=dict)        # dst -> set(ports)
    port_hosts: dict = field(default_factory=dict)     # port -> set(dsts)
    open_ports: set = field(default_factory=set)       # (dst, port) answered with SYN/ACK
    closed: int = 0                                    # answered with RST
    frames: list = field(default_factory=list)


class ScanTracker:
    """Records connection attempts (SYN without ACK) per source host."""

    def __init__(self, limits: Limits):
        self.limits = limits
        self.sources: BoundedDict = BoundedDict(limits.max_hosts)

    def observe(self, r: PacketRecord) -> None:
        f, cap = r.tcp_flags, self.limits.max_set_items
        if f & SYN and not f & ACK:
            s = self.sources.get_or_create(r.src_ip, lambda: ScanState(r.ts, r.ts))
            s.last = r.ts
            s.syns += 1
            capped_append(s.frames, r.frame, self.limits.max_evidence_frames)
            if r.dst_ip in s.targets or len(s.targets) < cap:
                capped_add(s.targets.setdefault(r.dst_ip, set()), r.dport, cap)
            if r.dport in s.port_hosts or len(s.port_hosts) < cap:
                capped_add(s.port_hosts.setdefault(r.dport, set()), r.dst_ip, cap)
        elif r.dst_ip in self.sources:
            s = self.sources[r.dst_ip]
            if f & SYN and f & ACK:
                capped_add(s.open_ports, (r.src_ip, r.sport), cap)
            elif f & RST:
                s.closed += 1


# --------------------------------------------------------------------------- whole capture
class GeneralTracker:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.packets = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.protocols: Counter = Counter()
        self.egress_macs: Counter = Counter()     # next-hop MAC for internet-bound traffic
        self.hosts: set = set()

    def observe(self, r: PacketRecord) -> None:
        self.packets += 1
        if r.ts > 0:
            self.first_ts = r.ts if self.first_ts is None else min(self.first_ts, r.ts)
            self.last_ts = r.ts if self.last_ts is None else max(self.last_ts, r.ts)
        label = r.proto
        if r.dns:
            label = "DNS"
        elif r.dhcp:
            label = "DHCP"
        self.protocols[label] += 1
        if r.dst_mac and is_public(r.dst_ip):
            self.egress_macs[r.dst_mac] += 1
        for h in (r.src_ip, r.dst_ip):
            if h and len(self.hosts) < self.limits.max_hosts:
                self.hosts.add(h)
