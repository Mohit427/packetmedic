"""ARP tracking: who claims which IP address, and whether anyone asked."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import Limits, Thresholds
from ..models import PacketRecord
from ..util import BROADCAST_MACS, BoundedDict, capped_add, capped_append


@dataclass(slots=True)
class Claim:
    first: float
    last: float
    count: int = 0
    replies: int = 0
    unsolicited: int = 0
    gratuitous: int = 0
    as_requester: int = 0
    reply_times: list = field(default_factory=list)
    frames: list = field(default_factory=list)


class ArpTracker:
    def __init__(self, limits: Limits, th: Thresholds):
        self.limits, self.th = limits, th
        self.claims: BoundedDict = BoundedDict(limits.max_hosts)      # ip -> {mac: Claim}
        self.mac_ips: BoundedDict = BoundedDict(limits.max_hosts)     # mac -> {ips}
        self.requests: BoundedDict = BoundedDict(limits.max_hosts)    # (asker_ip, target_ip) -> ts
        self.probes: list[tuple[float, int, str, str]] = []          # (ts, frame, mac, target)
        self.packets = 0

    def observe(self, r: PacketRecord) -> None:
        a = r.arp
        if a is None:
            return
        self.packets += 1
        if a.psrc in ("0.0.0.0", "") or a.hwsrc in BROADCAST_MACS:
            if a.op == 1:
                capped_append(self.probes, (r.ts, r.frame, a.hwsrc, a.pdst), 1000)
            return
        gratuitous = a.psrc == a.pdst
        solicited = False
        if a.op == 1 and not gratuitous:
            self.requests.get_or_create((a.psrc, a.pdst), lambda: r.ts)
            self.requests[(a.psrc, a.pdst)] = r.ts
        elif a.op == 2 and not gratuitous:
            asked = self.requests.get((a.pdst, a.psrc))
            solicited = asked is not None and 0 <= r.ts - asked <= self.th.arp_solicit_window_s
            if not solicited and r.dst_mac in BROADCAST_MACS:
                gratuitous = True   # broadcast announcement
        claims = self.claims.get_or_create(a.psrc, dict)
        c = claims.get(a.hwsrc)
        if c is None:
            if len(claims) >= 32:
                return
            c = claims[a.hwsrc] = Claim(first=r.ts, last=r.ts)
        c.last = r.ts
        c.count += 1
        capped_append(c.frames, r.frame, self.limits.max_evidence_frames)
        if gratuitous:
            c.gratuitous += 1
        elif a.op == 2:
            c.replies += 1
            capped_append(c.reply_times, r.ts, 500)
            if not solicited:
                c.unsolicited += 1
        else:
            c.as_requester += 1
        capped_add(self.mac_ips.get_or_create(a.hwsrc, set), a.psrc, 256)
