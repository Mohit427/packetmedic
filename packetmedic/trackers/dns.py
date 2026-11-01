"""DNS tracking: match questions to answers, measure latency, spot conflicts."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..config import Limits
from ..models import PacketRecord
from ..util import BoundedDict, capped_append


@dataclass(slots=True)
class DnsResponse:
    ts: float
    frame: int
    src: str
    ttl: int | None
    rcode: int
    answers: tuple


@dataclass(slots=True)
class DnsQuery:
    ts: float
    frame: int
    client: str
    server: str
    qname: str
    qtype: int
    retries: int = 0
    frames: list = field(default_factory=list)
    responses: list = field(default_factory=list)


@dataclass(slots=True)
class ServerStats:
    queries: int = 0
    answered: int = 0
    nxdomain: int = 0
    servfail: int = 0
    refused: int = 0
    latencies: list = field(default_factory=list)
    frames: list = field(default_factory=list)
    clients: set = field(default_factory=set)


class DnsTracker:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.queries: BoundedDict = BoundedDict(limits.max_dns_pending)
        self.servers: BoundedDict = BoundedDict(limits.max_hosts)
        self.responder_ttls: dict[str, Counter] = {}
        self.unsolicited: list[DnsResponse] = []
        self.conflicts: list[tuple[DnsQuery, DnsResponse, DnsResponse]] = []
        self.mismatched: list[tuple[DnsQuery, DnsResponse]] = []
        self.answered_queries: list[DnsQuery] = []   # bounded sample used for TTL checks

    def observe(self, r: PacketRecord) -> None:
        d = r.dns
        if d is None:
            return
        cap = self.limits.max_evidence_frames
        if not d.is_response:
            key = (r.src_ip, r.sport, d.txid, d.qname.lower())
            q = self.queries.get(key)
            if q is not None:
                q.retries += 1
                capped_append(q.frames, r.frame, 20)
                return
            q = self.queries.get_or_create(
                key, lambda: DnsQuery(r.ts, r.frame, r.src_ip, r.dst_ip, d.qname, d.qtype))
            q.frames.append(r.frame)
            st = self.servers.get_or_create(r.dst_ip, ServerStats)
            st.queries += 1
            capped_append(st.frames, r.frame, cap)
            if len(st.clients) < 256:
                st.clients.add(r.src_ip)
            return

        resp = DnsResponse(r.ts, r.frame, r.src_ip, r.ip_ttl, d.rcode, d.answers)
        ttls = self.responder_ttls.setdefault(r.src_ip, Counter())
        if len(ttls) < 64 and r.ip_ttl is not None:
            ttls[r.ip_ttl] += 1
        key = (r.dst_ip, r.dport, d.txid, d.qname.lower())
        q = self.queries.get(key)
        if q is None:
            capped_append(self.unsolicited, resp, 500)
            return
        capped_append(q.frames, r.frame, 20)
        if q.responses:
            first = q.responses[0]
            if set(a for a, _ in first.answers) != set(a for a, _ in resp.answers):
                capped_append(self.conflicts, (q, first, resp), 500)
            q.responses.append(resp)
            return
        q.responses.append(resp)
        capped_append(self.answered_queries, q, 20_000)
        if r.src_ip != q.server:
            capped_append(self.mismatched, (q, resp), 500)
        st = self.servers.get_or_create(q.server, ServerStats)
        st.answered += 1
        capped_append(st.latencies, r.ts - q.ts, 5000)
        capped_append(st.frames, r.frame, cap)
        if d.rcode == 3:
            st.nxdomain += 1
        elif d.rcode == 2:
            st.servfail += 1
        elif d.rcode == 5:
            st.refused += 1
