"""TCP conversation tracking: handshakes, retransmissions, RTT, resets."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import Limits
from ..models import ACK, FIN, RST, SYN, PacketRecord
from ..util import BoundedDict, capped_append

_PENDING_CAP = 64
_RTT_CAP = 200
_FRAME_CAP = 50


@dataclass(slots=True)
class Direction:
    seen: set = field(default_factory=set)         # (seq, len) of data segments already sent
    max_seq_end: int | None = None
    data_pkts: int = 0
    retrans: int = 0
    retrans_frames: list = field(default_factory=list)
    large_retrans: int = 0
    max_retrans_len: int = 0
    max_acked_len: int = 0                          # largest segment the peer confirmed
    pending: dict = field(default_factory=dict)     # seq_end -> (ts, len)
    rtt_samples: list = field(default_factory=list)
    dup_acks: int = 0
    last_ack: int | None = None
    ttl: int | None = None                          # hop count of normal packets
    bytes: int = 0
    keepalives: int = 0


@dataclass(slots=True)
class Flow:
    client: str
    cport: int
    server: str
    sport: int
    first_ts: float
    last_ts: float
    frames: list = field(default_factory=list)
    syn_count: int = 0
    last_syn_ts: float | None = None
    syn_frames: list = field(default_factory=list)
    synack_ts: float | None = None
    handshake_rtt: float | None = None
    established: bool = False
    saw_syn: bool = False
    rst_frames: list = field(default_factory=list)
    rst_from_server_before_est: bool = False
    rst_midstream: bool = False
    rst_ttl_mismatch: bool = False
    fin: bool = False
    dirs: tuple = field(default_factory=lambda: (Direction(), Direction()))

    @property
    def has_data(self) -> bool:
        return self.dirs[0].bytes > 0 or self.dirs[1].bytes > 0


class FlowTracker:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.flows: BoundedDict = BoundedDict(limits.max_flows)

    def observe(self, r: PacketRecord) -> None:
        a, b = (r.src_ip, r.sport), (r.dst_ip, r.dport)
        key = (a, b) if a <= b else (b, a)
        flow = self.flows.get(key)
        if flow is None:
            # decide who is the client
            if r.tcp_flags & SYN and not r.tcp_flags & ACK:
                client = a
            elif r.tcp_flags & SYN and r.tcp_flags & ACK:
                client = b
            else:
                # handshake not captured (capture started mid-conversation):
                # the side with the lower port is the service, the other the client
                client = b if r.sport < r.dport else a
            server = b if client == a else a
            flow = self.flows.get_or_create(
                key, lambda: Flow(client[0], client[1], server[0], server[1], r.ts, r.ts))
        flow.last_ts = r.ts
        capped_append(flow.frames, r.frame, _FRAME_CAP)
        d = 0 if (r.src_ip, r.sport) == (flow.client, flow.cport) else 1
        me, peer = flow.dirs[d], flow.dirs[1 - d]
        flags = r.tcp_flags

        if flags & SYN and not flags & ACK:
            flow.saw_syn = True
            flow.syn_count += 1
            flow.last_syn_ts = r.ts
            capped_append(flow.syn_frames, r.frame, _FRAME_CAP)
        elif flags & SYN and flags & ACK:
            if flow.synack_ts is None:
                flow.synack_ts = r.ts
                if flow.last_syn_ts is not None:
                    flow.handshake_rtt = r.ts - flow.last_syn_ts
        elif flags & ACK and flow.synack_ts is not None and d == 0:
            flow.established = True

        if flags & RST:
            capped_append(flow.rst_frames, r.frame, _FRAME_CAP)
            if d == 1 and not flow.established and flow.synack_ts is None:
                flow.rst_from_server_before_est = True
            elif flow.has_data and not flow.fin:
                flow.rst_midstream = True
                if me.ttl is not None and r.ip_ttl is not None and abs(me.ttl - r.ip_ttl) > 3:
                    flow.rst_ttl_mismatch = True
            return
        if r.ip_ttl is not None:
            me.ttl = r.ip_ttl
        if flags & FIN:
            flow.fin = True

        if r.payload_len > 0:
            flow.established = flow.established or flow.synack_ts is not None or not flow.saw_syn
            self._data(me, r)
        if flags & ACK:
            self._ack(me, peer, r)

    def _data(self, me: Direction, r: PacketRecord) -> None:
        lim = self.limits
        seg = (r.seq, r.payload_len)
        end = r.seq + r.payload_len
        # TCP keep-alive: a 0/1-byte probe that deliberately re-uses the last
        # sequence number ("are you still there?"). Not data loss - ignore it,
        # exactly like Wireshark's tcp.analysis.keep_alive rule.
        if r.payload_len <= 1 and me.max_seq_end is not None and r.seq == me.max_seq_end - 1:
            me.keepalives += 1
            return
        me.data_pkts += 1
        if seg in me.seen or (me.max_seq_end is not None and end <= me.max_seq_end
                              and me.max_seq_end - end < 1 << 30):
            me.retrans += 1
            capped_append(me.retrans_frames, r.frame, lim.max_evidence_frames)
            me.max_retrans_len = max(me.max_retrans_len, r.payload_len)
            if r.payload_len >= 1000:
                me.large_retrans += 1
            me.pending.pop(end, None)    # Karn's rule: no RTT from re-sent segments
            return
        me.bytes += r.payload_len
        if len(me.seen) < lim.max_set_items:
            me.seen.add(seg)
        me.max_seq_end = end if me.max_seq_end is None else max(me.max_seq_end, end)
        if len(me.pending) < _PENDING_CAP:
            me.pending[end] = (r.ts, r.payload_len)

    @staticmethod
    def _ack(me: Direction, peer: Direction, r: PacketRecord) -> None:
        v = r.ack
        if peer.pending:
            hit = peer.pending.get(v)
            if hit is not None:
                capped_append(peer.rtt_samples, r.ts - hit[0], _RTT_CAP)
            for k in [k for k in peer.pending if k <= v]:
                peer.max_acked_len = max(peer.max_acked_len, peer.pending.pop(k)[1])
        if r.payload_len == 0 and not r.tcp_flags & (SYN | FIN | RST):
            if me.last_ack == v:
                me.dup_acks += 1
            me.last_ack = v
