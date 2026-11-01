"""TCP fault detectors: retransmissions, refused / unanswered connections,
mid-stream resets, MTU problems and high latency."""
from __future__ import annotations

from collections import defaultdict

from ..models import Point, Signal
from ..trackers.context import Context
from ..util import fmt_ms, median, percentile, plural


def _frames(*lists, cap: int = 200) -> list[int]:
    out: set[int] = set()
    for lst in lists:
        out.update(lst)
        if len(out) >= cap * 2:
            break
    return sorted(out)[:cap]


def detect_retransmissions(ctx: Context) -> list[Signal]:
    th = ctx.settings.thresholds
    groups: dict[str, dict] = defaultdict(lambda: {
        "retrans": 0, "data": 0, "dup_acks": 0, "flows": 0, "peers": set(), "frames": [],
        "start": None, "end": None, "large": 0, "max_acked": 0, "pairs": set()})
    for f in ctx.flows.flows.values():
        for d, sender, receiver in ((0, f.client, f.server), (1, f.server, f.client)):
            dr = f.dirs[d]
            if dr.retrans == 0:
                continue
            g = groups[f.server]
            g["retrans"] += dr.retrans
            g["data"] += dr.data_pkts
            g["dup_acks"] += f.dirs[1 - d].dup_acks
            g["flows"] += 1
            g["peers"].add(f.client)
            g["pairs"].add((sender, receiver))
            g["large"] += dr.large_retrans
            g["frames"].extend(dr.retrans_frames[:50])
            g["start"] = f.first_ts if g["start"] is None else min(g["start"], f.first_ts)
            g["end"] = f.last_ts if g["end"] is None else max(g["end"], f.last_ts)
    signals = []
    for server, g in groups.items():
        rate = g["retrans"] / max(1, g["data"])
        if g["retrans"] < th.retrans_min_count or rate < th.retrans_min_rate:
            continue
        sev = "high" if rate >= 0.15 else "medium" if rate >= 0.05 else "low"
        fault = [Point(2, "The lost data was sent again and eventually got through. That is how a "
                          "congested, overloaded or noisy link behaves.")]
        if g["dup_acks"]:
            fault.append(Point(1, f"The receiver sent {plural(g['dup_acks'], 'duplicate acknowledgement')}, "
                                  "meaning it noticed gaps where packets went missing."))
        signals.append(Signal(
            kind="tcp_retransmissions", key=server,
            hosts=[server, *sorted(g["peers"])], start=g["start"], end=g["end"],
            frames=_frames(g["frames"]),
            metrics={"server": server, "retransmissions": g["retrans"], "data_segments": g["data"],
                     "loss_rate": round(rate, 4), "connections": g["flows"],
                     "clients": sorted(g["peers"]), "duplicate_acks": g["dup_acks"],
                     "pairs": sorted(g["pairs"])},
            fault_points=fault, severity=sev))
    return signals


def detect_refused_and_unanswered(ctx: Context) -> list[Signal]:
    th = ctx.settings.thresholds
    refused: dict[tuple, dict] = defaultdict(lambda: {"attempts": 0, "clients": set(), "frames": [],
                                                      "start": None, "end": None})
    silent: dict[tuple, dict] = defaultdict(lambda: {"attempts": 0, "clients": set(), "frames": [],
                                                     "start": None, "end": None})
    for f in ctx.flows.flows.values():
        if f.established or f.synack_ts is not None or not f.saw_syn:
            continue
        bucket = refused if f.rst_from_server_before_est else silent if not f.rst_frames else None
        if bucket is None:
            continue
        g = bucket[(f.server, f.sport)]
        g["attempts"] += f.syn_count
        g["clients"].add(f.client)
        g["frames"].extend(f.syn_frames[:10] + f.rst_frames[:10])
        g["start"] = f.first_ts if g["start"] is None else min(g["start"], f.first_ts)
        g["end"] = f.last_ts if g["end"] is None else max(g["end"], f.last_ts)

    signals = []
    for (server, port), g in refused.items():
        if g["attempts"] < th.refused_min_attempts:
            continue
        n_cli = len(g["clients"])
        fault = [Point(2, f"{server} is reachable (it answers instantly) but rejects every connection "
                          f"to port {port}. Nothing is listening there.")]
        if n_cli > 1:
            fault.append(Point(1, f"{n_cli} different devices were turned away the same way, so the "
                                  "problem is on the server, not on one client."))
        signals.append(Signal(
            kind="tcp_refused", key=f"{server}:{port}", hosts=[server, *sorted(g["clients"])],
            start=g["start"], end=g["end"], frames=_frames(g["frames"]),
            metrics={"server": server, "port": port, "attempts": g["attempts"],
                     "clients": sorted(g["clients"])},
            fault_points=fault, severity="high" if n_cli > 1 else "medium"))

    unreach_by_dst: dict[str, list] = defaultdict(list)
    for ev in ctx.icmp.unreachable:
        if ev.inner and ev.inner[2] == "TCP":
            unreach_by_dst[ev.inner[1]].append(ev)
    for (server, port), g in silent.items():
        if g["attempts"] < th.unanswered_min_attempts:
            continue
        fault = [Point(2, f"Connection attempts to {server} port {port} got no reply at all, so the "
                          "host is down, unreachable, or a firewall is silently dropping traffic.")]
        icmp = unreach_by_dst.get(server, [])
        if icmp:
            fault.append(Point(1, f"A router ({icmp[0].src}) reported the destination as unreachable."))
        signals.append(Signal(
            kind="tcp_unreachable", key=f"{server}:{port}", hosts=[server, *sorted(g["clients"])],
            start=g["start"], end=g["end"], frames=_frames(g["frames"], [e.frame for e in icmp]),
            metrics={"server": server, "port": port, "attempts": g["attempts"],
                     "clients": sorted(g["clients"]), "icmp_unreachable": len(icmp)},
            fault_points=fault, severity="high" if len(g["clients"]) > 1 else "medium"))
    return signals


def detect_midstream_resets(ctx: Context) -> list[Signal]:
    th = ctx.settings.thresholds
    groups: dict[str, dict] = defaultdict(lambda: {"flows": 0, "forged": 0, "clients": set(),
                                                   "frames": [], "start": None, "end": None})
    for f in ctx.flows.flows.values():
        if not f.rst_midstream:
            continue
        g = groups[f.server]
        g["flows"] += 1
        g["forged"] += int(f.rst_ttl_mismatch)
        g["clients"].add(f.client)
        g["frames"].extend(f.rst_frames[:10])
        g["start"] = f.first_ts if g["start"] is None else min(g["start"], f.first_ts)
        g["end"] = f.last_ts if g["end"] is None else max(g["end"], f.last_ts)
    signals = []
    for server, g in groups.items():
        if g["flows"] < th.midstream_reset_min_flows:
            continue
        fault = [Point(1.5, "Connections were cut off in the middle of a transfer. Applications "
                            "crashing, idle timeouts or overloaded servers cause this.")]
        attack = []
        if g["forged"]:
            attack.append(Point(3, f"{plural(g['forged'], 'reset packet')} arrived with a different "
                                   "hop count (IP TTL) from the server's normal packets, so they were "
                                   "probably forged by a third party."))
        signals.append(Signal(
            kind="tcp_reset_midstream", key=server, hosts=[server, *sorted(g["clients"])],
            start=g["start"], end=g["end"], frames=_frames(g["frames"]),
            metrics={"server": server, "connections_cut": g["flows"], "suspicious_resets": g["forged"],
                     "clients": sorted(g["clients"])},
            fault_points=fault, attack_points=attack, severity="medium"))
    return signals


def detect_mtu(ctx: Context) -> list[Signal]:
    th = ctx.settings.thresholds
    groups: dict[tuple, dict] = defaultdict(lambda: {"icmp": [], "mtu": set(), "blackhole": 0,
                                                     "stuck": 0, "delivered": 0, "frames": [],
                                                     "start": None, "end": None, "routers": set()})

    def touch(g, start, end):
        g["start"] = start if g["start"] is None else min(g["start"], start)
        g["end"] = end if g["end"] is None else max(g["end"], end)

    for ev in ctx.icmp.frag_needed:
        if not ev.inner:
            continue
        g = groups[(ev.inner[0], ev.inner[1])]
        g["icmp"].append(ev.frame)
        g["routers"].add(ev.src)
        if ev.mtu:
            g["mtu"].add(ev.mtu)
        touch(g, ev.ts, ev.ts)

    for f in ctx.flows.flows.values():
        for d, sender, receiver in ((0, f.client, f.server), (1, f.server, f.client)):
            dr = f.dirs[d]
            if (dr.large_retrans >= th.mtu_min_large_retrans
                    and dr.max_retrans_len >= th.mtu_large_segment
                    and dr.max_acked_len < dr.max_retrans_len):
                g = groups[(sender, receiver)]
                g["blackhole"] += 1
                g["stuck"] = max(g["stuck"], dr.max_retrans_len)
                g["delivered"] = max(g["delivered"], dr.max_acked_len)
                g["frames"].extend(dr.retrans_frames[:30])
                touch(g, f.first_ts, f.last_ts)
    signals = []
    for (sender, receiver), g in groups.items():
        if not g["icmp"] and not g["blackhole"]:
            continue
        fault = []
        if g["icmp"]:
            mtu_txt = "/".join(str(m) for m in sorted(g["mtu"])) or "a smaller size"
            fault.append(Point(2.5, f"A router on the path ({', '.join(sorted(g['routers']))}) said the "
                                    f"packets are too big and only {mtu_txt} bytes fit through."))
        if g["blackhole"]:
            fault.append(Point(2, f"Packets of {g['stuck']} bytes kept being re-sent and never got "
                                  f"through, while smaller ones ({g['delivered'] or 'small'} bytes) "
                                  "were delivered fine."))
        signals.append(Signal(
            kind="mtu_mismatch", key=f"{sender}>{receiver}", hosts=[sender, receiver],
            start=g["start"], end=g["end"], frames=_frames(g["icmp"], g["frames"]),
            metrics={"sender": sender, "receiver": receiver, "path_mtu": sorted(g["mtu"]),
                     "stuck_segment_size": g["stuck"], "largest_delivered": g["delivered"],
                     "icmp_messages": len(g["icmp"]), "blackholed_connections": g["blackhole"]},
            fault_points=fault, severity="high"))
    return signals


def detect_latency(ctx: Context) -> list[Signal]:
    th = ctx.settings.thresholds
    groups: dict[str, dict] = defaultdict(lambda: {"samples": [], "frames": [], "clients": set(),
                                                   "start": None, "end": None})
    for f in ctx.flows.flows.values():
        samples = []
        if f.handshake_rtt is not None:
            samples.append(f.handshake_rtt)
        # the capture point sits near one end; the direction with the larger
        # data->ACK delay is the one that crosses the real network path
        d0, d1 = f.dirs[0].rtt_samples, f.dirs[1].rtt_samples
        samples.extend(d0 if median(d0) >= median(d1) else d1)
        if not samples:
            continue
        g = groups[f.server]
        g["samples"].extend(samples)
        g["clients"].add(f.client)
        g["frames"].extend(f.frames[:4])
        g["start"] = f.first_ts if g["start"] is None else min(g["start"], f.first_ts)
        g["end"] = f.last_ts if g["end"] is None else max(g["end"], f.last_ts)
    signals = []
    for server, g in groups.items():
        s = g["samples"]
        if len(s) < th.latency_min_samples:
            continue
        med = median(s)
        if med < th.latency_high_s:
            continue
        p95 = percentile(s, 95)
        signals.append(Signal(
            kind="high_latency", key=server, hosts=[server, *sorted(g["clients"])],
            start=g["start"], end=g["end"], frames=_frames(g["frames"]),
            metrics={"server": server, "median_rtt_ms": round(med * 1000), "p95_rtt_ms": round(p95 * 1000),
                     "samples": len(s), "clients": sorted(g["clients"])},
            fault_points=[Point(2, f"Replies from {server} consistently took about {fmt_ms(med)} "
                                   "(under 100 ms is normal on a healthy network), which "
                                   "points to a slow link or an overloaded server.")],
            severity="high" if med >= 1.0 else "medium"))
    return signals
