"""Port scan / host sweep detection."""
from __future__ import annotations

from ..models import Point, Signal
from ..trackers.context import Context
from ..util import fmt_duration


def detect_port_scans(ctx: Context) -> list[Signal]:
    th = ctx.settings.thresholds
    # which (client, server, port) combinations carried real data = legitimate use
    useful: set[tuple[str, str, int]] = set()
    for f in ctx.flows.flows.values():
        if f.has_data:
            useful.add((f.client, f.server, f.sport))

    signals = []
    for src, s in ctx.scans.sources.items():
        vertical = {dst: ports for dst, ports in s.targets.items() if len(ports) >= th.scan_min_ports}
        horizontal = {p: hosts for p, hosts in s.port_hosts.items() if len(hosts) >= th.scan_min_hosts}
        if not vertical and not horizontal:
            continue
        probes = {(dst, p) for dst, ports in s.targets.items() for p in ports}
        ok = sum(1 for dst, p in probes if (src, dst, p) in useful)
        success = ok / max(1, len(probes))
        if success > th.scan_max_success_ratio:
            continue   # mostly real connections: a busy client or proxy, not a scan
        dur = max(s.last - s.first, 0.001)
        rate = s.syns / dur
        attack: list[Point] = []
        targets = sorted(vertical, key=lambda d: -len(vertical[d]))
        for dst in targets[:3]:
            attack.append(Point(3, f"{src} tried {len(vertical[dst])} different ports on {dst} "
                                   f"in {fmt_duration(dur)}, checking which services are open."))
        if horizontal:
            port = max(horizontal, key=lambda p: len(horizontal[p]))
            attack.append(Point(3, f"{src} tried port {port} on {len(horizontal[port])} different "
                                   "machines, looking for vulnerable hosts."))
        if rate >= 10:
            attack.append(Point(1, f"Very fast: about {rate:.0f} connection attempts per second, "
                                   "faster than any person could click."))
        if success < 0.1:
            attack.append(Point(1, "Almost none of these attempts were used to exchange data. "
                                   "The goal was only to see which ports answered."))
        open_ports = sorted(s.open_ports)
        sev = "high" if open_ports else "medium"
        signals.append(Signal(
            kind="port_scan", key=src,
            hosts=[src, *sorted(set(vertical) | {h for hs in horizontal.values() for h in hs})][:50],
            start=s.first, end=s.last, frames=sorted(s.frames)[:200],
            metrics={"scanner": src, "targets": targets[:20],
                     "ports_probed": len({p for _, p in probes}), "probes": s.syns,
                     "duration_s": round(dur, 3), "rate_per_s": round(rate, 1),
                     "open_ports": [f"{h}:{p}" for h, p in open_ports[:50]],
                     "closed_responses": s.closed,
                     "sweep_ports": sorted(horizontal)[:20]},
            attack_points=attack, severity=sev))
    return signals
