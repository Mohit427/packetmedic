"""Duplicate IP / ARP conflict vs ARP spoofing.

Same symptom (one IP address, two hardware addresses) - very different
meaning. We collect evidence for both explanations and let the verdict engine
weigh them.
"""
from __future__ import annotations

import statistics

from ..models import Point, Signal
from ..trackers.context import Context
from ..util import join_list, plural


def detect_arp_conflicts(ctx: Context) -> list[Signal]:
    th = ctx.settings.thresholds
    gateways = ctx.gateway_ips()
    signals = []
    # gateway first, so a merged spoofing incident is titled after the most important address
    for ip, claims in sorted(ctx.arp.claims.items(), key=lambda kv: kv[0] not in gateways):
        if len(claims) < 2:
            continue
        ordered = sorted(claims.items(), key=lambda kv: kv[1].first)
        original_mac, original = ordered[0]
        newcomers = ordered[1:]
        attack: list[Point] = []
        fault: list[Point] = []
        is_gw = ip in gateways

        def first_claimer(addr: str) -> str | None:
            cl = ctx.arp.claims.get(addr)
            return min(cl.items(), key=lambda kv: kv[1].first)[0] if cl else None

        multi_claimers = []
        for mac, _c in newcomers:
            # other addresses this MAC claims that already belonged to someone else
            others = sorted(i for i in ctx.arp.mac_ips.get(mac, set())
                            if i != ip and first_claimer(i) not in (mac, None))
            if others:
                multi_claimers.append((mac, others))
        for mac, others in multi_claimers:
            attack.append(Point(2.5, f"{mac} is also claiming to be {join_list(others)}. A normal "
                                     "network card has one address; one device pretending to be "
                                     "several is the signature of ARP spoofing."))

        unsolicited = [(mac, c) for mac, c in newcomers if c.unsolicited >= th.arp_unsolicited_min]
        for mac, c in unsolicited:
            attack.append(Point(2, f"{mac} sent {c.unsolicited} ARP replies nobody asked for, trying "
                                   f"to overwrite other devices' memory of who {ip} is."))
            if len(c.reply_times) >= 5:
                gaps = [b - a for a, b in zip(c.reply_times, c.reply_times[1:])]
                mean = statistics.mean(gaps)
                if mean > 0 and statistics.pstdev(gaps) / mean < 0.3:
                    attack.append(Point(1, f"The fake replies repeat like clockwork (every "
                                           f"~{mean:.1f} s), the way a poisoning tool refreshes "
                                           "the lie before it expires."))
        if is_gw and (multi_claimers or unsolicited):
            attack.append(Point(1, f"The address being taken over ({ip}) is the network gateway. "
                                   "Whoever owns it can see all internet traffic."))

        if not multi_claimers:
            fault.append(Point(2, "Each device claims only this one address, which looks like two "
                                  "machines that were given the same IP by mistake."))
        if not unsolicited:
            fault.append(Point(1, "The devices only announced themselves or answered real "
                                  "questions. Nobody pushed unsolicited replies."))
        overlap = any(c.first <= original.last for _, c in newcomers)
        if not overlap and not attack:
            fault.append(Point(1.5, "The old device stopped using the address before the new one "
                                    "appeared. A device was probably replaced or reconnected."))
        probe_hits = [p for p in ctx.arp.probes if p[3] == ip]
        if probe_hits:
            fault.append(Point(0.5, f"{plural(len(probe_hits), 'device')} checked whether {ip} "
                                    "was free before using it (ARP probe)."))

        frames: set[int] = set()
        for _mac, c in ordered:
            frames.update(c.frames[:60])
        frames.update(p[1] for p in probe_hits[:20])
        severity = "high" if attack or (is_gw and overlap) else "medium" if overlap else "low"
        impersonator = (multi_claimers[0][0] if multi_claimers
                        else unsolicited[0][0] if unsolicited else None)
        signals.append(Signal(
            # one spoofing device poisoning several addresses = one incident
            kind="arp_conflict", key=f"mac:{impersonator}" if impersonator else ip,
            hosts=[ip, *[m for m, _ in ordered]],
            start=min(c.first for c in claims.values()), end=max(c.last for c in claims.values()),
            frames=sorted(frames)[:200],
            metrics={"ip": ip, "original_mac": original_mac,
                     "other_macs": [m for m, _ in newcomers], "is_gateway": is_gw,
                     "impersonator": impersonator,
                     "also_claims": multi_claimers[0][1] if multi_claimers else [],
                     "unsolicited_replies": sum(c.unsolicited for _, c in newcomers),
                     "claims": {m: c.count for m, c in ordered}},
            attack_points=attack, fault_points=fault, severity=severity))
    return signals
