"""Rogue DHCP server detection and DHCP-not-answering faults."""
from __future__ import annotations

from ..models import Point, Signal
from ..trackers.context import Context
from ..util import join_list, median


def detect_dhcp(ctx: Context) -> list[Signal]:
    th = ctx.settings.thresholds
    signals: list[Signal] = []
    servers = [s for s in ctx.dhcp.servers.values() if s.offers + s.acks > 0]

    if len(servers) >= 2:
        gw_ips, gw_macs = ctx.gateway_ips(include_dhcp=False), ctx.gateway_macs()
        trusted = [s for s in servers if s.server_id in gw_ips or s.macs & gw_macs]
        legit = trusted[0] if len(trusted) == 1 else None
        if legit is None:
            legit = min(servers, key=lambda s: s.first_ts)   # first seen = most likely established
            legit_known = False
        else:
            legit_known = True
        for s in servers:
            if s is legit:
                continue
            attack = [Point(1.5, f"A second DHCP server ({s.server_id}) is handing out network "
                                 f"settings alongside {legit.server_id}. A network should have one.")]
            fault: list[Point] = []
            diff_router = s.routers and legit.routers and s.routers != legit.routers
            diff_dns = s.dns and legit.dns and s.dns != legit.dns
            if diff_router:
                attack.append(Point(2.5, f"It tells devices to use {join_list(sorted(s.routers))} as their "
                                         f"router instead of {join_list(sorted(legit.routers))}, which would "
                                         "send all their traffic through that machine."))
            if diff_dns:
                attack.append(Point(2, f"It hands out DNS server {join_list(sorted(s.dns))} instead of "
                                       f"{join_list(sorted(legit.dns))}, so it controls which site each "
                                       "web address leads to."))
            harmful = bool(diff_router or diff_dns)
            if (harmful and s.reply_delays and legit.reply_delays
                    and median(s.reply_delays) < median(legit.reply_delays)):
                attack.append(Point(0.5, "It answers faster than the real server, so devices accept its "
                                         "offer first."))
            if not harmful:
                fault.append(Point(2.5, "It hands out the same router and DNS settings. This is typical of "
                                        "a home Wi-Fi router plugged in by mistake rather than an attacker."))
            if legit_known and harmful:
                attack.append(Point(0.5, f"{legit.server_id} matches the network's real gateway, so "
                                         f"{s.server_id} is the newcomer."))
            else:
                fault.append(Point(0.5, "Couldn't confirm which server is the official one."))
            signals.append(Signal(
                kind="rogue_dhcp", key=s.server_id,
                hosts=[s.server_id, *sorted(m for m in s.macs if m), legit.server_id],
                start=s.first_ts, end=ctx.end, frames=sorted(set(s.frames) | set(legit.frames[:20]))[:200],
                metrics={"rogue_server": s.server_id, "rogue_macs": sorted(m for m in s.macs if m),
                         "legit_server": legit.server_id, "legit_confirmed": legit_known,
                         "rogue_router": sorted(s.routers), "legit_router": sorted(legit.routers),
                         "rogue_dns": sorted(s.dns), "legit_dns": sorted(legit.dns),
                         "rogue_offers": s.offers, "rogue_acks": s.acks,
                         "clients_affected": len(s.clients)},
                attack_points=attack, fault_points=fault, severity="high"))

    unanswered = [(xid, v) for xid, v in ctx.dhcp.discovers.items()
                  if xid not in ctx.dhcp.answered_xids and ctx.end - v[0] >= 2]
    if len(unanswered) >= th.dhcp_no_response_min:
        macs = sorted({v[2] for _, v in unanswered})
        signals.append(Signal(
            kind="dhcp_no_response", key="dhcp", hosts=macs[:30],
            start=min(v[0] for _, v in unanswered), end=max(v[0] for _, v in unanswered),
            frames=sorted(v[1] for _, v in unanswered)[:200],
            metrics={"unanswered_requests": len(unanswered), "devices": macs[:30]},
            fault_points=[Point(2, f"{len(unanswered)} requests for an IP address got no reply, so "
                                   "these devices can't join the network.")],
            severity="high"))
    return signals
