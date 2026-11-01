"""DNS fault detectors (timeouts, errors, slowness) and DNS spoofing/hijack detection."""
from __future__ import annotations

from collections import defaultdict

from ..models import Point, Signal
from ..trackers.context import Context
from ..util import fmt_ms, is_private, is_public, join_list, median, plural, shannon_entropy

INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".corp", ".home", ".home.arpa", ".intranet",
                     ".localdomain", ".in-addr.arpa", ".ip6.arpa")


def detect_dns_failures(ctx: Context) -> list[Signal]:
    th = ctx.settings.thresholds
    end = ctx.end
    timeouts: dict[str, list] = defaultdict(list)
    for q in ctx.dns.queries.values():
        if not q.responses and end - q.ts >= th.dns_timeout_s:
            timeouts[q.server].append(q)

    port_closed: dict[str, list] = defaultdict(list)
    for ev in ctx.icmp.unreachable:
        if ev.inner and ev.inner[2] == "UDP" and ev.inner[4] == 53 and ev.code == 3:
            port_closed[ev.inner[1]].append(ev)

    signals = []
    for server, st in ctx.dns.servers.items():
        if st.queries < th.dns_fail_min_queries:
            continue
        lost = timeouts.get(server, [])
        t_ratio = len(lost) / st.queries
        sf_ratio = (st.servfail + st.refused) / st.queries
        if t_ratio >= th.dns_fail_ratio or sf_ratio >= th.dns_fail_ratio:
            fault: list[Point] = []
            if lost:
                fault.append(Point(2, f"{len(lost)} of {st.queries} lookups sent to {server} never got "
                                      "an answer."))
            if st.servfail + st.refused:
                fault.append(Point(2, f"{server} answered {st.servfail + st.refused} lookups with an "
                                      "error (SERVFAIL/REFUSED). It is reachable but can't resolve names."))
            closed = port_closed.get(server, [])
            if closed:
                fault.append(Point(1, f"{server} replied 'port unreachable'. The machine is up but "
                                      "its DNS service is not running."))
            ratio = max(t_ratio, sf_ratio)
            frames = sorted({f for q in lost[:40] for f in q.frames} | set(st.frames[:40])
                            | {e.frame for e in closed[:20]})
            times = [q.ts for q in lost] or [ctx.start]
            signals.append(Signal(
                kind="dns_failure", key=server, hosts=[server, *sorted(st.clients)][:30],
                start=min(times), end=max(times), frames=frames[:200],
                metrics={"server": server, "queries": st.queries, "unanswered": len(lost),
                         "errors": st.servfail + st.refused, "failure_rate": round(ratio, 3),
                         "service_down": bool(closed),
                         "example_names": sorted({q.qname for q in lost})[:8],
                         "clients": sorted(st.clients)[:30]},
                fault_points=fault, severity="high" if ratio >= 0.8 else "medium"))
            continue

        if st.latencies and len(st.latencies) >= th.latency_min_samples:
            med = median(st.latencies)
            if med >= th.dns_slow_s:
                signals.append(Signal(
                    kind="dns_slow", key=server, hosts=[server, *sorted(st.clients)][:30],
                    start=ctx.start, end=ctx.end, frames=sorted(st.frames)[:200],
                    metrics={"server": server, "median_ms": round(med * 1000),
                             "samples": len(st.latencies)},
                    fault_points=[Point(2, f"{server} takes about {fmt_ms(med)} to answer each lookup "
                                           "(under 50 ms is normal), so every website feels slow to start loading.")],
                    severity="medium"))

    # NXDOMAIN (name does not exist)
    nx = [q for q in ctx.dns.answered_queries if q.responses and q.responses[0].rcode == 3]
    names = sorted({q.qname for q in nx})
    if len(nx) >= th.nxdomain_min and len(names) >= 3:
        labels = [n.split(".")[0] for n in names if n]
        long_random = [lab for lab in labels if len(lab) >= 10 and shannon_entropy(lab) >= 3.3]
        attack: list[Point] = []
        fault = [Point(1, "Lookups for names that don't exist usually come from mistyped addresses, "
                          "stale bookmarks or a misconfigured search domain.")]
        if len(long_random) >= 10 and len(long_random) / max(1, len(labels)) > 0.5:
            attack.append(Point(2, f"{len(long_random)} of the missing names look random "
                                   f"(e.g. {join_list(long_random[:3])}). Malware generates names like "
                                   "these to find its control server."))
        clients = sorted({q.client for q in nx})
        signals.append(Signal(
            kind="dns_nxdomain", key="nxdomain", hosts=clients[:30],
            start=min(q.ts for q in nx), end=max(q.ts for q in nx),
            frames=sorted({f for q in nx[:80] for f in q.frames})[:200],
            metrics={"failed_lookups": len(nx), "distinct_names": len(names),
                     "example_names": names[:10], "clients": clients[:30]},
            attack_points=attack, fault_points=fault, severity="low" if not attack else "medium"))
    return signals


def _modal_ttl(ctx: Context, responder: str) -> tuple[int | None, int]:
    c = ctx.dns.responder_ttls.get(responder)
    if not c:
        return None, 0
    ttl, n = c.most_common(1)[0]
    return ttl, sum(c.values())


def detect_dns_spoofing(ctx: Context) -> list[Signal]:
    th = ctx.settings.thresholds
    attack: list[Point] = []
    fault: list[Point] = []
    frames: set[int] = set()
    names: set[str] = set()
    hosts: set[str] = set()
    times: list[float] = []
    forged_ips: set[str] = set()

    def note(q, *resps):
        names.add(q.qname)
        hosts.update([q.client, q.server])
        frames.update(q.frames[:10])
        for r in resps:
            frames.add(r.frame)
            times.append(r.ts)

    # 1. two different answers to one question - the classic race of a spoofer
    for q, first, second in ctx.dns.conflicts[:50]:
        note(q, first, second)
        a1 = join_list([a for a, _ in first.answers]) or "no address"
        a2 = join_list([a for a, _ in second.answers]) or "no address"
        attack.append(Point(3, f"Two different answers arrived for the same lookup of {q.qname}: "
                               f"{a1} (frame {first.frame}) and {a2} (frame {second.frame}). A real "
                               "DNS server answers once. A forged answer was raced in."))
        # which one is fake? the one whose hop count doesn't match the server's usual
        for r in (first, second):
            mode, n = _modal_ttl(ctx, r.src)
            if mode is not None and r.ttl is not None and abs(r.ttl - mode) > th.dns_ttl_tolerance:
                forged_ips.update(a for a, _ in r.answers)

    # 2. answer from someone we didn't ask
    for q, r in ctx.dns.mismatched[:50]:
        note(q, r)
        attack.append(Point(2, f"The answer for {q.qname} came from {r.src}, but the question was "
                               f"sent to {q.server}."))

    # 3. hop-count (IP TTL) anomaly against the server's normal packets
    ttl_flags = 0
    for q in ctx.dns.answered_queries:
        r = q.responses[0]
        mode, n = _modal_ttl(ctx, r.src)
        if mode is None or n < 3 or r.ttl is None:
            continue
        if abs(r.ttl - mode) > th.dns_ttl_tolerance:
            ttl_flags += 1
            note(q, r)
            forged_ips.update(a for a, _ in r.answers)
    if ttl_flags:
        attack.append(Point(1.5, f"{plural(ttl_flags, 'answer')} claiming to be from the DNS server "
                                 "had a different hop count (IP TTL) from its other answers, so "
                                 "they came from a different machine, probably closer to you."))

    # 4. internet name pointed at a local address
    private_hits = []
    for q in ctx.dns.answered_queries:
        lname = q.qname.lower()
        if not lname or lname.endswith(INTERNAL_SUFFIXES) or "." not in lname:
            continue
        for r in q.responses:
            for addr, _ in r.answers:
                if is_private(addr) and is_public(q.server) or (is_private(addr) and addr in forged_ips):
                    private_hits.append((q, r, addr))
    if private_hits:
        for q, r, _ in private_hits[:30]:
            note(q, r)
        examples = join_list(sorted({f"{q.qname} -> {a}" for q, _, a in private_hits}), 3)
        attack.append(Point(1.5, f"Public website names were pointed at a local address ({examples}). "
                                 "Victims get sent to a machine inside your own network."))
        fault.append(Point(0.5, "Some offices run internal DNS that legitimately maps names to "
                                "local servers (split-horizon DNS)."))

    # 5. answers nobody asked for
    if len(ctx.dns.unsolicited) >= 3:
        for r in ctx.dns.unsolicited[:30]:
            frames.add(r.frame)
            times.append(r.ts)
        attack.append(Point(1, f"{len(ctx.dns.unsolicited)} DNS answers arrived that match no "
                               "question. Someone may be spraying forged answers hoping one is accepted."))
        fault.append(Point(0.5, "Answers can also look unasked-for if the capture started after "
                                "the question was sent."))

    if not attack:
        return []
    if not ctx.dns.conflicts and not ctx.dns.mismatched and ttl_flags == 0:
        fault.append(Point(1, "No direct proof of forgery (no conflicting or mismatched answers) "
                              "was found."))
    return [Signal(
        kind="dns_spoof", key="dns", hosts=sorted(hosts)[:30],
        start=min(times) if times else ctx.start, end=max(times) if times else ctx.end,
        frames=sorted(frames)[:200],
        metrics={"names": sorted(names)[:20], "conflicting_answers": len(ctx.dns.conflicts),
                 "mismatched_sources": len(ctx.dns.mismatched), "ttl_anomalies": ttl_flags,
                 "forged_addresses": sorted(forged_ips)[:20],
                 "unsolicited_answers": len(ctx.dns.unsolicited)},
        attack_points=attack, fault_points=fault, severity="high")]
