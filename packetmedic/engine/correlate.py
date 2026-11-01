"""Turn raw Signals into Incidents.

1. Merge signals of the same kind about the same thing.
2. Classify each one (fault / attack / suspicious).
3. Root-cause folding: when one incident explains another (an MTU problem
   explains retransmissions, a port scan explains a pile of resets...), the
   explained one is attached as a *symptom* instead of being reported as a
   separate alarm. Fewer, truer alerts.
"""
from __future__ import annotations

from typing import Callable

from ..models import Incident, Signal, Verdict
from .verdict import classify

SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
VERDICT_RANK = {Verdict.ATTACK: 0, Verdict.SUSPICIOUS: 1, Verdict.FAULT: 2}


def _merge(signals: list[Signal]) -> Signal:
    if len(signals) == 1:
        return signals[0]
    base = signals[0]
    for s in signals[1:]:
        base.hosts = list(dict.fromkeys(base.hosts + s.hosts))
        base.frames = sorted(set(base.frames) | set(s.frames))[:200]
        base.start, base.end = min(base.start, s.start), max(base.end, s.end)
        base.attack_points += [p for p in s.attack_points if p.text not in {q.text for q in base.attack_points}]
        base.fault_points += [p for p in s.fault_points if p.text not in {q.text for q in base.fault_points}]
        if SEVERITY_RANK[s.severity] < SEVERITY_RANK[base.severity]:
            base.severity = s.severity
        for k, v in s.metrics.items():
            base.metrics.setdefault(k, v)
    return base


def _overlap(cause: Incident, sym: Incident, need: int = 2) -> bool:
    shared = set(cause.hosts) & set(sym.hosts)
    return len(shared) >= min(need, len(set(sym.hosts)))


# (cause kind, required cause verdicts or None, symptom kinds, predicate)
FoldRule = tuple[str, set | None, set[str], Callable[[Incident, Incident], bool]]
FOLD_RULES: list[FoldRule] = [
    ("mtu_mismatch", None, {"tcp_retransmissions", "high_latency"}, _overlap),
    ("port_scan", None, {"tcp_refused", "tcp_unreachable", "tcp_reset_midstream"},
     lambda c, s: c.metrics.get("scanner") in s.hosts),
    ("arp_conflict", {Verdict.ATTACK, Verdict.SUSPICIOUS}, {"tcp_retransmissions", "high_latency"},
     lambda c, s: bool(set(c.metrics.get("also_claims", []) + [c.metrics.get("ip")]) & set(s.hosts))),
    ("rogue_dhcp", None, {"dns_spoof"},
     lambda c, s: bool({c.metrics.get("rogue_server"), *c.metrics.get("rogue_dns", [])} & set(s.hosts))),
    ("dns_failure", None, {"dns_slow", "dns_nxdomain"},
     lambda c, s: c.metrics.get("server") in s.hosts),
    # packet loss to a server also explains slow responses from that same server
    ("tcp_retransmissions", None, {"high_latency"},
     lambda c, s: c.metrics.get("server") == s.metrics.get("server")),
]


def correlate(signals: list[Signal]) -> list[Incident]:
    groups: dict[tuple[str, str], list[Signal]] = {}
    for s in signals:
        groups.setdefault((s.kind, s.key), []).append(s)

    incidents: list[Incident] = []
    for sigs in groups.values():
        s = _merge(sigs)
        verdict, conf, a, f = classify(s)
        incidents.append(Incident(
            id="", kind=s.kind, verdict=verdict, confidence=conf, severity=s.severity,
            hosts=s.hosts, start=s.start, end=s.end, frames=s.frames, metrics=s.metrics,
            attack_points=s.attack_points, fault_points=s.fault_points,
            attack_score=a, fault_score=f))

    folded: set[int] = set()
    for cause_kind, verdicts, sym_kinds, pred in FOLD_RULES:
        for cause in incidents:
            if cause.kind != cause_kind or id(cause) in folded:
                continue
            if verdicts and cause.verdict not in verdicts:
                continue
            for sym in incidents:
                if sym is cause or sym.kind not in sym_kinds or id(sym) in folded:
                    continue
                if pred(cause, sym):
                    folded.add(id(sym))
                    cause.symptoms.append(Signal(
                        kind=sym.kind, key="", hosts=sym.hosts, start=sym.start, end=sym.end,
                        frames=sym.frames, metrics=sym.metrics))
                    cause.frames = sorted(set(cause.frames) | set(sym.frames[:50]))[:250]

    final = [i for i in incidents if id(i) not in folded]
    final.sort(key=lambda i: (VERDICT_RANK[i.verdict], SEVERITY_RANK[i.severity], i.start))
    for n, inc in enumerate(final, 1):
        inc.id = f"PM-{n:03d}"
    return final
