"""Fault vs attack: weigh the evidence collected by detectors."""
from __future__ import annotations

from ..models import Signal, Verdict

ATTACK_MIN = 3.0        # need this much attack evidence to call it an attack
SUSPICIOUS_MIN = 1.5    # below this, attack hints are ignored


def classify(signal: Signal) -> tuple[Verdict, str, float, float]:
    a = sum(p.weight for p in signal.attack_points)
    f = sum(p.weight for p in signal.fault_points)
    if a >= ATTACK_MIN and a >= f + 1:
        verdict = Verdict.ATTACK
    elif a >= SUSPICIOUS_MIN and a >= f * 0.75:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.FAULT
    margin = abs(a - f) if verdict != Verdict.SUSPICIOUS else 0
    if verdict == Verdict.SUSPICIOUS:
        confidence = "low"
    elif margin >= 3:
        confidence = "high"
    elif margin >= 1.5:
        confidence = "medium"
    else:
        confidence = "low"
    return verdict, confidence, round(a, 2), round(f, 2)
