"""Network Health Score: one number a beginner can read at a glance."""
from __future__ import annotations

from ..models import Incident, Verdict

PENALTY = {
    Verdict.ATTACK: {"high": 35, "medium": 25, "low": 12},
    Verdict.SUSPICIOUS: {"high": 15, "medium": 10, "low": 5},
    Verdict.FAULT: {"high": 20, "medium": 10, "low": 4},
}


def health_score(incidents: list[Incident]) -> tuple[int, str]:
    score = 100
    for inc in incidents:
        score -= PENALTY[inc.verdict][inc.severity]
    score = max(0, score)
    if any(i.verdict == Verdict.ATTACK for i in incidents):
        label = "Under attack"
    elif score >= 90 and all(i.severity == "low" for i in incidents):
        label = "Healthy"
    elif score >= 85:
        label = "Minor issues"
    elif score >= 70:
        label = "Minor issues"
    elif score >= 40:
        label = "Degraded"
    else:
        label = "Critical"
    return score, label
