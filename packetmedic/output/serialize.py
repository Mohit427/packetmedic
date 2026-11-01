"""Report -> plain dict / JSON."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .. import __version__
from ..models import Incident, Report


def _iso(ts: float) -> str | None:
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds")
    except (OverflowError, OSError, ValueError):
        return None


def incident_to_dict(inc: Incident, t0: float) -> dict:
    e = inc.explanation
    return {
        "id": inc.id,
        "kind": inc.kind,
        "verdict": inc.verdict.value,
        "confidence": inc.confidence,
        "severity": inc.severity,
        "title": e.title if e else inc.kind,
        "summary": e.summary if e else "",
        "why_it_matters": e.why_it_matters if e else "",
        "likely_cause": e.likely_cause if e else "",
        "next_steps": e.next_steps if e else [],
        "wireshark_filter": e.wireshark_filter if e else "",
        "hosts": inc.hosts,
        "start_offset_s": round(inc.start - t0, 3) if inc.start else 0,
        "end_offset_s": round(inc.end - t0, 3) if inc.end else 0,
        "start_time": _iso(inc.start),
        "evidence_frames": inc.frames,
        "reasoning": {
            "attack_score": inc.attack_score,
            "fault_score": inc.fault_score,
            "points_for_attack": [{"weight": p.weight, "text": p.text} for p in inc.attack_points],
            "points_for_fault": [{"weight": p.weight, "text": p.text} for p in inc.fault_points],
        },
        "explains_symptoms": [{"kind": s.kind, "hosts": s.hosts, "frames": s.frames[:20]}
                              for s in inc.symptoms],
        "metrics": inc.metrics,
    }


def report_to_dict(r: Report) -> dict:
    t0 = r.start_ts
    return {
        "tool": f"PacketMedic {__version__}",
        "file": {"name": r.file_name, "size_bytes": r.file_size, "format": r.capture_format},
        "capture": {"packets": r.packets, "malformed_skipped": r.malformed,
                    "start_time": _iso(r.start_ts), "end_time": _iso(r.end_ts),
                    "duration_s": round(r.duration, 3), "hosts_seen": r.hosts_seen,
                    "protocols": r.protocols},
        "health": {"score": r.health_score, "label": r.health_label},
        "counts": {v: sum(1 for i in r.incidents if i.verdict.value == v)
                   for v in ("ATTACK", "SUSPICIOUS", "FAULT")},
        "incidents": [incident_to_dict(i, t0) for i in r.incidents],
        "warnings": r.warnings,
        "analysis_seconds": r.analysis_seconds,
    }


def _default(o):
    if isinstance(o, (set, tuple)):
        return list(o)
    return str(o)


def to_json(data: dict) -> str:
    return json.dumps(data, indent=2, default=_default, ensure_ascii=True)
