"""The full pipeline: ingest -> track -> detect -> correlate -> explain -> score."""
from __future__ import annotations

import os
import time
from pathlib import Path

from .config import DEFAULT_SETTINGS, Settings
from .detectors import DETECTORS
from .engine.correlate import correlate
from .engine.score import health_score
from .explain.templates import explain
from .ingest.decode import SUPPORTED_LINKTYPES, dissect, to_record, wifi_to_ethernet
from .util import BoundedDict
from .ingest.pcapfile import iter_raw_frames
from .ingest.validator import validate_capture
from .models import Report, Signal
from .trackers.context import Context


def analyze(path: str | os.PathLike, settings: Settings = DEFAULT_SETTINGS,
            display_name: str | None = None) -> Report:
    """Analyse one capture file. Raises InputError for files that are rejected up front;
    everything that goes wrong *inside* the file becomes a warning, never a crash."""
    t0 = time.perf_counter()
    path = str(path)
    fmt = validate_capture(path, settings.limits)
    warnings: list[str] = []
    ctx = Context(settings)
    malformed = 0
    unsupported: set[int] = set()
    deadline = t0 + settings.limits.max_seconds

    recent: BoundedDict = BoundedDict(4096)   # payload hash -> last time seen
    duplicates = 0
    for n, frame in enumerate(iter_raw_frames(path, settings.limits, warnings)):
        if frame.linktype not in SUPPORTED_LINKTYPES:
            unsupported.add(frame.linktype)
            continue
        # Capture duplicates: the exact same packet (same IP ID, same bytes)
        # recorded twice within 50 ms - pktmon logging one packet at two points,
        # or an 802.11 link-layer retry. A real TCP retransmission is a NEW IP
        # packet (different IP ID), so it is never removed by this check.
        eth = wifi_to_ethernet(frame.data) if frame.linktype in (1, 105) else None
        key = hash((eth or frame.data)[12:] if (eth or frame.linktype == 1) else frame.data)
        last = recent.get(key)
        recent[key] = frame.ts
        if last is not None and 0 <= frame.ts - last <= 0.05:
            duplicates += 1
            continue
        try:
            rec = to_record(dissect(frame), frame)
        except Exception:
            malformed += 1
            continue
        try:
            ctx.observe(rec)
        except Exception:      # a tracker bug must never take down the whole run
            malformed += 1
        if n % 5000 == 0 and time.perf_counter() > deadline:
            warnings.append(f"Time limit of {settings.limits.max_seconds:.0f}s reached; analysed the first "
                            f"{n:,} packets only.")
            break

    if unsupported:
        warnings.append(f"Skipped packets with unsupported link type(s): {sorted(unsupported)}.")
    if duplicates:
        warnings.append(f"Ignored {duplicates} duplicate copies of packets recorded twice by the capture tool.")
    if malformed:
        warnings.append(f"{malformed} malformed packet(s) could not be decoded and were skipped.")
    if ctx.flows.flows.evicted:
        warnings.append(f"Very large capture: {ctx.flows.flows.evicted:,} old TCP conversations were "
                        "dropped from memory; results for them may be incomplete.")

    signals: list[Signal] = []
    for detector in DETECTORS:
        try:
            signals.extend(detector(ctx))
        except Exception as exc:  # isolate detector failures
            warnings.append(f"Detector '{detector.__name__}' failed ({type(exc).__name__}); "
                            "its results are missing.")

    incidents = correlate(signals)
    for inc in incidents:
        try:
            inc.explanation = explain(inc)
        except Exception as exc:
            warnings.append(f"Could not build explanation for {inc.id} ({type(exc).__name__}).")
    score, label = health_score(incidents)

    return Report(
        file_name=display_name or Path(path).name,
        file_size=Path(path).stat().st_size,
        capture_format=fmt,
        packets=ctx.general.packets + malformed,
        malformed=malformed,
        warnings=warnings,
        start_ts=ctx.start,
        end_ts=ctx.end,
        protocols=dict(ctx.general.protocols.most_common()),
        hosts_seen=len(ctx.general.hosts),
        incidents=incidents,
        health_score=score,
        health_label=label,
        analysis_seconds=round(time.perf_counter() - t0, 3),
    )
