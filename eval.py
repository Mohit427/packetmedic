"""Measure PacketMedic against the labeled sample captures.

    python eval.py

For every sample, compares the (finding kind, verdict) pairs PacketMedic
reports against samples/truth.json and prints precision / recall plus how
often the fault-vs-attack verdict was right.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from packetmedic.analyzer import analyze
from packetmedic.ingest.validator import InputError

ROOT = Path(__file__).resolve().parent
SAMPLES = ROOT / "samples" / "pcaps"


def main() -> int:
    truth = json.loads((ROOT / "samples" / "truth.json").read_text())
    con = Console(highlight=False)
    t = Table(title="PacketMedic detection accuracy on labeled samples", header_style="bold")
    for col in ("Sample", "Expected", "Found", "Result"):
        t.add_column(col)
    tp = fp = fn = 0
    verdict_right = verdict_total = 0
    all_ok = True
    for name, expected in truth.items():
        path = SAMPLES / name
        if expected == "REJECT":
            try:
                analyze(path)
                t.add_row(name, "reject file", "accepted", "[red]FAIL[/]")
                all_ok = False
            except InputError:
                t.add_row(name, "reject file", "rejected", "[green]OK[/]")
            continue
        rep = analyze(path)
        exp = {(e["kind"], e["verdict"]) for e in expected}
        got = {(i.kind, i.verdict.value) for i in rep.incidents}
        exp_kinds = {k for k, _ in exp}
        got_kinds = {k for k, _ in got}
        tp += len(exp_kinds & got_kinds)
        fp += len(got_kinds - exp_kinds)
        fn += len(exp_kinds - got_kinds)
        for k, v in exp:
            if k in got_kinds:
                verdict_total += 1
                verdict_right += int((k, v) in got)
        ok = exp == got
        all_ok &= ok
        fmt = lambda s: "\n".join(f"{k} ({v})" for k, v in sorted(s)) or "-"   # noqa: E731
        t.add_row(name, fmt(exp), fmt(got), "[green]OK[/]" if ok else "[red]MISMATCH[/]")
    con.print(t)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    con.print(f"Detection precision: [bold]{precision:.0%}[/]  (false alarms: {fp})")
    con.print(f"Detection recall:    [bold]{recall:.0%}[/]  (missed: {fn})")
    con.print(f"Fault-vs-attack verdict accuracy: [bold]{verdict_right}/{verdict_total}[/]")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
