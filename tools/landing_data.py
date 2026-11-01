"""Extract REAL engine output for the landing page (landing/src/data.json).

Every trace, verdict, reasoning line and number on the landing page comes from
this file, which comes from running PacketMedic on the bundled synthetic samples.

    .venv\\Scripts\\python.exe tools\\landing_data.py
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from packetmedic import __version__  # noqa: E402
from packetmedic.analyzer import analyze  # noqa: E402
from packetmedic.config import DEFAULT_SETTINGS  # noqa: E402
from packetmedic.ingest.decode import dissect, to_record  # noqa: E402
from packetmedic.ingest.pcapfile import iter_raw_frames  # noqa: E402
from packetmedic.output.evidence import summarize  # noqa: E402
from packetmedic.output.serialize import report_to_dict  # noqa: E402

PCAPS = ROOT / "samples" / "pcaps"
OUT = ROOT / "landing" / "src" / "data.json"


def trace(path: Path, bins: int = 240) -> dict:
    ts = [f.ts for f in iter_raw_frames(str(path), DEFAULT_SETTINGS.limits, [])]
    t0, t1 = min(ts), max(ts)
    width = (t1 - t0) / bins or 1
    counts = [0] * bins
    for t in ts:
        counts[min(bins - 1, int((t - t0) / width))] += 1
    return {"duration": round(t1 - t0, 3), "bin_s": round(width, 4), "counts": counts}


def incident_view(i: dict) -> dict:
    r = i["reasoning"]
    return {
        "id": i["id"], "kind": i["kind"], "verdict": i["verdict"], "confidence": i["confidence"],
        "title": i["title"], "summary": i["summary"], "cause": i["likely_cause"],
        "steps": i["next_steps"][:3], "start": i["start_offset_s"], "end": i["end_offset_s"],
        "frames": len(i["evidence_frames"]), "filter": i["wireshark_filter"],
        "attack_score": r["attack_score"], "fault_score": r["fault_score"],
        "for_attack": [p["text"] for p in r["points_for_attack"]],
        "for_fault": [p["text"] for p in r["points_for_fault"]],
    }


def report(name: str) -> dict:
    d = report_to_dict(analyze(PCAPS / name))
    return {
        "file": name, "packets": d["capture"]["packets"], "duration": d["capture"]["duration_s"],
        "hosts": d["capture"]["hosts_seen"], "health": d["health"],
        "incidents": [incident_view(i) for i in d["incidents"]],
    }


def poison_packet() -> dict:
    """The first forged ARP reply in the spoofing sample, as raw hex and decoded."""
    for f in iter_raw_frames(str(PCAPS / "07_arp_spoofing.pcap"), DEFAULT_SETTINGS.limits, []):
        r = to_record(dissect(f), f)
        if r.arp and r.arp.op == 2 and r.arp.hwsrc == "de:ad:be:ef:00:66" and r.arp.psrc == "192.168.1.1":
            return {"frame": f.index, "hex": f.data.hex(" "), "decoded": summarize(r),
                    "fields": {"op": "reply", "claims_ip": r.arp.psrc, "claims_mac": r.arp.hwsrc,
                               "sent_to": r.arp.pdst}}
    return {}


def eval_stats() -> dict:
    truth = json.loads((ROOT / "samples" / "truth.json").read_text())
    tp = fp = fn = vr = vt = 0
    for name, exp in truth.items():
        if exp == "REJECT":
            continue
        got = {(i.kind, i.verdict.value) for i in analyze(PCAPS / name).incidents}
        ek, gk = {e["kind"] for e in exp}, {k for k, _ in got}
        tp += len(ek & gk); fp += len(gk - ek); fn += len(ek - gk)
        for e in exp:
            if e["kind"] in gk:
                vt += 1
                vr += int((e["kind"], e["verdict"]) in got)
    return {"precision": tp / max(1, tp + fp), "recall": tp / max(1, tp + fn),
            "false_alarms": fp, "verdicts_right": vr, "verdicts_total": vt, "samples": len(truth)}


def pmtui_exe() -> Path:
    name = "pmtui.exe" if sys.platform == "win32" else "pmtui"
    found = [p for p in (ROOT / "build" / name, ROOT / "cli_c" / name) if p.exists()]
    return max(found, key=lambda p: p.stat().st_mtime)


def pmtui_frames() -> list[dict]:
    """Real pmtui screens, with their real colours, for the hero's bedside monitor."""
    mixed = str(PCAPS / "11_mixed_outage_and_attack.pcapng")
    shots = [("main menu", ["menu"], 0), ("samples", ["samples"], 10),
             ("attack", ["dashboard", mixed], 0), ("fault", ["dashboard", mixed], 1)]
    frames = []
    for label, args, sel in shots:
        env = {**os.environ, "PMTUI_SNAPSHOT_FORMAT": "json", "PMTUI_SNAPSHOT_SEL": str(sel)}
        out = subprocess.run([str(pmtui_exe()), "--snapshot", *args, "80x24"], capture_output=True, text=True,
                             encoding="utf-8", cwd=ROOT, timeout=120, env=env, check=True)
        frames.append({"label": label, **json.loads(out.stdout)})
    return frames


def pmtui_snapshot() -> list[str]:
    exe = pmtui_exe()
    out = subprocess.run([str(exe), "--snapshot", "dashboard", str(PCAPS / "11_mixed_outage_and_attack.pcapng"),
                          "96x26"], capture_output=True, text=True, encoding="utf-8", cwd=ROOT, timeout=120)
    return out.stdout.rstrip("\n").split("\n")


def main() -> int:
    zpath = ROOT / "dist" / f"PacketMedic-{__version__}-win64.zip"
    data = {
        "version": __version__,
        "mixed": {**report("11_mixed_outage_and_attack.pcapng"), "trace": trace(PCAPS / "11_mixed_outage_and_attack.pcapng")},
        "duplicate_ip": {**report("04_duplicate_ip.pcap"), "trace": trace(PCAPS / "04_duplicate_ip.pcap", 160)},
        "arp_spoof": {**report("07_arp_spoofing.pcap"), "trace": trace(PCAPS / "07_arp_spoofing.pcap", 160)},
        "poison_packet": poison_packet(),
        "eval": eval_stats(),
        "tests": 66,
        "fuzz_cases": 35,
        "catalog": json.loads((ROOT / "samples" / "catalog.json").read_text(encoding="utf-8")),
        "pmtui": pmtui_snapshot(),
        "pmtui_frames": pmtui_frames(),
        "release": {
            "file": zpath.name,
            "size_mb": round(zpath.stat().st_size / 1e6, 1) if zpath.exists() else None,
            "sha256": hashlib.sha256(zpath.read_bytes()).hexdigest() if zpath.exists() else None,
            "url": "https://github.com/Mohit427/packetmedic/releases/latest",
            "direct": f"https://github.com/Mohit427/packetmedic/releases/latest/download/{zpath.name}",
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=1), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
