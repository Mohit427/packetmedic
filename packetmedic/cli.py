"""Command-line interface.

    python -m packetmedic analyze capture.pcap
    python -m packetmedic analyze capture.pcap --html report.html --json report.json --anonymize
    python -m packetmedic analyze capture.pcap --evidence-dir evidence/
"""
from __future__ import annotations

import argparse
import os
import sys
from dataclasses import replace
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .analyzer import analyze
from .config import DEFAULT_SETTINGS
from .ingest.validator import InputError
from .output.anonymize import anonymize_report
from .output.evidence import export_evidence_pcap
from .output.html_report import render_html
from .output.serialize import report_to_dict, to_json

COLORS = {"ATTACK": "bold red", "SUSPICIOUS": "bold yellow", "FAULT": "bold blue"}


def _print_report(con: Console, d: dict, verbose: bool) -> None:
    e = escape   # every dynamic string is escaped: packet data must never become Rich markup
    h = d["health"]
    color = "red" if h["label"] == "Under attack" else "green" if h["score"] >= 90 else \
        "yellow" if h["score"] >= 60 else "red"
    cap = d["capture"]
    con.print(Panel.fit(
        f"[bold]{e(d['file']['name'])}[/]  ({d['file']['format']}, {cap['packets']:,} packets, "
        f"{cap['duration_s']:.1f} s, {cap['hosts_seen']} hosts)\n"
        f"Network health: [bold {color}]{h['score']}/100 - {e(h['label'])}[/]   "
        f"[red]{d['counts']['ATTACK']} attack(s)[/]  [yellow]{d['counts']['SUSPICIOUS']} suspicious[/]  "
        f"[blue]{d['counts']['FAULT']} fault(s)[/]",
        title=f"PacketMedic {__version__}", border_style=color))
    for w in d["warnings"]:
        con.print(f"[yellow]! {e(w)}[/]")
    if not d["incidents"]:
        con.print("[green]No faults or attacks found in this capture.[/]")
        return
    t = Table(show_lines=False, header_style="bold")
    t.add_column("ID")
    t.add_column("Verdict")
    t.add_column("Finding")
    t.add_column("Conf.")
    t.add_column("When (s)")
    for i in d["incidents"]:
        t.add_row(i["id"], f"[{COLORS[i['verdict']]}]{i['verdict']}[/]", e(i["title"]), i["confidence"],
                  f"{i['start_offset_s']:.1f}-{i['end_offset_s']:.1f}")
    con.print(t)
    for i in d["incidents"]:
        con.rule(f"[{COLORS[i['verdict']]}]{i['id']}  {i['verdict']}[/]  {e(i['title'])}")
        con.print(e(i["summary"]))
        con.print(f"[bold]Why it matters:[/] {e(i['why_it_matters'])}")
        con.print(f"[bold]Likely cause:[/] {e(i['likely_cause'])}")
        con.print("[bold]What to do:[/]")
        for s in i["next_steps"]:
            con.print(f"  - {e(s)}")
        rs = i["reasoning"]
        con.print(f"[bold]Reasoning[/] (attack {rs['attack_score']} vs fault {rs['fault_score']}):")
        for p in rs["points_for_attack"]:
            con.print(f"  [red]![/] {e(p['text'])}")
        for p in rs["points_for_fault"]:
            con.print(f"  [green]+[/] {e(p['text'])}")
        frames = i["evidence_frames"]
        shown = ", ".join(map(str, frames[: (60 if verbose else 15)]))
        more = f" ... ({len(frames)} total)" if len(frames) > (60 if verbose else 15) else ""
        con.print(f"[bold]Evidence frames:[/] {shown}{more}")
        con.print(f"[bold]Wireshark filter:[/] [cyan]{e(i['wireshark_filter'])}[/]")
        con.print()


def _safe_output_path(p: str) -> Path:
    path = Path(p).expanduser().resolve()
    if path.exists() and path.is_dir():
        raise InputError(f"Output path {p} is a directory.")
    return path


def cmd_analyze(args) -> int:
    con = Console(stderr=False, highlight=False)
    settings = DEFAULT_SETTINGS
    if args.max_mb:
        settings = replace(settings, limits=replace(settings.limits, max_file_bytes=int(args.max_mb * 1e6)))
    try:
        report = analyze(args.capture, settings)
    except InputError as exc:
        con.print(f"[red]Rejected:[/] {escape(str(exc))}")
        return 2
    data = report_to_dict(report)
    if args.anonymize:
        data = anonymize_report(data)

    if args.json == "-":
        sys.stdout.write(to_json(data) + "\n")
    else:
        if not args.quiet:
            _print_report(con, data, args.verbose)
        if args.json:
            _safe_output_path(args.json).write_text(to_json(data), encoding="utf-8")
            con.print(f"JSON report written to {escape(args.json)}")
    if args.html:
        _safe_output_path(args.html).write_text(render_html(data), encoding="utf-8")
        con.print(f"HTML report written to {escape(args.html)}")
    if args.evidence_dir:
        if args.anonymize:
            con.print("[yellow]Evidence pcaps contain raw packets and are not anonymized; skipped.[/]")
        else:
            out = Path(args.evidence_dir)
            out.mkdir(parents=True, exist_ok=True)
            for inc in report.incidents:
                target = out / f"{inc.id}_{inc.kind}.pcap"
                n = export_evidence_pcap(args.capture, inc.frames, str(target), settings)
                con.print(f"Evidence for {inc.id}: {n} packets -> {escape(str(target))}")
    return 1 if any(i.verdict.value == "ATTACK" for i in report.incidents) and args.fail_on_attack else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="packetmedic",
                                 description="Find faults and attacks in a packet capture and explain them.")
    ap.add_argument("--version", action="version", version=f"PacketMedic {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyse a .pcap / .pcapng file")
    a.add_argument("capture")
    a.add_argument("--json", metavar="FILE", help="write JSON report (use - for stdout)")
    a.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    a.add_argument("--evidence-dir", metavar="DIR", help="export each finding's packets as its own pcap")
    a.add_argument("--anonymize", action="store_true", help="mask IP and MAC addresses in reports")
    a.add_argument("--max-mb", type=float, help="maximum input file size in MB (default 512)")
    a.add_argument("--verbose", "-v", action="store_true", help="show more evidence frames")
    a.add_argument("--quiet", "-q", action="store_true", help="don't print the report to the terminal")
    a.add_argument("--fail-on-attack", action="store_true", help="exit code 1 if an attack is found (for CI)")
    a.set_defaults(func=cmd_analyze)
    args = ap.parse_args(argv)
    if os.name == "nt":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
