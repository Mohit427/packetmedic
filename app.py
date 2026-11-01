"""PacketMedic web dashboard.

    streamlit run app.py
"""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

from packetmedic import __version__
from packetmedic.analyzer import analyze
from packetmedic.ingest.validator import InputError, check_extension
from packetmedic.output.anonymize import anonymize_report
from packetmedic.output.evidence import export_evidence_pcap, packet_table
from packetmedic.output.html_report import render_html
from packetmedic.output.serialize import report_to_dict, to_json

ROOT = Path(__file__).resolve().parent
SAMPLES = ROOT / "samples" / "pcaps"
MAX_UPLOAD_MB = 200
COLORS = {"ATTACK": "#d32f2f", "SUSPICIOUS": "#ef8f00", "FAULT": "#1f6fd1"}
ICONS = {"ATTACK": "🚨", "SUSPICIOUS": "⚠️", "FAULT": "🔧"}

st.set_page_config(page_title="PacketMedic", page_icon="🩺", layout="wide")

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~$:])")


def md(text) -> str:
    """Escape Markdown so text taken from packets (e.g. DNS names) renders literally."""
    return _MD_SPECIAL.sub(r"\\\1", str(text))


# --------------------------------------------------------------------------- input
def _private_tempfile(data: bytes, suffix: str) -> str:
    fd, path = tempfile.mkstemp(prefix="packetmedic_", suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


def _cleanup_upload() -> None:
    old = st.session_state.pop("upload_path", None)
    if old and os.path.exists(old):
        try:
            os.remove(old)
        except OSError:
            pass


with st.sidebar:
    st.title("🩺 PacketMedic")
    st.caption(f"v{__version__} · finds faults & attacks in packet captures and explains them. "
               "Runs 100% offline: your capture never leaves this machine.")
    # A capture handed over by the pmtui terminal app. It is read from the process
    # environment only (never from the URL), so web visitors can't choose server files.
    cli_file = os.environ.get("PACKETMEDIC_FILE", "")
    cli_ok = bool(cli_file) and Path(cli_file).is_file()
    sources = (["From terminal (pmtui)"] if cli_ok else []) + ["Bundled sample", "Upload my own"]
    source = st.radio("Capture source", sources, index=0)
    capture_path, display_name = None, None
    if source == "From terminal (pmtui)":
        capture_path, display_name = cli_file, Path(cli_file).name[:120]
        st.caption(f"Opened from pmtui: {display_name}")
    elif source == "Bundled sample":
        samples = sorted(p.name for p in SAMPLES.glob("*") if p.is_file())
        if not samples:
            st.warning("No samples found. Run `python samples/generate.py` first.")
        else:
            default = samples.index("11_mixed_outage_and_attack.pcapng") if \
                "11_mixed_outage_and_attack.pcapng" in samples else 0
            choice = st.selectbox("Sample", samples, index=default)
            capture_path, display_name = str(SAMPLES / choice), choice
    else:
        up = st.file_uploader("Upload .pcap / .pcapng", type=["pcap", "pcapng", "cap"],
                              help=f"Max {MAX_UPLOAD_MB} MB. Analysed locally; the temporary copy is deleted.")
        if up is not None:
            try:
                check_extension(up.name)
                if up.size > MAX_UPLOAD_MB * 1024 * 1024:
                    raise InputError(f"File is larger than {MAX_UPLOAD_MB} MB.")
                data = up.getvalue()
                digest = hashlib.sha256(data).hexdigest()
                if st.session_state.get("upload_digest") != digest:
                    _cleanup_upload()
                    st.session_state.upload_path = _private_tempfile(data, Path(up.name).suffix.lower())
                    st.session_state.upload_digest = digest
                capture_path = st.session_state.upload_path
                display_name = Path(up.name).name[:120]
            except InputError as exc:
                st.error(str(exc))
    anonymize = st.toggle("Anonymize IP/MAC addresses", value=False,
                          help="Replace addresses with consistent fake ones in everything shown and exported.")
    st.divider()
    st.caption("Legend: 🚨 attack · ⚠️ suspicious · 🔧 fault")


@st.cache_data(show_spinner=False, max_entries=8)
def run_analysis(path: str, name: str, mtime: float):
    report = analyze(path, display_name=name)
    return report_to_dict(report), report.start_ts


if not capture_path:
    st.header("Upload a capture or pick a sample to begin")
    st.write("PacketMedic reads a packet capture, finds network **faults** (lost packets, DNS outages, "
             "duplicate IPs, MTU problems, slow links) and **attacks** (port scans, ARP spoofing, DNS "
             "hijacking, rogue DHCP), tells you which is which, and explains each one in plain language "
             "with the evidence packets.")
    st.stop()

try:
    with st.spinner("Analysing capture…"):
        data, start_ts = run_analysis(capture_path, display_name, os.path.getmtime(capture_path))
except InputError as exc:
    st.error(f"This file was rejected: {exc}")
    st.stop()

view = anonymize_report(data) if anonymize else data

# --------------------------------------------------------------------------- header
h, cap, counts = view["health"], view["capture"], view["counts"]
st.subheader(md(view["file"]["name"]))
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Network health", f"{h['score']}/100", h["label"], delta_color="off")
c2.metric("🚨 Attacks", counts["ATTACK"])
c3.metric("⚠️ Suspicious", counts["SUSPICIOUS"])
c4.metric("🔧 Faults", counts["FAULT"])
c5.metric("Packets", f"{cap['packets']:,}", f"{cap['duration_s']:.1f} s · {cap['hosts_seen']} hosts",
          delta_color="off")
for w in view["warnings"]:
    st.warning(w)

d1, d2, _ = st.columns([1, 1, 4])
d1.download_button("⬇ HTML report", render_html(view), file_name="packetmedic_report.html", mime="text/html")
d2.download_button("⬇ JSON report", to_json(view), file_name="packetmedic_report.json", mime="application/json")

incidents = view["incidents"]
if not incidents:
    st.success("No faults or attacks found. This network traffic looks healthy.")
    st.stop()

# --------------------------------------------------------------------------- timeline
st.markdown("#### Timeline")
fig = go.Figure()
for i in reversed(incidents):
    dur = max(i["end_offset_s"] - i["start_offset_s"], cap["duration_s"] * 0.006 or 0.1)
    fig.add_trace(go.Bar(
        x=[dur], base=[i["start_offset_s"]], y=[f"{i['id']} {ICONS[i['verdict']]}"], orientation="h",
        marker_color=COLORS[i["verdict"]], showlegend=False,
        hovertemplate=f"{i['id']} · {i['verdict']}<br>{i['title'][:80]}<br>"
                      f"{i['start_offset_s']:.1f}s → {i['end_offset_s']:.1f}s<extra></extra>"))
fig.update_layout(height=60 + 38 * len(incidents), margin=dict(l=10, r=10, t=10, b=30),
                  xaxis_title="seconds since capture start", bargap=0.35,
                  xaxis=dict(range=[0, max(cap["duration_s"], 1)]))
st.plotly_chart(fig, width="stretch")

# --------------------------------------------------------------------------- findings
st.markdown("#### Findings")
for i in incidents:
    head = f"{ICONS[i['verdict']]} {i['id']} · {i['verdict']} · {i['title']}"
    with st.expander(head, expanded=i["verdict"] == "ATTACK" or len(incidents) <= 2):
        st.markdown(f"**Confidence:** {i['confidence']} · **Severity:** {i['severity']} · "
                    f"**Time:** {i['start_offset_s']:.1f}s – {i['end_offset_s']:.1f}s")
        st.markdown(md(i["summary"]))
        a, b = st.columns(2)
        with a:
            st.markdown("**Why it matters**")
            st.markdown(md(i["why_it_matters"]))
            st.markdown("**Likely cause**")
            st.markdown(md(i["likely_cause"]))
        with b:
            st.markdown("**What to do next**")
            for s in i["next_steps"]:
                st.markdown(f"- {md(s)}")
        r = i["reasoning"]
        st.markdown(f"**Fault or attack?** Attack evidence **{r['attack_score']}** vs "
                    f"fault evidence **{r['fault_score']}**")
        for p in r["points_for_attack"]:
            st.markdown(f"🔴 {md(p['text'])}")
        for p in r["points_for_fault"]:
            st.markdown(f"🟢 {md(p['text'])}")
        if i["explains_symptoms"]:
            st.caption("Also explains: " + ", ".join(sorted({s["kind"] for s in i["explains_symptoms"]})))
        st.markdown("**Evidence packets**")
        rows = packet_table(capture_path, data["incidents"][incidents.index(i)]["evidence_frames"], start_ts)
        if anonymize:
            rows = anonymize_report({"file": {}, "rows": rows})["rows"]
        st.dataframe(rows, width="stretch", hide_index=True,
                     column_config={"info": st.column_config.TextColumn("info", width="large")})
        st.markdown("**Verify in Wireshark** (paste as display filter):")
        st.code(i["wireshark_filter"], language=None)
        if not anonymize:
            key = f"ev_{i['id']}"
            if st.button("Prepare evidence .pcap", key=key):
                out = _private_tempfile(b"", ".pcap")
                try:
                    n = export_evidence_pcap(capture_path, data["incidents"][incidents.index(i)]["evidence_frames"], out)
                    with open(out, "rb") as fh:
                        st.download_button(f"⬇ Download {n} evidence packets", fh.read(),
                                           file_name=f"{i['id']}_{i['kind']}.pcap",
                                           mime="application/vnd.tcpdump.pcap", key=key + "_dl")
                finally:
                    os.remove(out)
        else:
            st.caption("Evidence .pcap export is disabled while anonymizing (raw packets contain real addresses).")
