# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Landing page: React (Vite) with components pulled from the ReactBits registry, bundled to a single self-contained HTML file and embedded in the existing Streamlit app (`app.py`), deployed on Streamlit Community Cloud at packetmedic.streamlit.app. The existing Streamlit dashboard moves to the `/demo` route. User chose Streamlit hosting knowing the page renders inside Streamlit's frame.

## Users

Primary: hackathon judges at the IIITDM Kancheepuram 24h Cybersecurity Hackathon (Network track), evaluating in minutes. They need to grasp what PacketMedic does, believe the fault-vs-attack claim, and reach the demo or the download quickly. Secondary: students, beginners and small offices/labs without a network engineer, who download the Windows build to diagnose their own network.

## Product Purpose

PacketMedic takes a packet capture (or records live traffic), finds the faults and attacks hidden in it, separates a plain outage from malicious activity, and explains each finding in plain language with the likely cause, a practical fix, and the exact evidence packets. Success: a non-expert can tell "the network is broken" apart from "someone is attacking us" and knows what to do next.

## Positioning

Verdicts, not alerts: every finding is classified ATTACK / SUSPICIOUS / FAULT from weighted evidence for and against an attack, with root-cause folding so one cause is one finding. Fully offline and deterministic: no LLM or cloud calls; the detection logic is the team's own code. Terminal-first: the primary product is `pmtui`, a native C htop-style dashboard that also captures live traffic; the web app is a demonstration only.

## Operating Context

Windows release zip (pmtui.exe + bundled engine, no install) from GitHub Releases; live capture through Windows' built-in pktmon in an Administrator terminal (5-300 s, consent screen, passive). Engine CLI for scripting. Web demo on Streamlit for no-install evaluation of bundled samples (no live capture; uploads processed on the cloud server).

## Capabilities and Constraints

Detects: TCP retransmissions, refused/unanswered connections, mid-stream resets, DNS failures/slowness/NXDOMAIN, duplicate IP/ARP conflicts, MTU mismatches, high latency, DHCP not answering; port scans, ARP spoofing, DNS hijacking, rogue DHCP, forged resets, possible DGA lookups. Outputs HTML/JSON reports, evidence .pcap per finding, Wireshark filters, health score. The Windows build is unsigned: SmartScreen may warn; Windows Defender may flag the PyInstaller-packed engine as a false positive (not yet observed by the team; describe as possible, never as having happened). Streamlit web dashboard is not included in the zip.

## Brand Commitments

Name: PacketMedic. Team name: Three Pointers. Existing terminal identity in pmtui: heartbeat/ECG line, htop-style meters, verdict colours (red ATTACK, yellow SUSPICIOUS, blue FAULT).

## Evidence on Hand

15 synthetic labelled sample captures (`samples/pcaps`, descriptions in `samples/catalog.json`); `eval.py` result on those samples: 100% precision/recall, 14/14 verdicts (synthetic, a regression check, not a benchmark); 66 automated tests; a real live Wi-Fi capture test that detected a harmless self-generated port scan, dead-DNS and NXDOMAIN tests plus a genuine Chromecast packet-loss finding. No users, testimonials, press or benchmarks exist; do not invent any.

## Product Principles

1. Explain, don't alarm: every finding comes with cause, fix and evidence.
2. Separate fault from attack, and show the reasoning.
3. Offline and private by default; be explicit whenever data would leave the machine.
4. The terminal app is the product; everything else demonstrates it.
5. Honest claims only: synthetic data is labelled as synthetic.
