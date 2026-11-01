# 🩺 PacketMedic

**Finds the faults and attacks hidden in a packet capture, tells you which is which, and explains each one in plain language with the evidence packets.**

> **Team Three Pointers** · Network track · 24h Cybersecurity Hackathon · IIITDM Kancheepuram
> Demo video: _<add link here>_

> [!IMPORTANT]
> **The product is the terminal app, `pmtui`.** It's a native C, htop-style dashboard that analyses sample captures, your own files, **and live traffic captured from your machine**, fully offline.
> **⬇ Get it: [PacketMedic for Windows (zip, no install)](https://github.com/Mohit427/packetmedic/releases/latest)**
>
> The web version at **[packetmedic.streamlit.app](https://packetmedic.streamlit.app)** is **for demonstration purposes only**: a quick, no-install way to see the same analysis engine on the bundled samples. It **cannot capture live traffic**, and anything uploaded there is processed on a cloud server. Use the terminal app for real diagnosis.

| | **`pmtui` terminal app: primary product** | Web demo: demonstration only |
|---|---|---|
| Analyse bundled samples | ✅ | ✅ |
| Analyse your own capture file | ✅ local, never leaves your machine | ⚠ uploaded to a cloud server |
| **Live capture of your network** | ✅ (5–300 s, passive, consent screen) | ❌ a cloud server can't see your network |
| Works offline | ✅ | ❌ |
| HTML report, JSON, evidence .pcap export | ✅ | ✅ |
| Install | unzip and run (Windows) or build from source | none, open the link |

---

## The problem

Small offices, labs and departments have no network engineer. When "the network is broken", someone has to open a packet capture and read it line by line. That takes deep protocol knowledge, and it's even harder to tell a **harmless fault** from an **attack hiding in the same traffic**. So people restart the router and wait while the real problem continues.

## Our solution

PacketMedic reads a `.pcap` / `.pcapng` file and produces a **diagnosis**, not a raw list of alerts:

- **Detects faults:** TCP retransmissions, refused or unanswered connections, mid-stream resets, DNS outages/errors/slowness, failed lookups, duplicate IPs / ARP conflicts, MTU mismatches (including "black holes"), high latency, and DHCP not answering.
- **Detects attacks:** port scans and host sweeps, ARP spoofing (man-in-the-middle), DNS hijacking (forged answers), rogue DHCP servers, forged TCP resets, and possible DGA malware lookups.
- **Separates outage from attack.** Every finding carries weighted evidence *for* "attack" and *for* "fault". The verdict engine decides **ATTACK / SUSPICIOUS / FAULT** with a confidence level, and shows its reasoning.
- **Root-cause folding.** When one problem explains another, the explained one is attached as a symptom instead of raising a second alarm. For example, an MTU mismatch explains retransmissions, a port scan explains a pile of resets, and a rogue DHCP server explains forged DNS answers. Fewer, truer alerts.
- **Explains clearly:** what happened, why it matters, the likely cause, and practical next steps, in beginner-friendly language. The text comes from templates, so there are **no LLM or API calls**: output is deterministic and nothing leaves your machine.
- **Shows the evidence:** exact frame numbers (same numbering as Wireshark), a packet table per finding, a timeline, a ready-to-paste **Wireshark display filter**, and a one-click **evidence .pcap** with only the packets behind that finding.
- **Network Health Score** (0–100) for an at-a-glance status.

### How fault vs attack is decided: examples

| Symptom | Evidence for **fault** | Evidence for **attack** |
|---|---|---|
| One IP, two MAC addresses | Each device claims only that IP; they only answered real ARP questions | One MAC claims several IPs; floods of unsolicited replies; clockwork timing; the gateway IP is targeted |
| Lots of TCP resets | One server rejects every client on one port (service down) | One source hits hundreds of ports and gets resets back (scan) |
| DNS problems | Timeouts / SERVFAIL from the usual resolver; "port unreachable" | Two different answers to one query; answers with the wrong hop count (IP TTL); public names pointed at LAN addresses |
| Two DHCP servers | Same router/DNS settings (someone plugged in a home router) | Hands out itself as router/DNS; answers faster than the real server |

---

## 1. The product: `pmtui` terminal app

### Option A: download for Windows (no install, recommended)

1. Download **`PacketMedic-1.0.0-win64.zip`** from **[Releases](https://github.com/Mohit427/packetmedic/releases/latest)**.
2. Right-click, **Extract All**, open the folder, and run **`pmtui.exe`** (in Windows Terminal for the best look).
3. Press **1** for a sample, **2** for your own file, **3** for live capture. Live capture needs Terminal opened with **Run as administrator**.

No Python or setup is needed: the analysis engine is bundled (frozen with PyInstaller), and the 15 sample captures are included. Windows SmartScreen may warn about an unsigned app; click **More info → Run anyway**.
To rebuild the zip yourself: `pip install pyinstaller`, then `python tools/build_release.py` (needs MSYS2 gcc).

### Option B: build from source (Windows, Linux, macOS)

Requires **Python 3.10+** (tested on 3.12) and a C compiler (gcc/clang; MSYS2 on Windows). No network access, accounts or API keys needed.

```bash
git clone https://github.com/Mohit427/packetmedic.git && cd packetmedic
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt

cd cli_c
mingw32-make        # Windows (MSYS2 / MinGW-w64 gcc)   ->  cli_c\pmtui.exe
make                # Linux / macOS (gcc or clang)      ->  cli_c/pmtui
cd ..
cli_c/pmtui                                         # interactive menu
cli_c/pmtui samples/pcaps/07_arp_spoofing.pcap     # straight to the dashboard
```

### What pmtui does

The main menu offers three options:
1. **Bundled sample.** Browse all 15 scenarios with a description of each.
2. **Your own file.** Type or paste a path; it is validated before analysis.
3. **Live capture.** You type how long to listen, capped between **5 s and 300 s** (5 min), and the capture also auto-stops at 400 MB. It records this machine's traffic passively, after a consent screen, then diagnoses it. It uses `dumpcap` (Wireshark), `tcpdump`, or Windows' built-in `pktmon` (run the terminal **as Administrator** for pktmon).

The dashboard shows health/verdict meters, protocol meters, a findings table with mini timelines, and a scrollable detail pane with reasoning, evidence frames and a Wireshark filter. It also shows a clickable link to the **HTML report**. **F3** launches the **Streamlit dashboard** for the same capture and shows its `http://localhost:…` link. Other keys: **F2** opens the HTML report, **F5** exports evidence pcaps.
`pmtui` uses no third-party C libraries (own ANSI terminal layer, own JSON parser) and never invokes a shell. Design: [`docs/CLI_ARCHITECTURE.md`](docs/CLI_ARCHITECTURE.md).

## 2. Engine command line (for scripting / automation)

The same engine pmtui uses, scriptable from the shell or CI:
```bash
python -m packetmedic analyze samples/pcaps/07_arp_spoofing.pcap
python -m packetmedic analyze samples/pcaps/11_mixed_outage_and_attack.pcapng --html report.html --json report.json
python -m packetmedic analyze capture.pcap --evidence-dir evidence/   # one pcap per finding
python -m packetmedic analyze capture.pcap --anonymize --html shareable.html
python -m packetmedic analyze capture.pcap --json -                  # JSON to stdout
```
(In the Windows zip: `engine\packetmedic.exe analyze capture.pcap ...`)

## 3. Website and web demo (demonstration only)

**Hosted:** **[packetmedic.streamlit.app](https://packetmedic.streamlit.app)** opens the landing page, with downloads, the Windows warning explained and the SHA-256 checksum. **[/demo](https://packetmedic.streamlit.app/demo)** opens the web demo, with the mixed outage + attack sample already loaded.
The landing page is a React app in `landing/` that uses ReactBits components (DecryptedText, CountUp, Noise, SpotlightCard). It is built into one self-contained file, `web/landing.html`, which Streamlit embeds (`app.py` routes `/` to `views/landing.py` and `/demo` to `views/demo.py`). Every trace and number on it comes from real engine output (`python tools/landing_data.py`). To rebuild: `cd landing && npm install && npm run build`, then copy `dist/index.html` to `web/landing.html`.
**Locally:** `streamlit run app.py --server.address 127.0.0.1`, or press **F3** inside pmtui.

It exists so anyone can try the engine in a browser without installing anything. It is **not** the product: it has no live capture, and the hosted copy processes uploads on a cloud server (the app shows this warning). Use pmtui for real network diagnosis.

## Accuracy check and tests
```bash
python eval.py      # precision / recall / verdict accuracy on the labeled samples
pytest -q           # 66 tests: detection, fuzzing, truncation, injection, anonymization, real Wi-Fi capture quirks
```

---

## Where the data comes from

PacketMedic needs no live network. It analyses capture files.

1. **Bundled sample captures (`samples/pcaps/`)** are **synthetic**. `samples/generate.py` builds them packet by packet with Scapy, simulating a small office LAN (`192.168.1.0/24`, gateway `.1`, clients `.20–.24`, attacker `.66`). They are reproducible (fixed random seeds), and each comes with ground truth in `samples/truth.json`. No real network was captured, as the hackathon's safe-testing rule requires. Regenerate them any time with `python samples/generate.py`.
2. **Your own captures:** any `.pcap`/`.pcapng` from Wireshark, `tcpdump -w`, or `dumpcap`, **on networks you own or have permission to monitor**.

| Sample | Scenario | Expected |
|---|---|---|
| 01_healthy_office | normal traffic incl. one lost packet and one typo lookup (noise) | nothing (false-alarm test) |
| 02_slow_web_retransmissions | lossy link to a web server | fault |
| 03_dns_server_down | resolver not answering; raw-IP traffic still works | fault |
| 04_duplicate_ip | two machines with the same static IP | fault |
| 05_mtu_blackhole | VPN path MTU 1400, big packets vanish | fault (retransmissions folded in) |
| 06_port_scan | SYN scan of 250 ports | attack |
| 07_arp_spoofing | attacker poisons gateway and victim | attack |
| 08_dns_hijack | forged DNS answers raced against the real resolver | attack |
| 09_rogue_dhcp | rogue server hands out itself as router + DNS | attack |
| 10_service_down_and_latency | service refusing connections + a slow remote server | 2 faults |
| 11_mixed_outage_and_attack (pcapng) | DNS outage **and** a port scan at the same time | 1 fault + 1 attack |
| 12_second_dhcp_misconfigured | extra DHCP server with identical settings | fault (not attack) |
| 13_malicious_dns_names | DNS names containing `<script>` / markup | fault; proves output escaping |
| 14_malformed_truncated | garbage frames + a record claiming to be 4 GB | no crash, warnings |
| 15_not_a_capture | text file named `.pcap` | rejected |

Current result of `python eval.py`: **100% precision, 100% recall, 14/14 correct fault-vs-attack verdicts, 0 false alarms.**
(These are our own synthetic scenarios, so treat this as a regression check, not a real-world benchmark.)

---

## Architecture

```
pcap ─► 1 Safe ingest ─► 2 State trackers ─► 3 Detectors ─► 4 Correlation & verdict ─► 5 Explainer ─► 6 Outputs
        validate, own      TCP flows, ARP,     faults +        merge, root-cause fold,     templates     CLI / web / HTML
        bounded reader     DNS, DHCP, ICMP,    attacks →       fault-vs-attack scoring,    (no LLM)      JSON / evidence pcap
                           scans (single pass) Signals         health score
```

```
packetmedic/
  ingest/     validator.py (size/magic checks) · pcapfile.py (own pcap/pcapng reader+writer) · decode.py
  trackers/   flow.py · arp.py · dns.py · misc.py (DHCP, ICMP, scans, general) · context.py
  detectors/  tcp.py · scan.py · arp.py · dns.py · dhcp.py
  engine/     correlate.py · verdict.py · score.py
  explain/    templates.py
  output/     serialize.py · html_report.py · evidence.py · anonymize.py
  analyzer.py · cli.py · config.py (all limits & thresholds) · models.py
app.py (Streamlit) · eval.py · samples/generate.py · tests/
```

## Security of the tool itself

- **Own bounded capture reader.** Every length field is checked against hard limits *before* reading, so a file claiming a 4 GB packet cannot exhaust memory. Truncated or corrupt files end with a warning, never a crash.
- **Up-front validation:** file size cap (512 MB CLI / 200 MB web), magic-byte check for pcap/pcapng, extension check on uploads.
- **Minimal parser surface:** Scapy is restricted to the ~20 dissectors we need; everything else stays as opaque bytes.
- **Isolation:** each packet decode, each tracker update and each detector runs in its own error guard. A bad packet or a detector bug becomes a warning.
- **Bounded memory:** every tracker table is an LRU-capped dict; a wall-clock limit applies too.
- **Output escaping:** HTML report via Jinja2 autoescape plus a strict Content-Security-Policy; Rich markup escaped in the CLI; Markdown escaped in the dashboard. Sample 13 proves it.
- **Privacy:** fully offline, no telemetry (`gatherUsageStats = false`), no LLM/API calls. Uploads go to a private temp file that is deleted when replaced. `--anonymize` consistently masks IPs/MACs in every report.
- **No secrets** anywhere in the repo, since nothing needs one.
- **Fuzz-tested:** 35 fuzz cases (random frames, bit-flipped captures, corrupt pcapng) in `tests/test_safety.py`.

## Limitations

- Heuristic thresholds (in `config.py`) are tuned on simulated traffic; very unusual networks may need tuning.
- Live Windows captures (pktmon) on Wi-Fi store raw 802.11 frames mislabelled as Ethernet; PacketMedic detects and converts them, ignores duplicate copies the capture tool records twice, and does not mistake TCP keep-alives for packet loss.
- Encrypted payloads aren't inspected (not needed for these diagnoses). IPv6 is parsed for TCP analysis, but ARP/DHCP checks are IPv4-only.
- One capture point sees one view of the network: problems on segments the capture didn't see can't be diagnosed.

## Open-source libraries used

| Library | License | Used for |
|---|---|---|
| [Scapy](https://scapy.net) 2.8 | GPL-2.0 | Decoding protocol headers from raw packet bytes (parsing only), and building synthetic samples |
| [Streamlit](https://streamlit.io) 1.66 | Apache-2.0 | Web dashboard |
| [Plotly](https://plotly.com/python/) 7.1 | MIT | Timeline chart |
| [Jinja2](https://jinja.palletsprojects.com) 3.1 | BSD-3 | HTML report rendering (autoescaped) |
| [Rich](https://github.com/Textualize/rich) 15 | MIT | Terminal output |
| [React](https://react.dev) 19, [Vite](https://vite.dev) 7, vite-plugin-singlefile | MIT | Landing page build |
| [ReactBits](https://reactbits.dev) components | MIT + Commons Clause | Landing page effects (DecryptedText, CountUp, Noise, SpotlightCard) |
| [Motion](https://motion.dev), [Lucide](https://lucide.dev) | MIT, ISC | Landing page animation and icons |
| Big Shoulders Display, Atkinson Hyperlegible, JetBrains Mono, Permanent Marker (via Fontsource) | OFL / Apache-2.0 | Landing page typefaces |
| [pytest](https://pytest.org) 9 | MIT | Tests |

The C terminal app (`cli_c/`) uses only the C standard library and the OS APIs (Win32 / POSIX). No external APIs or AI services are used. All detection, correlation, verdict, explanation and pcap reading/writing logic is our own code. We do not wrap Wireshark or tshark.

## Responsible use

Analyse only captures from networks you own or are authorised to monitor. PacketMedic is a diagnostic tool and performs no active scanning or interception.
