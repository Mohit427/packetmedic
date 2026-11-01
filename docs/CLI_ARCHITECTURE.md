# PacketMedic TUI (`pmtui`): architecture

_Team Three Pointers_

A native **C** terminal front-end for PacketMedic with an htop-style look. From one screen you can:

1. **Analyse a bundled sample**: browse the sample captures with a description of each.
2. **Analyse your own capture**: type or paste a path to a `.pcap` / `.pcapng`.
3. **Capture live traffic**: the user types how long to listen (enforced range **5–300 s**, plus a 400 MB size cap), PacketMedic records passively, then analyses it.

…and then see an **interactive dashboard in the terminal**, plus links to the **HTML report** (file link) and the **Streamlit web dashboard** (`http://localhost:<port>`) for the same capture.

---

## 1. Key design decision: one engine, two front-ends

```
                ┌──────────────────────────── pmtui (C, this document) ───────────────────────────┐
                │                                                                                  │
   keyboard ──► │  TUI layer ──► Screens ──► Actions ──► Process layer (no shell, argv only)  ────┼──► python -m packetmedic analyze <file> --json <tmp> --html <report>
                │  (ANSI/VT,     menu,        analyse,     spawn / poll / kill                     │        (existing engine: ingest → trackers → detectors →
   terminal ◄── │  own code)     samples,     capture,          │                                  │         correlation/verdict → explainer)
                │                path,        open link,        ├──► dumpcap / tcpdump / pktmon ───┼──► captures/live_<time>.pcap(ng)
                │                capture,     launch web        │                                  │
                │                dashboard    ▲                 └──► python -m streamlit run app.py┼──► http://localhost:8501 (bound to 127.0.0.1)
                │                             │                                                    │
                │                 JSON parser (own) ◄── report JSON ◄──────────────────────────────┤
                └──────────────────────────────────────────────────────────────────────────────────┘
```

The detection, verdict and explanation logic stays in the existing Python engine. `pmtui` drives it as a subprocess and renders its JSON report.

**Why:** there is a single source of truth for detection. The 61 tests and `eval.py` cover what the TUI shows, and the CLI, web and TUI can never disagree. Re-implementing ten detectors in C before the deadline would double the bug surface for no user benefit. Everything *around* the engine (terminal UI, JSON parsing, process control, live capture orchestration, file validation, links) is new C code written for this project.

**No third-party C libraries.** No ncurses, no cJSON, no libpcap. The TUI uses ANSI/VT escape codes directly (Windows 10+ console, Windows Terminal, any Linux/macOS terminal), so judges only need a C compiler.

---

## 2. Modules

| File | Responsibility |
|---|---|
| `tui.c/.h` | Terminal setup/restore (alt screen, raw keys, UTF-8, VT mode), key decoding (arrows, F-keys, PgUp/PgDn), frame buffer, clipped/padded text drawing, colours, meters/bars, OSC-8 hyperlinks, **control-character sanitising** |
| `json.c/.h` | Small recursive-descent JSON parser (arena allocated, depth and size limits, full `\uXXXX` → UTF-8) plus lookup helpers |
| `proc.c/.h` | Cross-platform process control: run, spawn in background, poll, terminate, open URL. Windows uses `CreateProcessW` with correct argv quoting; POSIX uses `fork`/`execvp`. **No `system()`/`popen()` and no shell, ever** |
| `engine.c/.h` | Finds the project root and Python interpreter (`.venv` first), runs analyses, finds a free port and launches/stops the Streamlit dashboard, exports evidence |
| `capture.c/.h` | Detects a capture backend and records N seconds: **dumpcap** (Wireshark) → **tcpdump** → **pktmon** (built into Windows 10/11, needs admin) |
| `screens.c/.h` | Every screen: main menu, sample browser, path input, live capture, progress, dashboard, help |
| `main.c` | Startup checks, screen state machine, cleanup |

---

## 3. Screen flow

```
                    ┌─────────────┐
          ┌────────►│  MAIN MENU  │◄──────────────────────────────┐
          │         └──┬───┬───┬──┘                               │
          │      1     │   │2  │ 3                                │ Esc / F9
          │  ┌─────────▼┐ ┌▼───────────┐ ┌▼────────────────┐       │
          │  │ SAMPLES  │ │ PATH INPUT │ │ LIVE CAPTURE    │       │
          │  │ table +  │ │ line edit, │ │ consent → time  │       │
          │  │ details  │ │ validation │ │ → progress bar  │       │
          │  └────┬─────┘ └─────┬──────┘ └───────┬─────────┘       │
          │       └─────────────┼────────────────┘                 │
          │                     ▼                                  │
          │            ┌──────────────────┐                        │
          │            │ ANALYSING…       │ spinner + elapsed time  │
          │            └────────┬─────────┘ (Esc cancels)           │
          │                     ▼                                  │
          │            ┌──────────────────┐  F2 open HTML report   │
          └────────────┤    DASHBOARD     │  F3 launch web (link)  ├┘
                       │  meters, table,  │  F5 export evidence
                       │  timeline, detail│  Enter full detail view
                       └──────────────────┘  F1 help · F10 quit
```

### Dashboard layout (htop-inspired)

```
 PacketMedic v1.0 ── 11_mixed_outage_and_attack.pcapng ────────────────────────────────
  Health [|||||||||||||||||||||        55/100 ]  Under attack     Packets  278   Hosts 12
  Attack [|||                               1 ]                   Duration 29.9 s
  Suspic [                                  0 ]                   Format   pcapng
  Faults [|||                               1 ]                   Malformed 0
  TCP [||||||||||||   61%]  DNS [|||    20%]  ARP [|      4%]  UDP [|      9%] ...
 Timeline 0s ┊                                                             ┊ 29.9s
  PM-001 ATTACK ┊           ██████                                          ┊
  PM-002 FAULT  ┊   ████████████████████████████                            ┊
 ID      VERDICT     SEV     CONF    TIME         FINDING                              ← header bar
 PM-001  ATTACK      high    high    12.0–14.4    Port scan from 192.168.1.66          ← selected
 PM-002  FAULT       medium  medium   4.0–20.0    DNS server 192.168.1.1 is not answering
 ─ PM-001 details ───────────────────────────────────────────────────────────────────
  192.168.1.66 probed 120 different ports on 192.168.1.30 with 120 connection attempts…
  Why it matters …   Likely cause …   What to do …   Reasoning: ! … + …
  Evidence frames …   Wireshark filter: ip.src==192.168.1.66 && tcp.flags.syn==1 …
 HTML: file:///…/reports/11_mixed….html     Web: http://localhost:8501 (F3)
 F1Help F2HTML F3Web F5Evidence F9Back F10Quit                                       ← F-key bar
```

Colours: green meters, red ATTACK, yellow SUSPICIOUS, blue FAULT, cyan selection bar, and an F-key bar with htop's colour scheme. Below 80×24 the TUI asks you to enlarge the window.

---

## 4. Data flow for one analysis

1. **Validate in C** before anything runs: the file exists, is a regular file, is ≤ 512 MB and starts with pcap/pcapng magic bytes. Wrapping quotes from "Copy as path" are stripped.
2. **Spawn** `python -m packetmedic analyze <file> --json reports/<name>.json --html reports/<name>.html -q`. The arguments are passed as an argv array, so a path containing `&`, `;`, `"` or spaces can never become a command. Engine stdout/stderr go to a log file.
3. **Poll** the child every 100 ms while animating a spinner. Esc kills it.
4. **Exit code**: 0 = OK; 2 = file rejected by the engine (the reason is read from the log); anything else = engine error (the log tail is shown).
5. **Parse** the JSON with the arena parser (max 64 MB, max depth 64) and render.

## 5. Live capture

| Platform | Backend (first found) | Command (argv) | Notes |
|---|---|---|---|
| any | `dumpcap` (Wireshark) | `dumpcap -q -a duration:N -w <file.pcapng>` | stops by itself |
| Linux/macOS | `tcpdump` | `tcpdump -i any -U -w <file.pcap>` (no `-i any` on macOS) | stopped with SIGINT after N s; needs root/CAP_NET_RAW |
| Windows | `pktmon` (built in) | `pktmon start --capture --comp nics --pkt-size 0 --file-name <etl>` → `pktmon stop` → `pktmon etl2pcap <etl> --out <pcapng>` | needs an **Administrator** terminal; `--comp nics` avoids duplicate copies of each packet from different stack layers |

- **Listening caps:** the duration is typed by the user but must be between `CAP_MIN_SECONDS` (5) and `CAP_MAX_SECONDS` (300). The screen validates it and `capture_start()` clamps it again. Recording also stops early if the file reaches `CAP_MAX_BYTES` (400 MB), which keeps it under the engine's 512 MB input limit.
- **Passive only:** nothing is transmitted. A consent screen appears before every capture: *"Only capture on networks you own or are authorised to monitor."*
- Captures are written to `captures/` (git-ignored) and never leave the machine.
- If no backend or no privilege is available, the screen explains exactly what to install or how to re-run as admin/root instead of failing silently.

## 6. Web dashboard link

- `F3` finds a free port (8501–8520, checked with a TCP connect) and launches `python -m streamlit run app.py --server.port P --server.address 127.0.0.1 --server.headless true` with the environment variable `PACKETMEDIC_FILE=<capture>`.
- `app.py` reads `PACKETMEDIC_FILE` (environment only, never from the URL, so a web visitor cannot make the server open arbitrary files), validates it, and pre-selects it.
- The TUI waits until the port accepts connections, then shows `http://localhost:P` (clickable via OSC-8 in Windows Terminal and most modern terminals) and opens the browser.
- Only one dashboard runs at a time, and it is stopped when `pmtui` exits, so no orphan servers keep using memory.
- `F2` opens the HTML report via `ShellExecuteW` (Windows) or `xdg-open`/`open`. Again no shell.

## 7. Security measures (C side)

| Risk | Mitigation |
|---|---|
| Command injection via file paths | argv-only process creation; MS-compatible quoting on Windows; never a shell |
| Terminal escape injection (a DNS name containing `ESC[2J…` in the report) | every string drawn passes through `tui_sanitize`: C0/C1 control chars and DEL become `?` |
| Malformed/huge JSON | size cap, depth cap, bounds-checked parser; a missing field becomes a default value instead of a crash |
| Buffer overflows | all text through a length-tracked growable buffer; `snprintf` only; compiled with `-Wall -Wextra -Wformat=2 -fstack-protector-strong` |
| Web server exposure | Streamlit bound to `127.0.0.1`; file chosen via environment only |
| Leftover processes / broken terminal | `atexit` + Ctrl-C handler restore the terminal and stop child processes |
| Accidental capture of others' traffic | explicit consent screen, passive capture only, local storage only |

## 8. Build

```
cd cli_c
make            # Linux/macOS (gcc or clang)          → cli_c/pmtui
mingw32-make    # Windows with MSYS2/MinGW-w64 gcc   → cli_c/pmtui.exe
```

`pmtui` finds the project root by walking up from the current directory and from its own location until it finds `packetmedic/__init__.py`. It prefers the project's `.venv` interpreter, then `$PACKETMEDIC_PYTHON`, then `python3`/`python` on PATH.

## 9. Out of scope (for the deadline)

- Re-implementing detection in C (see §1).
- Choosing a capture interface (the backend's default is used: "any" on Linux, all NICs with pktmon).
- Mouse support.
