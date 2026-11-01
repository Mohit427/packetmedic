"""Build the self-contained Windows release zip.

    .venv\\Scripts\\python.exe tools\\build_release.py

Needs (build machine only): PyInstaller in the venv (pip install pyinstaller)
and MSYS2/MinGW gcc + mingw32-make on PATH (C:\\msys64\\ucrt64\\bin).

Produces dist/PacketMedic-<version>-win64.zip:
    PacketMedic/
      pmtui.exe                 C terminal app (static, no DLLs)
      engine/packetmedic.exe    Python engine frozen with PyInstaller (no Python needed)
      samples/                  15 sample captures + catalog.json + truth.json
      README.txt
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from packetmedic import __version__  # noqa: E402

BUILD = ROOT / "build"
DIST = ROOT / "dist"
STAGE = DIST / "PacketMedic"
MSYS_BIN = Path(r"C:\msys64\ucrt64\bin")

README_TXT = f"""PacketMedic {__version__} for Windows - Team Three Pointers
==============================================================

Finds the faults and attacks hidden in packet captures, tells you which is
which, and explains each one in plain language. Runs 100% offline.

QUICK START
  1. Unzip this folder anywhere.
  2. Open Windows Terminal in this folder and run:   .\\pmtui.exe
     (Double-clicking pmtui.exe also works.)
  3. Press 1 to try a bundled sample, 2 to analyse your own .pcap/.pcapng,
     or 3 to capture live traffic.

LIVE CAPTURE
  Uses Windows' built-in pktmon, which needs Administrator rights:
  right-click Terminal -> "Run as administrator", cd to this folder, run pmtui.exe.
  You choose how long to listen (5-300 seconds). Only capture on networks you
  own or are authorised to monitor.

COMMAND LINE ENGINE
  engine\\packetmedic.exe analyze capture.pcap --html report.html --json report.json

OUTPUT
  reports\\   HTML/JSON reports      captures\\   live captures

NOTES
  * The Streamlit web dashboard (F3) needs the full Python install from GitHub;
    in this build use F2 to open the HTML report instead.
  * Windows SmartScreen may warn about an unsigned app: More info -> Run anyway.
  * Source, docs and tests: https://github.com/Mohit427/packetmedic
"""


def run(cmd: list[str], **kw) -> None:
    print("  $", " ".join(str(c) for c in cmd))
    subprocess.run(cmd, check=True, **kw)


def main() -> int:
    if os.name != "nt":
        print("This script builds the Windows release; run it on Windows.")
        return 1
    print(f"Building PacketMedic {__version__} Windows release")
    shutil.rmtree(STAGE, ignore_errors=True)
    STAGE.mkdir(parents=True)

    print("[1/4] Freezing the Python engine with PyInstaller")
    run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--log-level", "WARN",
         "--onedir", "--console", "--name", "packetmedic",
         "--distpath", str(BUILD / "pyi-dist"), "--workpath", str(BUILD / "pyi-work"),
         "--specpath", str(BUILD),
         "--collect-submodules", "rich._unicode_data",
         *[a for m in ("streamlit", "plotly", "pandas", "numpy", "pyarrow", "matplotlib", "tkinter",
                       "pytest", "IPython", "PIL") for a in ("--exclude-module", m)],
         str(ROOT / "tools" / "engine_entry.py")])
    shutil.copytree(BUILD / "pyi-dist" / "packetmedic", STAGE / "engine")

    print("[2/4] Compiling pmtui.exe")
    env = dict(os.environ)
    if MSYS_BIN.exists():
        env["PATH"] = str(MSYS_BIN) + os.pathsep + env["PATH"]
    BUILD.mkdir(exist_ok=True)
    # build into build/ so a running pmtui.exe in cli_c/ (file locked) doesn't matter
    run(["mingw32-make", "-B", f"TARGET={(BUILD / 'pmtui.exe').as_posix()}"], cwd=ROOT / "cli_c", env=env)
    shutil.copy2(BUILD / "pmtui.exe", STAGE / "pmtui.exe")

    print("[3/4] Copying samples and docs")
    (STAGE / "samples").mkdir()
    shutil.copytree(ROOT / "samples" / "pcaps", STAGE / "samples" / "pcaps")
    for f in ("catalog.json", "truth.json"):
        shutil.copy2(ROOT / "samples" / f, STAGE / "samples" / f)
    (STAGE / "README.txt").write_text(README_TXT, encoding="utf-8")

    print("[4/4] Zipping")
    zpath = DIST / f"PacketMedic-{__version__}-win64.zip"
    zpath.unlink(missing_ok=True)
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in sorted(STAGE.rglob("*")):
            if p.is_file():
                z.write(p, Path("PacketMedic") / p.relative_to(STAGE))
    print(f"\nDone: {zpath}  ({zpath.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
