"""Render pmtui's real opening screen to docs/thumbnail.png (Windows, uses Edge headless).

    .venv\\Scripts\\python.exe tools\\render_thumbnail.py
"""
from __future__ import annotations

import html
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
COLS, ROWS = 120, 34
# Windows Terminal "Campbell" palette, the colours pmtui is seen in
PALETTE = ["#0c0c0c", "#c50f1f", "#13a10e", "#c19c00", "#0037da", "#881798", "#3a96dd", "#cccccc",
           "#767676", "#e74856", "#16c60c", "#f9f1a5", "#3b78ff", "#b4009e", "#61d6d6", "#f2f2f2"]


def main() -> int:
    exe = max((p for p in (ROOT / "build" / "pmtui.exe", ROOT / "cli_c" / "pmtui.exe") if p.exists()),
              key=lambda p: p.stat().st_mtime)
    env = {**os.environ, "PMTUI_SNAPSHOT_FORMAT": "json"}
    out = subprocess.run([str(exe), "--snapshot", "menu", f"{COLS}x{ROWS}"], capture_output=True, text=True,
                         encoding="utf-8", cwd=ROOT, timeout=120, env=env, check=True)
    frame = json.loads(out.stdout)

    rows = []
    for row in frame["rows"]:
        runs = []
        for col, fg, bg, attr, text in row:
            style = [f"left:{col}ch", f"width:{len(text)}ch", f"color:{PALETTE[fg] if fg >= 0 else '#cccccc'}"]
            if bg >= 0:
                style.append(f"background:{PALETTE[bg]}")
            if attr & 1:
                style.append("font-weight:700")
            runs.append(f'<span style="{";".join(style)}">{html.escape(text)}</span>')
        rows.append(f'<div class="r">{"".join(runs)}</div>')
    page = f"""<!doctype html><meta charset="utf-8"><style>
html,body{{margin:0;background:#0c0c0c}}
#s{{font:18px/1.2 'Cascadia Mono',Consolas,monospace;width:{COLS}ch;white-space:pre}}
.r{{position:relative;height:1.2em}} .r span{{position:absolute;top:0;height:1.2em}}
</style><div id="s">{''.join(rows)}</div>"""

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "thumb.html"
        src.write_text(page, encoding="utf-8")
        dst = ROOT / "docs" / "thumbnail.png"
        subprocess.run([EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=2",
                        f"--user-data-dir={tmp}\\edge", "--window-size=1267,735", f"--screenshot={dst}", src.as_uri()],
                       check=True, capture_output=True, timeout=120)
    print(f"wrote {dst} ({dst.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
