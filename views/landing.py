"""PacketMedic landing page (the / route).

The page itself is a React app built to one self-contained HTML file
(landing/ -> web/landing.html). Streamlit can't serve a raw HTML page, so it is
embedded full-width; the page resizes its own frame to its full height.
"""
from __future__ import annotations

from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components

HTML = Path(__file__).resolve().parent.parent / "web" / "landing.html"

# Strip Streamlit's own chrome so the landing page owns the whole viewport.
st.markdown(
    """
    <style>
      header[data-testid="stHeader"], [data-testid="stToolbar"], [data-testid="stDecoration"],
      [data-testid="stStatusWidget"], footer { display: none !important; }
      .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] { background: #0b1016 !important; }
      [data-testid="stMainBlockContainer"], .block-container {
        padding: 0 !important; max-width: 100% !important; }
      [data-testid="stVerticalBlock"] { gap: 0 !important; }
      [data-testid="stElementContainer"]:has(iframe), .element-container:has(iframe) { margin: 0 !important; }
      iframe { display: block; border: 0; width: 100% !important; }
    </style>
    """,
    unsafe_allow_html=True,
)

if HTML.exists():
    components.html(HTML.read_text(encoding="utf-8"), height=5200, scrolling=False)
else:
    st.error("Landing page not built. Run: cd landing && npm install && npm run build, then copy dist/index.html to web/landing.html.")
