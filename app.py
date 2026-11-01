"""PacketMedic on Streamlit: router.

    /       landing page (hosted public site)
    /demo   web demo of the engine (demonstration only; the product is pmtui)

    streamlit run app.py --server.address 127.0.0.1
"""
from __future__ import annotations

import os
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
PUBLIC = str(ROOT).startswith("/mount/src") or os.environ.get("PACKETMEDIC_PUBLIC_DEMO") == "1"
FROM_PMTUI = bool(os.environ.get("PACKETMEDIC_FILE"))

st.set_page_config(page_title="PacketMedic", page_icon="🩺", layout="wide", initial_sidebar_state="auto")

landing = st.Page("views/landing.py", title="PacketMedic", icon="🩺", url_path="home", default=not FROM_PMTUI)
demo = st.Page("views/demo.py", title="Web demo", icon="🖥️", url_path="demo", default=FROM_PMTUI)

# pmtui's F3 opens straight into the demo with its capture; everyone else lands on the landing page.
st.navigation([landing, demo], position="hidden").run()
