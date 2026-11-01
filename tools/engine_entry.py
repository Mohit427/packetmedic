"""Entry point for the frozen (PyInstaller) engine shipped in the Windows release.

engine/packetmedic.exe analyze capture.pcap ...   ==   python -m packetmedic analyze capture.pcap ...
"""
from packetmedic.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
