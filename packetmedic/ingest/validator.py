"""First line of defence: decide whether a file is even worth opening."""
from __future__ import annotations

import os
from pathlib import Path

from ..config import Limits

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("pcap", "<", 1e-6),
    b"\xa1\xb2\xc3\xd4": ("pcap", ">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("pcap", "<", 1e-9),   # nanosecond resolution
    b"\xa1\xb2\x3c\x4d": ("pcap", ">", 1e-9),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".dmp"}


class InputError(Exception):
    """The input file was rejected. The message is safe to show to users."""


def validate_capture(path: str | os.PathLike, limits: Limits) -> str:
    """Return 'pcap' or 'pcapng', or raise InputError with a friendly reason."""
    p = Path(path)
    if not p.exists():
        raise InputError("File not found.")
    if not p.is_file():
        raise InputError("Path is not a regular file.")
    size = p.stat().st_size
    if size == 0:
        raise InputError("File is empty.")
    if size > limits.max_file_bytes:
        raise InputError(
            f"File is {size / 1e6:.0f} MB; the limit is {limits.max_file_bytes / 1e6:.0f} MB. "
            "Split it first (e.g. with editcap -c)."
        )
    if size < 24:
        raise InputError("File is too small to be a packet capture.")
    with p.open("rb") as fh:
        magic = fh.read(4)
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    if magic[:2] == b"\x1f\x8b":
        raise InputError("File is gzip-compressed. Decompress it first.")
    raise InputError("Not a pcap/pcapng file (unrecognised file signature).")


def check_extension(filename: str) -> None:
    """Used for uploads, where we only have the client-supplied name."""
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise InputError(f"Unsupported file type '{ext or '(none)'}'. Use .pcap or .pcapng.")
