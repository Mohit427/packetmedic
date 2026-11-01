"""A small, defensive pcap / pcapng reader written for this project.

Why not just use Scapy's reader? Because a malicious capture can claim that a
packet is 4 GB long, and naive readers will try to allocate that. Here every
length field is checked against hard limits *before* any read, files are
streamed one record at a time, and any structural corruption ends the read
cleanly with a warning instead of an exception.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from ..config import Limits
from .validator import PCAP_MAGICS, PCAPNG_MAGIC


@dataclass(slots=True)
class RawFrame:
    index: int        # 1-based, matches Wireshark's frame numbers
    ts: float
    linktype: int
    data: bytes
    orig_len: int


class _Stop(Exception):
    pass


def _read_exact(fh: BinaryIO, n: int, what: str, warnings: list[str]) -> bytes:
    data = fh.read(n)
    if len(data) != n:
        warnings.append(f"Capture ends in the middle of {what} (file truncated); stopped reading there.")
        raise _Stop
    return data


def iter_raw_frames(path: str, limits: Limits, warnings: list[str]) -> Iterator[RawFrame]:
    with open(path, "rb") as fh:
        magic = fh.read(4)
        fh.seek(0)
        try:
            if magic in PCAP_MAGICS:
                yield from _iter_pcap(fh, limits, warnings)
            elif magic == PCAPNG_MAGIC:
                yield from _iter_pcapng(fh, limits, warnings)
            else:
                warnings.append("Unknown capture format.")
        except _Stop:
            return


# --------------------------------------------------------------------------- classic pcap
def _iter_pcap(fh: BinaryIO, limits: Limits, warnings: list[str]) -> Iterator[RawFrame]:
    header = _read_exact(fh, 24, "the file header", warnings)
    _, endian, resolution = PCAP_MAGICS[header[:4]]
    _vmaj, _vmin, _zone, _sig, _snap, linktype = struct.unpack(endian + "HHiIII", header[4:])
    linktype &= 0x0FFFFFFF  # upper bits may carry FCS info
    rec = struct.Struct(endian + "IIII")
    index = 0
    while index < limits.max_packets:
        head = fh.read(16)
        if not head:
            return
        if len(head) < 16:
            warnings.append(f"Capture truncated after packet {index}; stopped reading there.")
            return
        ts_sec, ts_frac, incl_len, orig_len = rec.unpack(head)
        if incl_len > limits.max_packet_bytes:
            warnings.append(
                f"Packet {index + 1} claims a size of {incl_len} bytes (limit "
                f"{limits.max_packet_bytes}); the file is corrupt or malicious. Stopped reading there."
            )
            return
        data = _read_exact(fh, incl_len, f"packet {index + 1}", warnings)
        index += 1
        yield RawFrame(index, ts_sec + ts_frac * resolution, linktype, data, orig_len)
    warnings.append(f"Packet limit of {limits.max_packets:,} reached; the rest of the file was not analysed.")


# --------------------------------------------------------------------------- pcapng
def _iter_pcapng(fh: BinaryIO, limits: Limits, warnings: list[str]) -> Iterator[RawFrame]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []   # (linktype, ts resolution)
    index = 0
    while index < limits.max_packets:
        head = fh.read(8)
        if not head:
            return
        if len(head) < 8:
            warnings.append(f"Capture truncated after packet {index}; stopped reading there.")
            return
        if head[:4] == PCAPNG_MAGIC:
            bom = _read_exact(fh, 4, "a section header", warnings)
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                warnings.append("Invalid pcapng section header; stopped reading.")
                return
            btype = 0x0A0D0D0A
            (total_len,) = struct.unpack(endian + "I", head[4:])
            consumed = 12
            interfaces = []
        else:
            btype, total_len = struct.unpack(endian + "II", head)
            consumed = 8
        if total_len < 12 or total_len % 4 or total_len > limits.max_block_bytes:
            warnings.append(f"Corrupt pcapng block (length {total_len}) after packet {index}; stopped reading.")
            return
        body = _read_exact(fh, total_len - consumed - 4, "a pcapng block", warnings)
        trailer = _read_exact(fh, 4, "a pcapng block", warnings)
        if struct.unpack(endian + "I", trailer)[0] != total_len:
            warnings.append(f"Corrupt pcapng block after packet {index}; stopped reading.")
            return

        if btype == 0x00000001:            # Interface Description Block
            if len(body) < 8:
                continue
            linktype = struct.unpack(endian + "H", body[:2])[0]
            interfaces.append((linktype, _tsresol(body[8:], endian)))
        elif btype == 0x00000006:          # Enhanced Packet Block
            if len(body) < 20:
                continue
            iface, ts_hi, ts_lo, caplen, origlen = struct.unpack(endian + "IIIII", body[:20])
            if caplen > limits.max_packet_bytes or caplen > len(body) - 20:
                warnings.append(f"Packet {index + 1} has an impossible length; stopped reading.")
                return
            if iface >= len(interfaces):
                index += 1
                continue
            linktype, res = interfaces[iface]
            index += 1
            yield RawFrame(index, ((ts_hi << 32) | ts_lo) * res, linktype, body[20:20 + caplen], origlen)
        elif btype == 0x00000003:          # Simple Packet Block
            if len(body) < 4 or not interfaces:
                continue
            origlen = struct.unpack(endian + "I", body[:4])[0]
            data = body[4:4 + min(origlen, limits.max_packet_bytes)]
            index += 1
            yield RawFrame(index, 0.0, interfaces[0][0], data, origlen)
        # every other block type is skipped safely
    warnings.append(f"Packet limit of {limits.max_packets:,} reached; the rest of the file was not analysed.")


def _tsresol(options: bytes, endian: str) -> float:
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[pos:pos + 4])
        if code == 0:
            break
        value = options[pos + 4:pos + 4 + length]
        if code == 9 and length == 1:
            v = value[0]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        pos += 4 + length + ((4 - length % 4) % 4)
    return 1e-6


# --------------------------------------------------------------------------- writer
def write_pcap(path: str, frames: list[RawFrame]) -> int:
    """Write frames as a classic pcap (used for evidence export). Returns frames written."""
    if not frames:
        linktype = 1
    else:
        linktype = frames[0].linktype
    written = 0
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
        for f in frames:
            if f.linktype != linktype:
                continue
            sec = int(f.ts)
            usec = int(round((f.ts - sec) * 1e6))
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            fh.write(struct.pack("<IIII", sec, usec, len(f.data), max(f.orig_len, len(f.data))))
            fh.write(f.data)
            written += 1
    return written
