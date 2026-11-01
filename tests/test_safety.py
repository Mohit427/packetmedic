"""Hostile-input tests: the tool must reject or survive bad files, never crash or inject."""
import random
import struct
from pathlib import Path

import pytest
from rich.console import Console

from packetmedic.analyzer import analyze
from packetmedic.cli import _print_report
from packetmedic.ingest.validator import InputError
from packetmedic.output.anonymize import anonymize_report
from packetmedic.output.html_report import render_html
from packetmedic.output.serialize import report_to_dict

ROOT = Path(__file__).resolve().parents[1]
PCAPS = ROOT / "samples" / "pcaps"
PCAP_HDR = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def test_empty_file(tmp_path):
    p = tmp_path / "empty.pcap"
    p.write_bytes(b"")
    with pytest.raises(InputError):
        analyze(p)


def test_wrong_format(tmp_path):
    p = tmp_path / "fake.pcap"
    p.write_bytes(b"<html>" + b"A" * 100)
    with pytest.raises(InputError):
        analyze(p)


def test_header_only(tmp_path):
    p = tmp_path / "hdr.pcap"
    p.write_bytes(PCAP_HDR)
    rep = analyze(p)
    assert rep.packets == 0 and rep.incidents == []


def test_huge_length_claim_does_not_allocate(tmp_path):
    p = tmp_path / "liar.pcap"
    p.write_bytes(PCAP_HDR + struct.pack("<IIII", 1, 0, 0xFFFFFFF0, 0xFFFFFFF0) + b"x" * 64)
    rep = analyze(p)
    assert any("corrupt" in w for w in rep.warnings)


def test_truncated_mid_packet(tmp_path):
    src = (PCAPS / "02_slow_web_retransmissions.pcap").read_bytes()
    p = tmp_path / "cut.pcap"
    p.write_bytes(src[: len(src) // 2 + 7])
    rep = analyze(p)
    assert any("truncated" in w for w in rep.warnings)


@pytest.mark.parametrize("seed", range(25))
def test_fuzz_random_frames(tmp_path, seed):
    rng = random.Random(seed)
    body = b""
    for i in range(200):
        n = rng.randint(0, 300)
        body += struct.pack("<IIII", 1000 + i, 0, n, n) + bytes(rng.randrange(256) for _ in range(n))
    p = tmp_path / f"fuzz{seed}.pcap"
    p.write_bytes(PCAP_HDR + body)
    analyze(p)   # must not raise


@pytest.mark.parametrize("seed", range(10))
def test_fuzz_bitflips_real_capture(tmp_path, seed):
    rng = random.Random(seed)
    data = bytearray((PCAPS / "07_arp_spoofing.pcap").read_bytes())
    for _ in range(300):
        pos = rng.randrange(24, len(data))
        data[pos] = rng.randrange(256)
    p = tmp_path / f"flip{seed}.pcap"
    p.write_bytes(bytes(data))
    analyze(p)   # must not raise


def test_corrupt_pcapng(tmp_path):
    src = bytearray((PCAPS / "11_mixed_outage_and_attack.pcapng").read_bytes())
    src[40:44] = b"\xff\xff\xff\x7f"
    p = tmp_path / "bad.pcapng"
    p.write_bytes(bytes(src))
    analyze(p)


def test_html_escapes_packet_strings():
    rep = analyze(PCAPS / "13_malicious_dns_names.pcap")
    html = render_html(report_to_dict(rep))
    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_cli_does_not_interpret_markup_from_packets():
    rep = analyze(PCAPS / "13_malicious_dns_names.pcap")
    con = Console(record=True, width=200)
    _print_report(con, report_to_dict(rep), verbose=True)
    assert "[red]rich-markup[/red]" in con.export_text()


def test_anonymize_removes_addresses():
    rep = analyze(PCAPS / "07_arp_spoofing.pcap")
    out = str(anonymize_report(report_to_dict(rep)))
    assert "192.168.1." not in out
    assert "de:ad:be:ef:00:66" not in out
