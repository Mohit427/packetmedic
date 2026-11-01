"""Regression tests for issues found on a real Windows Wi-Fi capture (pktmon)."""
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from packetmedic.analyzer import analyze
from packetmedic.ingest.decode import wifi_to_ethernet
from packetmedic.ingest.pcapfile import RawFrame, write_pcap

PC, PC_MAC, SRV, AP = "192.168.20.101", "34:fd:70:c0:5c:1a", "203.0.113.9", "98:25:4a:25:45:ef"


def to_wifi(eth: bytes) -> bytes:
    """Re-encode an Ethernet frame the way pktmon stores Wi-Fi traffic (802.11 data, ToDS)."""
    dst, src, etype, payload = eth[0:6], eth[6:12], eth[12:14], eth[14:]
    hdr = b"\x08\x01" + b"\x00\x00" + bytes.fromhex(AP.replace(":", "")) + src + dst + b"\x00\x00"
    return hdr + b"\xaa\xaa\x03\x00\x00\x00" + etype + payload


def tcp(seq, ack, flags, payload=b"", src=PC, dst=SRV, sport=50000, dport=443, ipid=1):
    smac, dmac = (PC_MAC, AP) if src == PC else (AP, PC_MAC)
    p = Ether(src=smac, dst=dmac) / IP(src=src, dst=dst, id=ipid) / TCP(sport=sport, dport=dport, flags=flags,
                                                                       seq=seq, ack=ack)
    return bytes(p / Raw(payload)) if payload else bytes(p)


def write(tmp_path, frames, name="x.pcap"):
    path = tmp_path / name
    write_pcap(str(path), [RawFrame(i + 1, ts, 1, data, len(data)) for i, (ts, data) in enumerate(frames)])
    return path


def test_wifi_conversion_roundtrip():
    eth = tcp(1, 1, "S")
    back = wifi_to_ethernet(to_wifi(eth))
    assert back == eth


def test_wifi_frames_labelled_as_ethernet_are_decoded(tmp_path):
    frames = [(1000 + i * 0.01, to_wifi(tcp(100 + i * 10, 1, "PA", b"x" * 10, ipid=i))) for i in range(20)]
    rep = analyze(write(tmp_path, frames))
    assert rep.protocols.get("TCP") == 20 and "OTHER" not in rep.protocols


def test_keepalives_are_not_retransmissions(tmp_path):
    frames = [(1000.0, tcp(1, 1, "S")), (1000.05, tcp(1, 2, "SA", src=SRV, dst=PC, sport=443, dport=50000)),
              (1000.06, tcp(2, 2, "A")), (1000.07, tcp(2, 2, "PA", b"y" * 100))]
    t = 1001.0
    for i in range(40):                          # 1-byte probes re-using seq end-1, answered by ACK
        frames.append((t, tcp(101, 2, "A", b"\x00", ipid=100 + i)))
        frames.append((t + 0.04, tcp(2, 102, "A", src=SRV, dst=PC, sport=443, dport=50000, ipid=500 + i)))
        t += 1.0
    rep = analyze(write(tmp_path, frames))
    assert not [i for i in rep.incidents if i.kind == "tcp_retransmissions"]


def test_capture_duplicates_ignored(tmp_path):
    frames = []
    for i in range(30):                          # every packet recorded twice, 0.2 ms apart
        data = tcp(1000 + i * 100, 1, "PA", b"z" * 100, ipid=i)
        frames += [(2000 + i * 0.01, data), (2000 + i * 0.01 + 0.0002, data)]
    rep = analyze(write(tmp_path, frames))
    assert not [i for i in rep.incidents if i.kind == "tcp_retransmissions"]
    assert any("duplicate" in w for w in rep.warnings)


def test_real_retransmission_still_detected(tmp_path):
    frames = []
    for i in range(40):                          # each segment resent 0.3 s later with a NEW IP id
        frames.append((3000 + i * 0.01, tcp(1000 + i * 100, 1, "PA", b"r" * 100, ipid=i)))
        if i % 4 == 0:
            frames.append((3000 + i * 0.01 + 0.3, tcp(1000 + i * 100, 1, "PA", b"r" * 100, ipid=1000 + i)))
    frames.sort()
    rep = analyze(write(tmp_path, frames))
    assert [i for i in rep.incidents if i.kind == "tcp_retransmissions"]
