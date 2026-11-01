"""Every labeled sample must produce exactly the expected (finding, verdict) pairs."""
import json
from pathlib import Path

import pytest

from packetmedic.analyzer import analyze
from packetmedic.ingest.validator import InputError

ROOT = Path(__file__).resolve().parents[1]
TRUTH = json.loads((ROOT / "samples" / "truth.json").read_text())


@pytest.mark.parametrize("name", sorted(TRUTH))
def test_sample(name):
    path = ROOT / "samples" / "pcaps" / name
    expected = TRUTH[name]
    if expected == "REJECT":
        with pytest.raises(InputError):
            analyze(path)
        return
    report = analyze(path)
    got = sorted((i.kind, i.verdict.value) for i in report.incidents)
    assert got == sorted((e["kind"], e["verdict"]) for e in expected)
    for inc in report.incidents:
        assert inc.explanation and inc.explanation.summary
        assert inc.frames, "every finding must point at evidence packets"
        assert inc.explanation.next_steps


def test_root_cause_folding():
    rep = analyze(ROOT / "samples" / "pcaps" / "05_mtu_blackhole.pcap")
    (inc,) = rep.incidents
    assert inc.kind == "mtu_mismatch"
    assert any(s.kind == "tcp_retransmissions" for s in inc.symptoms)


def test_healthy_score():
    rep = analyze(ROOT / "samples" / "pcaps" / "01_healthy_office.pcap")
    assert rep.health_score == 100 and rep.health_label == "Healthy"
