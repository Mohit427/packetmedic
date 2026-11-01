"""Consistent pseudonymisation of IP and MAC addresses in a report.

The same real address always maps to the same fake one within a report, so
the story still makes sense, but the report can be shared without exposing
the network's real addressing.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
_MAC = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")
_KEEP = {"0.0.0.0", "255.255.255.255", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


class Anonymizer:
    def __init__(self):
        self.ips: dict[str, str] = {}
        self.macs: dict[str, str] = {}

    def _ip(self, m: re.Match) -> str:
        real = m.group(0)
        if real in _KEEP:
            return real
        try:
            ipaddress.ip_address(real)
        except ValueError:
            return real      # e.g. a version number, not an address
        if real not in self.ips:
            n = len(self.ips) + 1
            self.ips[real] = f"10.255.{n // 250}.{n % 250 + 1}"
        return self.ips[real]

    def _mac(self, m: re.Match) -> str:
        real = m.group(0).lower()
        if real in _KEEP:
            return real
        if real not in self.macs:
            n = len(self.macs) + 1
            self.macs[real] = f"02:00:00:00:{n // 256:02x}:{n % 256:02x}"
        return self.macs[real]

    def text(self, s: str) -> str:
        return _IPV4.sub(self._ip, _MAC.sub(self._mac, s))

    def apply(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            return {self.apply(k) if isinstance(k, str) else k: self.apply(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [self.apply(v) for v in obj]
        return obj


def anonymize_report(data: dict) -> dict:
    out = Anonymizer().apply(data)
    out["file"]["name"] = "capture (anonymized)"
    out["anonymized"] = True
    return out
