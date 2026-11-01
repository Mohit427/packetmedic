"""Small shared helpers."""
from __future__ import annotations

import ipaddress
import math
import statistics
from collections import OrderedDict
from typing import Callable, Generic, Hashable, Iterable, TypeVar

K = TypeVar("K", bound=Hashable)
V = TypeVar("V")


class BoundedDict(OrderedDict, Generic[K, V]):
    """Dict with a hard size cap; the least recently used entry is evicted.

    Every tracker table uses this so a hostile capture (e.g. millions of fake
    addresses) cannot exhaust memory.
    """

    def __init__(self, maxlen: int):
        super().__init__()
        self.maxlen = maxlen
        self.evicted = 0

    def get_or_create(self, key: K, factory: Callable[[], V]) -> V:
        if key in self:
            self.move_to_end(key)
            return self[key]
        value = factory()
        self[key] = value
        if len(self) > self.maxlen:
            self.popitem(last=False)
            self.evicted += 1
        return value


def capped_add(s: set, item, cap: int) -> None:
    if len(s) < cap:
        s.add(item)


def capped_append(lst: list, item, cap: int) -> None:
    if len(lst) < cap:
        lst.append(item)


def _ip(addr: str | None):
    if not addr:
        return None
    try:
        return ipaddress.ip_address(addr)
    except ValueError:
        return None


def is_private(addr: str | None) -> bool:
    ip = _ip(addr)
    return bool(ip and (ip.is_private or ip.is_link_local or ip.is_loopback))


def is_public(addr: str | None) -> bool:
    ip = _ip(addr)
    return bool(ip and ip.is_global and not ip.is_multicast)


def is_unicast_host(addr: str | None) -> bool:
    ip = _ip(addr)
    return bool(ip and not (ip.is_multicast or ip.is_unspecified or ip.is_reserved)
                and str(ip) != "255.255.255.255")


BROADCAST_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}

_PRINTABLE = set(range(0x20, 0x7F))


def sanitize_text(raw: bytes | str | None, maxlen: int = 255) -> str:
    """Turn untrusted bytes from a packet into a short, printable string.

    Control characters are replaced; length is capped. HTML/markup escaping is
    still done separately by each output (defence in depth).
    """
    if raw is None:
        return ""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    raw = raw[: maxlen * 2]
    out = "".join(chr(b) if b in _PRINTABLE else "?" for b in raw)
    if out.endswith("."):
        out = out[:-1]
    return out[:maxlen]


def median(values: Iterable[float]) -> float:
    vals = list(values)
    return statistics.median(vals) if vals else 0.0


def percentile(values: Iterable[float], pct: float) -> float:
    vals = sorted(values)
    if not vals:
        return 0.0
    idx = min(len(vals) - 1, max(0, math.ceil(pct / 100 * len(vals)) - 1))
    return vals[idx]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def fmt_ms(seconds: float) -> str:
    return f"{seconds * 1000:.0f} ms"


def fmt_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 120:
        return f"{seconds:.1f} s"
    return f"{seconds / 60:.1f} min"


def plural(n: int, word: str, plural_word: str | None = None) -> str:
    return f"{n} {word if n == 1 else (plural_word or word + 's')}"


def join_list(items: Iterable[str], limit: int = 5) -> str:
    items = list(items)
    if len(items) > limit:
        return ", ".join(items[:limit]) + f" and {len(items) - limit} more"
    return ", ".join(items)
