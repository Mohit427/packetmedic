"""Evidence: pull the exact packets behind a finding out of the original capture."""
from __future__ import annotations

from ..config import DEFAULT_SETTINGS, Settings
from ..ingest.decode import SUPPORTED_LINKTYPES, dissect, to_record
from ..ingest.pcapfile import RawFrame, iter_raw_frames, write_pcap
from ..models import ACK, FIN, PSH, RST, SYN, PacketRecord

_DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE"}
_RCODES = {0: "OK", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def collect_frames(path: str, frames: set[int], settings: Settings = DEFAULT_SETTINGS) -> list[RawFrame]:
    out: list[RawFrame] = []
    if not frames:
        return out
    last = max(frames)
    for f in iter_raw_frames(path, settings.limits, []):
        if f.index in frames:
            out.append(f)
        if f.index >= last:
            break
    return out


def export_evidence_pcap(path: str, frames: list[int], out_path: str,
                         settings: Settings = DEFAULT_SETTINGS) -> int:
    return write_pcap(out_path, collect_frames(path, set(frames), settings))


def _flags(f: int) -> str:
    names = [n for bit, n in ((SYN, "SYN"), (ACK, "ACK"), (FIN, "FIN"), (RST, "RST"), (PSH, "PSH")) if f & bit]
    return ",".join(names)


def summarize(r: PacketRecord) -> str:
    """Our own one-line description of a packet (Wireshark 'Info' style)."""
    if r.arp:
        a = r.arp
        if a.op == 1:
            if a.psrc == a.pdst:
                return f"ARP announcement: {a.psrc} is at {a.hwsrc}"
            return f"ARP who has {a.pdst}? tell {a.psrc} ({a.hwsrc})"
        return f"ARP reply: {a.psrc} is at {a.hwsrc} (sent to {a.pdst})"
    if r.dns:
        d = r.dns
        if not d.is_response:
            return f"DNS query #{d.txid} for {d.qname}"
        ans = ", ".join(a for a, _ in d.answers) or _RCODES.get(d.rcode, str(d.rcode))
        return f"DNS answer #{d.txid} {d.qname} -> {ans} (IP TTL {r.ip_ttl})"
    if r.dhcp:
        d = r.dhcp
        kind = _DHCP_TYPES.get(d.msg_type, str(d.msg_type))
        extra = ""
        if d.server_id:
            extra = f" from server {d.server_id}"
        if d.routers or d.dns_servers:
            extra += f" (router {', '.join(d.routers) or '-'}, DNS {', '.join(d.dns_servers) or '-'})"
        return f"DHCP {kind} for {d.client_mac}{extra}"
    if r.icmp:
        i = r.icmp
        if i.type == 3 and i.code == 4:
            return f"ICMP 'packet too big' - path MTU {i.mtu}"
        return f"ICMP type {i.type} code {i.code}"
    if r.proto == "TCP":
        return (f"TCP {r.sport} -> {r.dport} [{_flags(r.tcp_flags)}] seq={r.seq} "
                f"ack={r.ack} len={r.payload_len}")
    if r.proto == "UDP":
        return f"UDP {r.sport} -> {r.dport} len={r.payload_len}"
    return r.proto


def packet_table(path: str, frames: list[int], start_ts: float, limit: int = 60,
                 settings: Settings = DEFAULT_SETTINGS) -> list[dict]:
    rows = []
    for f in collect_frames(path, set(frames[:limit]), settings):
        if f.linktype not in SUPPORTED_LINKTYPES:
            continue
        try:
            r = to_record(dissect(f), f)
        except Exception:
            rows.append({"frame": f.index, "time": round(f.ts - start_ts, 4), "source": "?",
                         "destination": "?", "protocol": "?", "info": "(could not decode)"})
            continue
        proto = "DNS" if r.dns else "DHCP" if r.dhcp else r.proto
        rows.append({
            "frame": r.frame,
            "time": round(r.ts - start_ts, 4),
            "source": r.src_ip or r.src_mac or "",
            "destination": r.dst_ip or r.dst_mac or "",
            "protocol": proto,
            "info": summarize(r),
        })
    return rows
