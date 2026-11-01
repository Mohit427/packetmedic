"""Turn raw frame bytes into a flat PacketRecord.

Scapy is used *only* as a protocol parser here. To shrink the attack surface
(and speed things up) we enable just the dissectors PacketMedic needs; every
other protocol is left as opaque bytes.
"""
from __future__ import annotations

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.config import conf  # noqa: E402
from scapy.layers.dhcp import BOOTP, DHCP  # noqa: E402
from scapy.layers.dns import DNS, DNSQR, DNSRR  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP, ICMPerror, IPerror, TCPerror, UDPerror  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.layers.l2 import ARP, CookedLinux, Dot1Q, Ether  # noqa: E402
from scapy.packet import Padding, Raw  # noqa: E402

from ..models import ArpInfo, DhcpInfo, DnsInfo, IcmpInfo, PacketRecord  # noqa: E402
from ..util import sanitize_text  # noqa: E402
from .pcapfile import RawFrame  # noqa: E402

conf.verb = 0
_ENABLED_LAYERS = [Ether, Dot1Q, CookedLinux, ARP, IP, IPv6, TCP, UDP, ICMP, IPerror,
                   TCPerror, UDPerror, ICMPerror, DNS, DNSQR, DNSRR, BOOTP, DHCP, Raw, Padding]
try:
    conf.layers.filter(_ENABLED_LAYERS)
except Exception:  # pragma: no cover - older Scapy without layer filtering
    pass

_LINKTYPES = {1: Ether, 113: CookedLinux, 228: IP, 229: IPv6}
_RAW_IP_LINKTYPES = {12, 14, 101}
SUPPORTED_LINKTYPES = set(_LINKTYPES) | _RAW_IP_LINKTYPES


class UnsupportedLinkType(Exception):
    pass


def dissect(frame: RawFrame):
    cls = _LINKTYPES.get(frame.linktype)
    if cls is None:
        if frame.linktype in _RAW_IP_LINKTYPES and frame.data:
            cls = IPv6 if frame.data[0] >> 4 == 6 else IP
        else:
            raise UnsupportedLinkType(frame.linktype)
    return cls(frame.data)


def _mac(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = ":".join(f"{b:02x}" for b in value[:6])
    return str(value).lower()


def to_record(pkt, frame: RawFrame) -> PacketRecord:
    rec = PacketRecord(frame=frame.index, ts=frame.ts, length=frame.orig_len)

    eth = pkt.getlayer(Ether)
    if eth is not None:
        rec.src_mac = _mac(eth.src)
        rec.dst_mac = _mac(eth.dst)

    arp = pkt.getlayer(ARP)
    if arp is not None:
        rec.proto = "ARP"
        rec.arp = ArpInfo(int(arp.op), _mac(arp.hwsrc) or "", str(arp.psrc),
                          _mac(arp.hwdst) or "", str(arp.pdst))
        return rec

    ip = pkt.getlayer(IP)
    if ip is not None:
        rec.src_ip, rec.dst_ip, rec.ip_ttl = str(ip.src), str(ip.dst), int(ip.ttl)
    else:
        ip6 = pkt.getlayer(IPv6)
        if ip6 is not None:
            rec.src_ip, rec.dst_ip, rec.ip_ttl = str(ip6.src), str(ip6.dst), int(ip6.hlim)
        else:
            return rec

    tcp = pkt.getlayer(TCP)
    if tcp is not None:
        rec.proto = "TCP"
        rec.sport, rec.dport = int(tcp.sport), int(tcp.dport)
        rec.tcp_flags = int(tcp.flags)
        rec.seq, rec.ack = int(tcp.seq), int(tcp.ack)
        payload = tcp.payload
        rec.payload_len = len(bytes(payload)) if payload and not isinstance(payload, Padding) else 0
        return rec

    udp = pkt.getlayer(UDP)
    if udp is not None:
        rec.proto = "UDP"
        rec.sport, rec.dport = int(udp.sport), int(udp.dport)
        rec.payload_len = max(0, int(udp.len or 8) - 8)
        if 53 in (rec.sport, rec.dport):
            dns = pkt.getlayer(DNS)
            if dns is not None:
                rec.dns = _dns(dns)
        elif {rec.sport, rec.dport} & {67, 68}:
            if pkt.getlayer(DHCP) is not None and pkt.getlayer(BOOTP) is not None:
                rec.dhcp = _dhcp(pkt[BOOTP], pkt[DHCP])
        return rec

    icmp = pkt.getlayer(ICMP)
    if icmp is not None:
        rec.proto = "ICMP"
        rec.icmp = _icmp(pkt, icmp)
    return rec


def _as_list(field) -> list:
    if field is None:
        return []
    if isinstance(field, list):
        return field
    return [field]


def _dns(dns) -> DnsInfo:
    qname, qtype = "", 0
    questions = _as_list(dns.qd)
    if questions:
        q = questions[0]
        qname = sanitize_text(getattr(q, "qname", b""))
        qtype = int(getattr(q, "qtype", 0) or 0)
    answers: list[tuple[str, int]] = []
    for rr in _as_list(dns.an)[:32]:
        if getattr(rr, "type", None) in (1, 28):
            answers.append((sanitize_text(str(rr.rdata), 64), int(getattr(rr, "ttl", 0) or 0)))
    return DnsInfo(int(dns.id), bool(dns.qr), int(dns.rcode), qname, qtype, tuple(answers))


def _dhcp(bootp, dhcp) -> DhcpInfo:
    msg_type, server_id, routers, dns_servers = 0, None, (), ()
    for opt in dhcp.options:
        if not isinstance(opt, tuple) or len(opt) < 2:
            continue
        name, values = opt[0], opt[1:]
        if name == "message-type":
            msg_type = int(values[0]) if isinstance(values[0], int) else 0
        elif name == "server_id":
            server_id = str(values[0])
        elif name == "router":
            routers = tuple(str(v) for v in values[:8])
        elif name == "name_server":
            dns_servers = tuple(str(v) for v in values[:8])
    yiaddr = str(bootp.yiaddr) if bootp.yiaddr and str(bootp.yiaddr) != "0.0.0.0" else None
    return DhcpInfo(msg_type, int(bootp.xid), _mac(bytes(bootp.chaddr)) or "", server_id, yiaddr,
                    routers, dns_servers)


def _icmp(pkt, icmp) -> IcmpInfo:
    itype, code = int(icmp.type), int(icmp.code)
    mtu = None
    if itype == 3 and code == 4:
        mtu = int(getattr(icmp, "nexthopmtu", 0) or 0) or None
    inner = None
    ipe = pkt.getlayer(IPerror)
    if ipe is not None:
        proto, sport, dport = "OTHER", 0, 0
        tcpe, udpe = pkt.getlayer(TCPerror), pkt.getlayer(UDPerror)
        if tcpe is not None:
            proto, sport, dport = "TCP", int(tcpe.sport), int(tcpe.dport)
        elif udpe is not None:
            proto, sport, dport = "UDP", int(udpe.sport), int(udpe.dport)
        inner = (str(ipe.src), str(ipe.dst), proto, sport, dport)
    return IcmpInfo(itype, code, mtu, inner)
