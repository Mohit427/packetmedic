"""Generate labeled sample captures for PacketMedic.

Every capture here is SYNTHETIC: packets are built with Scapy to simulate a
small office network (192.168.1.0/24) - no real network was captured. Each
scenario is reproducible (fixed random seed) and comes with ground truth in
truth.json so the detection accuracy can be measured with eval.py.

Usage:  python samples/generate.py
"""
from __future__ import annotations

import json
import random
import struct
from pathlib import Path

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import PcapNgWriter, mac2str, wrpcap

OUT = Path(__file__).resolve().parent / "pcaps"
BASE_TS = 1_793_520_000.0          # 2026-11-01

GW, GW_MAC = "192.168.1.1", "00:11:22:33:44:01"
ATTACKER, ATTACKER_MAC = "192.168.1.66", "de:ad:be:ef:00:66"
CLIENTS = ["192.168.1.20", "192.168.1.21", "192.168.1.22", "192.168.1.23", "192.168.1.24"]
BCAST = "ff:ff:ff:ff:ff:ff"
MACS: dict[str, str] = {GW: GW_MAC, ATTACKER: ATTACKER_MAC}
WEB_SITES = {"example.com": "93.184.216.34", "news.example.org": "203.0.113.15",
             "cdn.example.net": "198.51.100.25", "mail.example.com": "203.0.113.25",
             "docs.example.org": "198.51.100.44", "api.example.net": "203.0.113.77"}


def mac_of(ip: str) -> str:
    if ip in MACS:
        return MACS[ip]
    if ip.startswith("192.168.1."):
        return "02:00:00:00:01:%02x" % int(ip.rsplit(".", 1)[1])
    return GW_MAC          # off-net hosts are reached through the gateway


def is_local(ip: str) -> bool:
    return ip.startswith("192.168.1.")


class Capture:
    def __init__(self, seed: int):
        self.pkts: list = []
        self.rng = random.Random(seed)

    def add(self, t: float, pkt) -> None:
        pkt.time = BASE_TS + t
        self.pkts.append(pkt)

    def eth(self, src: str, dst: str, src_mac: str | None = None, dst_mac: str | None = None):
        s = src_mac or (mac_of(src) if is_local(src) else GW_MAC)
        d = dst_mac or (mac_of(dst) if is_local(dst) else GW_MAC)
        return Ether(src=s, dst=d)

    def ip(self, src, dst, **kw):
        ttl = kw.pop("ttl", None)
        if ttl is None:
            ttl = 128 if src in CLIENTS else 64 if is_local(src) else 52
        return IP(src=src, dst=dst, ttl=ttl)

    # ------------------------------------------------------------------ protocols
    def tcp_session(self, t, client, server, sport=443, rtt=0.03, segments=12, seg_len=1448,
                    loss=(), rto=0.25, request=320, close=True, blackhole_over=None,
                    small_first=False, client_mac=None, server_mac=None, server_ttl=None) -> float:
        cport = self.rng.randint(49152, 65000)
        c_isn, s_isn = self.rng.randint(1, 2**31), self.rng.randint(1, 2**31)
        ce = lambda: self.eth(client, server, src_mac=client_mac, dst_mac=server_mac)   # noqa: E731
        se = lambda: self.eth(server, client, src_mac=server_mac, dst_mac=client_mac)   # noqa: E731
        cip = lambda: self.ip(client, server)                                           # noqa: E731
        sip = lambda: self.ip(server, client, ttl=server_ttl)                           # noqa: E731
        self.add(t, ce() / cip() / TCP(sport=cport, dport=sport, flags="S", seq=c_isn))
        self.add(t + rtt, se() / sip() / TCP(sport=sport, dport=cport, flags="SA", seq=s_isn, ack=c_isn + 1))
        self.add(t + rtt + 0.0002, ce() / cip() / TCP(sport=cport, dport=sport, flags="A", seq=c_isn + 1, ack=s_isn + 1))
        tr = t + rtt + 0.0004
        c_next = c_isn + 1 + request
        self.add(tr, ce() / cip() / TCP(sport=cport, dport=sport, flags="PA", seq=c_isn + 1, ack=s_isn + 1)
                 / Raw(b"G" * request))

        # server data: (seq, len, ts, received_by_client)
        sends = []
        seq = s_isn + 1
        start = tr + rtt
        sizes = ([200] if small_first else []) + [seg_len] * segments
        for i, ln in enumerate(sizes):
            ts = start + i * 0.0008
            lost = i in loss
            too_big = blackhole_over is not None and ln > blackhole_over
            sends.append((seq, ln, ts, not lost and not too_big))
            if lost:
                sends.append((seq, ln, ts + rto, True))
            if too_big:
                for k in range(3):
                    sends.append((seq, ln, ts + rto * (2 ** k), False))
            seq += ln
        s_end = seq
        received: set[int] = set()
        seqs = sorted({s for s, _, _, _ in sends})
        for s, ln, ts, ok in sorted(sends, key=lambda x: x[2]):
            self.add(ts, se() / sip() / TCP(sport=sport, dport=cport, flags="PA", seq=s, ack=c_next)
                     / Raw(b"D" * ln))
            if ok:
                received.add(s)
                nxt = s_isn + 1
                for q in seqs:
                    if q in received and q == nxt:
                        nxt = q + next(l for qq, l, _, _ in sends if qq == q)
                self.add(ts + 0.0002, ce() / cip() / TCP(sport=cport, dport=sport, flags="A", seq=c_next, ack=nxt))
        t_end = max(x[2] for x in sends) + 0.001
        if close and blackhole_over is None:
            self.add(t_end, se() / sip() / TCP(sport=sport, dport=cport, flags="FA", seq=s_end, ack=c_next))
            self.add(t_end + 0.0002, ce() / cip() / TCP(sport=cport, dport=sport, flags="FA", seq=c_next, ack=s_end + 1))
            self.add(t_end + rtt, se() / sip() / TCP(sport=sport, dport=cport, flags="A", seq=s_end + 1, ack=c_next + 1))
        return t_end + rtt

    def dns(self, t, client, server, name, answer=None, rcode=0, delay=0.02, respond=True,
            txid=None, server_ttl=None, retries=0):
        txid = self.rng.randint(1, 65535) if txid is None else txid
        cport = self.rng.randint(49152, 65000)
        for k in range(retries + 1):
            self.add(t + k * 1.0, self.eth(client, server) / self.ip(client, server)
                     / UDP(sport=cport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=name, qtype="A")))
        if respond:
            an = [DNSRR(rrname=name, type="A", ttl=300, rdata=answer)] if answer else None
            self.add(t + delay, self.eth(server, client) / self.ip(server, client, ttl=server_ttl)
                     / UDP(sport=53, dport=cport)
                     / DNS(id=txid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name, qtype="A"), an=an))
        return txid, cport

    def arp_request(self, t, src_ip, target_ip, src_mac=None):
        m = src_mac or mac_of(src_ip)
        self.add(t, Ether(src=m, dst=BCAST) / ARP(op=1, hwsrc=m, psrc=src_ip, hwdst="00:00:00:00:00:00", pdst=target_ip))

    def arp_reply(self, t, claimed_ip, claimed_mac, to_ip, to_mac=None):
        to_mac = to_mac or mac_of(to_ip)
        self.add(t, Ether(src=claimed_mac, dst=to_mac) / ARP(op=2, hwsrc=claimed_mac, psrc=claimed_ip,
                                                              hwdst=to_mac, pdst=to_ip))

    def arp_exchange(self, t, asker, target, answer_mac=None):
        self.arp_request(t, asker, target)
        self.arp_reply(t + 0.0005, target, answer_mac or mac_of(target), asker)

    def gratuitous(self, t, ip, mac):
        self.add(t, Ether(src=mac, dst=BCAST) / ARP(op=1, hwsrc=mac, psrc=ip, hwdst="00:00:00:00:00:00", pdst=ip))

    def dhcp_msg(self, t, kind, xid, client_mac, server=None, server_mac=None, yiaddr="0.0.0.0",
                 router=None, dns=None):
        opts = [("message-type", kind)]
        if server:
            opts.append(("server_id", server))
        if kind in ("offer", "ack"):
            opts += [("subnet_mask", "255.255.255.0"), ("router", router), ("name_server", dns),
                     ("lease_time", 86400)]
        opts.append("end")
        if kind in ("discover", "request"):
            pkt = (Ether(src=client_mac, dst=BCAST) / IP(src="0.0.0.0", dst="255.255.255.255")
                   / UDP(sport=68, dport=67) / BOOTP(op=1, xid=xid, chaddr=mac2str(client_mac)) / DHCP(options=opts))
        else:
            pkt = (Ether(src=server_mac, dst=BCAST) / IP(src=server, dst="255.255.255.255", ttl=64)
                   / UDP(sport=67, dport=68)
                   / BOOTP(op=2, xid=xid, yiaddr=yiaddr, siaddr=server, chaddr=mac2str(client_mac))
                   / DHCP(options=opts))
        self.add(t, pkt)

    # ------------------------------------------------------------------ scenery
    def office_background(self, t0=0.0, duration=30.0, clients=CLIENTS, dns_server=GW, dns_ok=True,
                          sessions=14, dns_ttl=None):
        """Normal office traffic: ARP, DNS lookups and web sessions."""
        for c in clients:
            self.arp_exchange(t0 + self.rng.uniform(0, 0.5), c, GW)
        names = list(WEB_SITES)
        for _ in range(sessions):
            t = t0 + self.rng.uniform(0.5, duration - 2)
            c = self.rng.choice(clients)
            name = self.rng.choice(names)
            self.dns(t, c, dns_server, name, answer=WEB_SITES[name], respond=dns_ok,
                     delay=self.rng.uniform(0.008, 0.03), server_ttl=dns_ttl)
            if dns_ok:
                self.tcp_session(t + 0.05, c, WEB_SITES[name], rtt=self.rng.uniform(0.018, 0.06),
                                 segments=self.rng.randint(6, 20))
        for _ in range(4):   # periodic ARP refreshes from the gateway
            c = self.rng.choice(clients)
            self.arp_exchange(t0 + self.rng.uniform(1, duration), GW, c)

    def write(self, name: str, pcapng: bool = False) -> None:
        self.pkts.sort(key=lambda p: float(p.time))
        path = OUT / name
        if pcapng:
            with PcapNgWriter(str(path)) as w:
                for p in self.pkts:
                    w.write(p)
        else:
            wrpcap(str(path), self.pkts)
        print(f"  wrote {name:38s} {len(self.pkts):6d} packets")


# =========================================================================== scenarios
def s01_healthy():
    c = Capture(1)
    c.office_background(duration=40, sessions=20)
    # realistic noise that must NOT raise alarms: one lost packet, one typo lookup
    c.tcp_session(20, CLIENTS[0], "203.0.113.15", segments=60, loss={30})
    c.dns(25, CLIENTS[1], GW, "exmaple.com", rcode=3)
    c.write("01_healthy_office.pcap")
    return []


def s02_retransmissions():
    c = Capture(2)
    c.office_background(duration=30)
    srv = "203.0.113.50"
    for i, cl in enumerate(CLIENTS[:3]):
        for k in range(2):
            loss = set(c.rng.sample(range(40), 5))
            c.tcp_session(3 + i * 4 + k * 2, cl, srv, segments=40, loss=loss, rtt=0.04)
    c.write("02_slow_web_retransmissions.pcap")
    return [("tcp_retransmissions", "FAULT")]


def s03_dns_down():
    c = Capture(3)
    c.office_background(duration=30, dns_ok=False, sessions=10)
    for i in range(6):   # users retrying
        c.dns(5 + i * 3, CLIENTS[i % 5], GW, "intranet.example.com", respond=False, retries=2)
    # traffic to raw IPs still works: network is up, only DNS is broken
    c.tcp_session(8, CLIENTS[0], "93.184.216.34", segments=15)
    c.tcp_session(12, CLIENTS[2], "198.51.100.25", segments=15)
    c.write("03_dns_server_down.pcap")
    return [("dns_failure", "FAULT")]


def s04_duplicate_ip():
    c = Capture(4)
    c.office_background(duration=40)
    dup = "192.168.1.50"
    mac_a, mac_b = "02:00:00:00:01:32", "0a:1b:2c:3d:4e:50"
    c.gratuitous(1.0, dup, mac_a)
    c.gratuitous(12.0, dup, mac_b)            # second machine boots with the same static IP
    for t in (5, 15, 22, 30, 36):              # gateway asks; both answer
        c.arp_request(t, GW, dup)
        c.arp_reply(t + 0.0004, dup, mac_a, GW)
        if t > 12:
            c.arp_reply(t + 0.0007, dup, mac_b, GW)
    for t in (3, 18, 27):
        c.tcp_session(t, dup, "203.0.113.15", segments=8, client_mac=mac_a)
    for t in (14, 25, 33):
        c.tcp_session(t, dup, "198.51.100.25", segments=8, client_mac=mac_b)
    c.write("04_duplicate_ip.pcap")
    return [("arp_conflict", "FAULT")]


def s05_mtu():
    c = Capture(5)
    c.office_background(duration=30)
    srv, cl = "203.0.113.80", CLIENTS[1]
    c.tcp_session(5, cl, srv, segments=6, blackhole_over=1400, small_first=True, close=False)
    c.tcp_session(14, cl, srv, segments=6, blackhole_over=1400, small_first=True, close=False)
    # the VPN router reports the problem once (later ones are filtered by a firewall)
    inner = IP(src=srv, dst=cl, ttl=50) / TCP(sport=443, dport=50000, flags="PA", seq=1)
    c.add(5.2, Ether(src=GW_MAC, dst=GW_MAC) / IP(src=GW, dst=srv, ttl=64)
          / ICMP(type=3, code=4, nexthopmtu=1400) / inner)
    c.write("05_mtu_blackhole.pcap")
    return [("mtu_mismatch", "FAULT")]


def s06_port_scan():
    c = Capture(6)
    c.office_background(duration=30)
    target = "192.168.1.30"
    open_ports = {22, 80, 443}
    ports = sorted(set(c.rng.sample(range(1, 1025), 250)) | open_ports)
    c.rng.shuffle(ports)
    t = 10.0
    for p in ports:
        sp = c.rng.randint(40000, 60000)
        seq = c.rng.randint(1, 2**31)
        c.add(t, c.eth(ATTACKER, target) / c.ip(ATTACKER, target) / TCP(sport=sp, dport=p, flags="S", seq=seq))
        if p in open_ports:
            c.add(t + 0.0004, c.eth(target, ATTACKER) / c.ip(target, ATTACKER)
                  / TCP(sport=p, dport=sp, flags="SA", seq=7, ack=seq + 1))
            c.add(t + 0.0006, c.eth(ATTACKER, target) / c.ip(ATTACKER, target)
                  / TCP(sport=sp, dport=p, flags="R", seq=seq + 1))
        else:
            c.add(t + 0.0004, c.eth(target, ATTACKER) / c.ip(target, ATTACKER)
                  / TCP(sport=p, dport=sp, flags="RA", seq=0, ack=seq + 1))
        t += 0.01
    c.write("06_port_scan.pcap")
    return [("port_scan", "ATTACK")]


def s07_arp_spoof():
    c = Capture(7)
    c.office_background(duration=40, clients=CLIENTS[1:], sessions=16)
    victim = CLIENTS[0]
    c.arp_exchange(0.3, victim, GW)
    c.arp_exchange(0.6, ATTACKER, GW)
    c.tcp_session(2, victim, "93.184.216.34", segments=10)
    t = 8.0
    while t < 38:             # poison both directions every 2 seconds
        c.arp_reply(t, GW, ATTACKER_MAC, victim)
        c.arp_reply(t + 0.001, victim, ATTACKER_MAC, GW, to_mac=GW_MAC)
        t += 2.0
    # victim traffic now flows through the attacker (seen twice on the mirror port)
    for ts in (12, 20, 28):
        c.tcp_session(ts, victim, "203.0.113.15", segments=12, rtt=0.05, server_mac=ATTACKER_MAC)
        c.tcp_session(ts + 0.0001, victim, "203.0.113.15", segments=12, rtt=0.05,
                      client_mac=ATTACKER_MAC)
    c.write("07_arp_spoofing.pcap")
    return [("arp_conflict", "ATTACK")]


def s08_dns_hijack():
    c = Capture(8)
    resolver = "8.8.8.8"
    c.office_background(duration=30, dns_server=resolver, dns_ttl=117)
    for t, name, real in ((10, "mybank.example", "93.184.216.99"), (18, "login.shop.example", "203.0.113.120")):
        victim = CLIENTS[2]
        txid, cport = c.dns(t, victim, resolver, name, answer=real, delay=0.028, server_ttl=117)
        # attacker on the LAN races a forged answer (spoofed source = resolver)
        c.add(t + 0.002, Ether(src=ATTACKER_MAC, dst=mac_of(victim)) / IP(src=resolver, dst=victim, ttl=64)
              / UDP(sport=53, dport=cport)
              / DNS(id=txid, qr=1, rd=1, ra=1, qd=DNSQR(qname=name), an=[DNSRR(rrname=name, type="A",
                                                                                ttl=600, rdata=ATTACKER)]))
        c.tcp_session(t + 0.01, victim, ATTACKER, segments=6)
    c.write("08_dns_hijack.pcap")
    return [("dns_spoof", "ATTACK")]


def _dhcp_scenario(seed, rogue_router, rogue_dns, name):
    c = Capture(seed)
    c.office_background(duration=30)
    for i, mac in enumerate(["02:aa:00:00:00:01", "02:aa:00:00:00:02", "02:aa:00:00:00:03"]):
        t = 6 + i * 6
        xid = c.rng.randint(1, 2**31)
        c.dhcp_msg(t, "discover", xid, mac)
        c.dhcp_msg(t + 0.003, "offer", xid, mac, ATTACKER, ATTACKER_MAC, f"192.168.1.{200 + i}",
                   rogue_router, rogue_dns)
        c.dhcp_msg(t + 0.015, "offer", xid, mac, GW, GW_MAC, f"192.168.1.{100 + i}", GW, GW)
        c.dhcp_msg(t + 0.02, "request", xid, mac, ATTACKER)
        c.dhcp_msg(t + 0.023, "ack", xid, mac, ATTACKER, ATTACKER_MAC, f"192.168.1.{200 + i}",
                   rogue_router, rogue_dns)
    c.write(name)


def s09_rogue_dhcp():
    _dhcp_scenario(9, ATTACKER, ATTACKER, "09_rogue_dhcp.pcap")
    return [("rogue_dhcp", "ATTACK")]


def s10_service_down_and_latency():
    c = Capture(10)
    c.office_background(duration=30)
    srv = "192.168.1.30"
    for i, cl in enumerate(CLIENTS[:4]):
        for k in range(3):
            t = 4 + i * 2 + k * 0.5
            sp, seq = c.rng.randint(49152, 65000), c.rng.randint(1, 2**31)
            c.add(t, c.eth(cl, srv) / c.ip(cl, srv) / TCP(sport=sp, dport=8080, flags="S", seq=seq))
            c.add(t + 0.0005, c.eth(srv, cl) / c.ip(srv, cl) / TCP(sport=8080, dport=sp, flags="RA",
                                                                   seq=0, ack=seq + 1))
    for i in range(4):     # far-away / overloaded remote server
        c.tcp_session(6 + i * 4, CLIENTS[i], "198.51.100.7", rtt=0.65, segments=8)
    c.write("10_service_down_and_latency.pcap")
    return [("tcp_refused", "FAULT"), ("high_latency", "FAULT")]


def s11_mixed():
    c = Capture(11)
    c.office_background(duration=30, dns_ok=False, sessions=10)
    for i in range(5):
        c.dns(4 + i * 4, CLIENTS[i], GW, "portal.example.com", respond=False, retries=1)
    target = "192.168.1.30"
    t = 12.0
    for p in range(20, 140):
        sp, seq = c.rng.randint(40000, 60000), c.rng.randint(1, 2**31)
        c.add(t, c.eth(ATTACKER, target) / c.ip(ATTACKER, target) / TCP(sport=sp, dport=p, flags="S", seq=seq))
        c.add(t + 0.0004, c.eth(target, ATTACKER) / c.ip(target, ATTACKER)
              / TCP(sport=p, dport=sp, flags="RA", seq=0, ack=seq + 1))
        t += 0.02
    c.write("11_mixed_outage_and_attack.pcapng", pcapng=True)
    return [("dns_failure", "FAULT"), ("port_scan", "ATTACK")]


def s12_second_dhcp_misconfig():
    _dhcp_scenario(12, GW, GW, "12_second_dhcp_misconfigured.pcap")
    return [("rogue_dhcp", "FAULT")]


def s13_xss_names():
    c = Capture(13)
    c.office_background(duration=20, sessions=8)
    evil = ["<script>alert('xss')</script>.evil.example", "<img src=x onerror=alert(1)>.example",
            "[red]rich-markup[/red].example", "exmaple.com", "gogle.com", "intranet.lcoal"]
    for i, n in enumerate(evil):
        c.dns(3 + i, CLIENTS[i % 5], GW, n, rcode=3)
    c.write("13_malicious_dns_names.pcap")
    return [("dns_nxdomain", "FAULT")]


def s14_malformed():
    """Valid header + a few packets, then garbage, then a record claiming to be ~4 GB."""
    c = Capture(14)
    c.office_background(duration=5, sessions=2)
    c.pkts.sort(key=lambda p: float(p.time))
    good = c.pkts[:25]
    path = OUT / "14_malformed_truncated.pcap"
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for p in good:
            raw = bytes(p)
            ts = float(p.time)
            fh.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(raw), len(raw)))
            fh.write(raw)
        rng = random.Random(14)
        for i in range(10):    # random garbage frames
            junk = bytes(rng.randrange(256) for _ in range(rng.randint(1, 80)))
            fh.write(struct.pack("<IIII", int(BASE_TS) + 6, i, len(junk), len(junk)))
            fh.write(junk)
        fh.write(struct.pack("<IIII", int(BASE_TS) + 7, 0, 0xFFFFFF00, 0xFFFFFF00))  # lie
        fh.write(b"\x00" * 40)
    print(f"  wrote {path.name:38s} (crafted: garbage + bogus 4 GB record)")
    (OUT / "15_not_a_capture.pcap").write_text("This is a text file pretending to be a pcap.\n")
    print(f"  wrote {'15_not_a_capture.pcap':38s} (text file with a .pcap extension)")
    return []


SCENARIOS = [
    ("01_healthy_office.pcap", s01_healthy),
    ("02_slow_web_retransmissions.pcap", s02_retransmissions),
    ("03_dns_server_down.pcap", s03_dns_down),
    ("04_duplicate_ip.pcap", s04_duplicate_ip),
    ("05_mtu_blackhole.pcap", s05_mtu),
    ("06_port_scan.pcap", s06_port_scan),
    ("07_arp_spoofing.pcap", s07_arp_spoof),
    ("08_dns_hijack.pcap", s08_dns_hijack),
    ("09_rogue_dhcp.pcap", s09_rogue_dhcp),
    ("10_service_down_and_latency.pcap", s10_service_down_and_latency),
    ("11_mixed_outage_and_attack.pcapng", s11_mixed),
    ("12_second_dhcp_misconfigured.pcap", s12_second_dhcp_misconfig),
    ("13_malicious_dns_names.pcap", s13_xss_names),
    ("14_malformed_truncated.pcap", s14_malformed),
]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    print("Generating synthetic sample captures ->", OUT)
    truth = {}
    for name, fn in SCENARIOS:
        expected = fn()
        truth[name] = [{"kind": k, "verdict": v} for k, v in expected]
    truth["15_not_a_capture.pcap"] = "REJECT"
    (OUT.parent / "truth.json").write_text(json.dumps(truth, indent=2))
    print("Ground truth written to samples/truth.json")


if __name__ == "__main__":
    main()
