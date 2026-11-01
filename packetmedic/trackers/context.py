"""Bundles all trackers and routes each packet to the ones that care."""
from __future__ import annotations

from ..config import Settings
from ..models import PacketRecord
from .arp import ArpTracker
from .dns import DnsTracker
from .flow import FlowTracker
from .misc import DhcpTracker, GeneralTracker, IcmpTracker, ScanTracker


class Context:
    def __init__(self, settings: Settings):
        self.settings = settings
        lim, th = settings.limits, settings.thresholds
        self.general = GeneralTracker(lim)
        self.flows = FlowTracker(lim)
        self.scans = ScanTracker(lim)
        self.arp = ArpTracker(lim, th)
        self.dns = DnsTracker(lim)
        self.dhcp = DhcpTracker(lim)
        self.icmp = IcmpTracker(lim)

    def observe(self, r: PacketRecord) -> None:
        self.general.observe(r)
        if r.proto == "TCP":
            self.flows.observe(r)
            self.scans.observe(r)
        elif r.proto == "ARP":
            self.arp.observe(r)
        elif r.proto == "ICMP":
            self.icmp.observe(r)
        if r.dns is not None:
            self.dns.observe(r)
        elif r.dhcp is not None:
            self.dhcp.observe(r)

    # ----------------------------------------------------------------- derived facts
    @property
    def start(self) -> float:
        return self.general.first_ts or 0.0

    @property
    def end(self) -> float:
        return self.general.last_ts or 0.0

    def gateway_ips(self, include_dhcp: bool = True) -> set[str]:
        """Best guess at the router: the IP that the main internet next-hop MAC
        originally answered ARP for, plus (optionally) DHCP 'router' options."""
        gws: set[str] = set()
        if include_dhcp and len(self.dhcp.servers) == 1:
            for s in self.dhcp.servers.values():
                gws.update(s.routers)
        if self.general.egress_macs:
            egress_mac = self.general.egress_macs.most_common(1)[0][0]
            for ip, claims in self.arp.claims.items():
                if not claims:
                    continue
                first_mac = min(claims.items(), key=lambda kv: kv[1].first)[0]
                if first_mac == egress_mac:
                    gws.add(ip)
        return gws

    def gateway_macs(self) -> set[str]:
        if not self.general.egress_macs:
            return set()
        return {self.general.egress_macs.most_common(1)[0][0]}
