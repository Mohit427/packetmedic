"""Deterministic plain-language explanations. No LLM, no network calls:
the same capture always yields the same, fully traceable wording."""
from __future__ import annotations

from typing import Callable

from ..models import Explanation, Incident, Verdict
from ..util import fmt_duration, join_list, plural


def _span(inc: Incident) -> str:
    return fmt_duration(max(0.0, inc.end - inc.start))


# ----------------------------------------------------------------------------- faults
def _retrans(inc: Incident) -> Explanation:
    m = inc.metrics
    pct = m["loss_rate"] * 100
    sym = _symptom_note(inc)
    return Explanation(
        title=f"Data getting lost on the way to/from {m['server']}",
        summary=(f"About {pct:.0f}% of the data sent between {m['server']} and "
                 f"{plural(len(m['clients']), 'device')} ({join_list(m['clients'])}) got lost and had to "
                 f"be sent again ({m['retransmissions']} re-sends over {plural(m['connections'], 'connection')}).{sym}"),
        why_it_matters="Every lost packet makes the sender wait and resend, so pages load slowly, "
                       "downloads stall and video calls freeze, even though the network looks 'up'.",
        likely_cause="A congested or overloaded link, a bad cable or switch port, weak Wi-Fi signal, "
                     "or a duplex mismatch between two network devices.",
        next_steps=["Check whether the problem affects one device (its cable/Wi-Fi) or everyone (the uplink).",
                    "Look for interface errors (CRC/drops) on the switch port or router.",
                    "Swap the cable or move closer to the access point and re-test.",
                    "If the internet uplink is saturated, find the heavy users or upgrade the link."],
        wireshark_filter=f"ip.addr=={m['server']} && tcp.analysis.retransmission")


def _refused(inc: Incident) -> Explanation:
    m = inc.metrics
    return Explanation(
        title=f"Service on {m['server']} port {m['port']} is not running",
        summary=(f"{plural(len(m['clients']), 'device')} tried to connect to {m['server']} on port "
                 f"{m['port']} {plural(m['attempts'], 'time')}, and every attempt was immediately refused. "
                 "The machine is on, but the program that should answer on that port isn't."),
        why_it_matters="Users see 'connection refused' or 'site can't be reached'. Restarting the router "
                       "won't help because the network is working fine.",
        likely_cause="The service (web server, database, app) crashed, was stopped, or is configured on "
                     "a different port, or a local firewall rule is rejecting connections.",
        next_steps=[f"Log in to {m['server']} and check that the service is running (e.g. systemctl status ...).",
                    f"Confirm it listens on port {m['port']} (netstat -ano / ss -ltnp).",
                    "Check the service's logs for a crash or configuration error.",
                    "Check host firewall rules on the server."],
        wireshark_filter=f"ip.addr=={m['server']} && tcp.port=={m['port']} && tcp.flags.reset==1")


def _unreachable(inc: Incident) -> Explanation:
    m = inc.metrics
    return Explanation(
        title=f"{m['server']} is not responding",
        summary=(f"{m['attempts']} connection attempts to {m['server']} (port {m['port']}) from "
                 f"{plural(len(m['clients']), 'device')} got no reply at all."
                 + (" A router also reported it as unreachable." if m.get("icmp_unreachable") else "")),
        why_it_matters="Anything that depends on this server hangs and eventually times out.",
        likely_cause="The server is powered off or crashed, its network cable is unplugged, routing to "
                     "it is broken, or a firewall is silently dropping the traffic.",
        next_steps=[f"Ping {m['server']} and check it is powered on and connected.",
                    "Check routing between the clients and the server (traceroute).",
                    "Review firewall rules between the two networks."],
        wireshark_filter=f"ip.dst=={m['server']} && tcp.flags.syn==1 && tcp.flags.ack==0")


def _midstream(inc: Incident) -> Explanation:
    m = inc.metrics
    attack = inc.verdict != Verdict.FAULT
    return Explanation(
        title=("Connections to {s} are being cut by forged resets" if attack
               else "Connections to {s} keep getting cut off").format(s=m["server"]),
        summary=(f"{plural(m['connections_cut'], 'connection')} to {m['server']} ended abruptly in the middle "
                 "of a transfer."
                 + (f" {m['suspicious_resets']} of the 'reset' packets look forged." if m["suspicious_resets"] else "")),
        why_it_matters="Downloads fail half way, sessions log out and apps show network errors.",
        likely_cause=("A device on the path is injecting fake TCP reset packets to kill connections "
                      "(censorship or a disruption attack)." if attack else
                      "The server application is crashing or timing out, or a firewall/NAT device is "
                      "dropping long-lived connections."),
        next_steps=(["Compare the IP TTL of the reset packets with the server's real packets.",
                     "Find which device sits between the clients and server and inspect it.",
                     "Use encrypted transports (TLS/VPN) to make injection harder."] if attack else
                    ["Check server application logs for crashes at the times shown.",
                     "Check firewall/NAT idle-timeout settings.",
                     "Check whether the server is running out of memory or connections."]),
        wireshark_filter=f"ip.addr=={m['server']} && tcp.flags.reset==1")


def _mtu(inc: Incident) -> Explanation:
    m = inc.metrics
    mtu = m["path_mtu"][0] if m["path_mtu"] else None
    return Explanation(
        title=f"Packets too big for the path between {m['sender']} and {m['receiver']}",
        summary=("Large packets from {s} to {r} don't fit through a link on the way{mtu}. "
                 "Small requests work, but anything big (page content, file transfers) stalls."
                 ).format(s=m["sender"], r=m["receiver"], mtu=f" (it only allows {mtu} bytes)" if mtu else "")
                + _symptom_note(inc),
        why_it_matters="This is the classic 'website half-loads' or 'VPN connects but nothing works' problem. "
                       "Basic tests like ping succeed, so it is often misdiagnosed.",
        likely_cause="A VPN, PPPoE or tunnel link with a smaller MTU, combined with a firewall that blocks "
                     "the ICMP 'packet too big' messages that would let devices adapt.",
        next_steps=["Lower the MTU on the affected interface/VPN (e.g. to 1400) and re-test.",
                    "Enable TCP MSS clamping on the router/firewall.",
                    "Allow ICMP type 3 code 4 ('fragmentation needed') through firewalls.",
                    f"Test with: ping -f -l 1472 {m['receiver']} (Windows) to find the largest size that works."],
        wireshark_filter=f"(icmp.type==3 && icmp.code==4) || (ip.src=={m['sender']} && tcp.len>1000 && "
                         "tcp.analysis.retransmission)")


def _latency(inc: Incident) -> Explanation:
    m = inc.metrics
    return Explanation(
        title=f"Slow responses from {m['server']}",
        summary=(f"Round trips to {m['server']} took {m['median_rtt_ms']} ms typically and up to "
                 f"{m['p95_rtt_ms']} ms ({m['samples']} measurements). On a healthy network this "
                 "is well under 100 ms."),
        why_it_matters="High delay makes every click feel sluggish and breaks real-time apps like calls and games.",
        likely_cause="A saturated internet link (someone downloading/streaming heavily), an overloaded server, "
                     "Wi-Fi interference, or a very distant server.",
        next_steps=["Check whether the delay affects all servers (local link problem) or just this one.",
                    "Look at bandwidth usage on the router for heavy users.",
                    "Test from a wired connection to rule out Wi-Fi.",
                    "If it's one server, contact its owner or check its load."],
        wireshark_filter=f"ip.addr=={m['server']} && tcp.analysis.ack_rtt > 0.5")


def _dns_failure(inc: Incident) -> Explanation:
    m = inc.metrics
    down = m.get("service_down")
    return Explanation(
        title=f"DNS server {m['server']} is not answering",
        summary=(f"{m['unanswered']} of {m['queries']} name lookups sent to {m['server']} got no answer"
                 + (f" and {m['errors']} came back with an error" if m["errors"] else "")
                 + (f" (e.g. {join_list(m['example_names'], 3)})" if m["example_names"] else "") + "."
                 + (" The machine replied that no DNS service is running." if down else "")
                 + _symptom_note(inc)),
        why_it_matters="Without DNS, devices can't turn names like google.com into addresses, so "
                       "'the internet is down' even though the connection itself works.",
        likely_cause=("The DNS service on that machine has stopped." if down else
                      "The DNS server (often the router) is down, overloaded or unreachable, or devices "
                      "were given the wrong DNS server address."),
        next_steps=[f"Try another resolver to confirm: nslookup example.com 1.1.1.1 vs nslookup example.com {m['server']}",
                    f"Restart the DNS service on {m['server']} (or the router if it's the router).",
                    "Check the DNS server address handed out by DHCP.",
                    "As a temporary fix, set a known-good DNS server on affected devices."],
        wireshark_filter=f"dns && ip.addr=={m['server']}")


def _dns_slow(inc: Incident) -> Explanation:
    m = inc.metrics
    return Explanation(
        title=f"DNS server {m['server']} is slow",
        summary=f"Name lookups through {m['server']} take about {m['median_ms']} ms each ({m['samples']} lookups).",
        why_it_matters="Every new website or app connection waits for DNS first, so everything starts slowly.",
        likely_cause="An overloaded or distant DNS server, or a slow upstream resolver.",
        next_steps=["Compare with a public resolver (1.1.1.1 / 8.8.8.8).",
                    "Enable DNS caching on the router.",
                    "Switch the DHCP-provided DNS server to a faster one."],
        wireshark_filter="dns.time > 0.5")


def _nxdomain(inc: Incident) -> Explanation:
    m = inc.metrics
    sus = inc.verdict != Verdict.FAULT
    return Explanation(
        title="Possible malware looking up random names" if sus else "Many lookups for names that don't exist",
        summary=(f"{m['failed_lookups']} lookups for {m['distinct_names']} different names failed with "
                 f"'name does not exist' (e.g. {join_list(m['example_names'], 3)}) from "
                 f"{join_list(m['clients'], 3)}."),
        why_it_matters=("Random-looking names are how some malware tries to find its control server."
                        if sus else "Usually harmless, but it can slow apps down and hide misconfigurations."),
        likely_cause=("Malware on the listed device(s) generating domain names." if sus else
                      "Typos, outdated bookmarks or app settings, or a wrong DNS search domain."),
        next_steps=(["Scan the listed device(s) with up-to-date antivirus.",
                     "Check which process makes these lookups (Sysmon / netstat -b).",
                     "Block the device from the internet until it is cleaned."] if sus else
                    ["Check app/server settings that refer to the names listed.",
                     "Check the DNS search domain configured via DHCP."]),
        wireshark_filter="dns.flags.rcode==3")


def _dhcp_none(inc: Incident) -> Explanation:
    m = inc.metrics
    return Explanation(
        title="Devices can't get an IP address",
        summary=f"{m['unanswered_requests']} requests for an IP address from {join_list(m['devices'], 3)} got no reply.",
        why_it_matters="Without an address a device can't use the network at all ('No internet', 169.254.x.x address).",
        likely_cause="The DHCP server (usually the router) is off, crashed, out of addresses, or not reachable on this network segment.",
        next_steps=["Check the router/DHCP server is running and its DHCP service is enabled.",
                    "Check the address pool isn't exhausted (too many devices).",
                    "If devices are on another VLAN, check the DHCP relay (ip helper) configuration."],
        wireshark_filter="dhcp.option.dhcp==1")


# ----------------------------------------------------------------------------- attacks / mixed
def _arp(inc: Incident) -> Explanation:
    m = inc.metrics
    ip, orig, others = m["ip"], m["original_mac"], m["other_macs"]
    if inc.verdict == Verdict.FAULT:
        return Explanation(
            title=f"Two devices are using the same IP address ({ip})",
            summary=(f"The address {ip} is being used by {plural(1 + len(others), 'different device')}: "
                     f"{orig} and {join_list(others)}. Each one behaves like a normal computer, so this looks "
                     "like a configuration mistake, not an attack."),
            why_it_matters="Traffic for that address randomly goes to one device or the other, so both "
                           "lose connection intermittently.",
            likely_cause="A device with a manually set (static) IP that is also inside the DHCP pool, or two "
                         "devices configured with the same static address.",
            next_steps=["Find both devices by their MAC addresses (router's client list / switch MAC table).",
                        "Give one of them a different address, or switch it to DHCP.",
                        "Reserve static addresses outside the DHCP range."],
            wireshark_filter=f"arp.src.proto_ipv4=={ip}")
    who = m.get("impersonator") or (others[0] if others else "an unknown device")
    gw = " (your gateway/router)" if m.get("is_gateway") else ""
    also = f" and also as {join_list(m['also_claims'])}" if m.get("also_claims") else ""
    return Explanation(
        title=f"ARP spoofing: {who} is impersonating {ip}",
        summary=(f"The device with hardware address {who} is telling the network that it is {ip}{gw}{also}. "
                 f"The real owner of {ip} is {orig}. This is a man-in-the-middle setup: traffic meant for "
                 f"{ip} is being redirected through the attacker." + _symptom_note(inc)),
        why_it_matters="The attacker can read unencrypted traffic, steal logins and cookies, alter downloads, "
                       "or simply cut people off. It often goes unnoticed for weeks.",
        likely_cause="Someone on the local network is running an ARP spoofing tool (e.g. a "
                     "man-in-the-middle toolkit), or a device there is infected with malware.",
        next_steps=[f"Find the switch port of MAC {who} (switch MAC table) and disconnect it.",
                    "Enable Dynamic ARP Inspection / DHCP snooping on managed switches.",
                    f"Set a static ARP entry for {ip} on critical machines as a stop-gap.",
                    "Change passwords used over the network during this time, and prefer HTTPS/VPN."],
        wireshark_filter=f"arp.src.hw_mac=={who} || arp.duplicate-address-detected")


def _scan(inc: Incident) -> Explanation:
    m = inc.metrics
    tgt = join_list(m["targets"], 3) if m["targets"] else "many machines"
    open_txt = (f" It found these open services: {join_list(m['open_ports'], 5)}." if m["open_ports"]
                else " No open services were found.")
    return Explanation(
        title=f"Port scan from {m['scanner']}",
        summary=(f"{m['scanner']} probed {m['ports_probed']} different ports on {tgt} with "
                 f"{m['probes']} connection attempts in {fmt_duration(m['duration_s'])}.{open_txt}"
                 + _symptom_note(inc)),
        why_it_matters="Scanning is the reconnaissance step before an attack: the scanner is mapping which "
                       "services exist so it can try to break into them.",
        likely_cause="Someone running a scanning tool (e.g. a port scanner) from that machine, or malware on it "
                     "looking for other devices to infect. It could also be an authorised security test.",
        next_steps=[f"Identify who uses {m['scanner']} and whether a security test was authorised.",
                    "If not authorised, isolate the machine and check it for malware.",
                    "Close or firewall any open services that don't need to be reachable.",
                    "Make sure exposed services are patched and use strong passwords."],
        wireshark_filter=f"ip.src=={m['scanner']} && tcp.flags.syn==1 && tcp.flags.ack==0")


def _dns_spoof(inc: Incident) -> Explanation:
    m = inc.metrics
    names = join_list(m["names"], 3) or "some websites"
    forged = f" Forged answers pointed to {join_list(m['forged_addresses'], 3)}." if m["forged_addresses"] else ""
    return Explanation(
        title="DNS answers are being forged (DNS hijacking)" if inc.verdict != Verdict.FAULT
        else "Unusual DNS answers",
        summary=(f"Lookups for {names} received answers that did not come from the real DNS server.{forged}"),
        why_it_matters="A hijacked lookup silently sends users to a fake site that can steal passwords or "
                       "serve malware, even when they typed the correct address.",
        likely_cause="An attacker on the local network (often combined with ARP spoofing) or a compromised "
                     "router answering DNS queries before the real server can.",
        next_steps=["Find the device sending the forged answers (check the evidence frames' source MAC).",
                    "Check the router's DNS settings and firmware for tampering.",
                    "Use DNS-over-HTTPS/TLS on clients; tell users not to ignore certificate warnings.",
                    "Flush DNS caches on affected devices (ipconfig /flushdns) after fixing."],
        wireshark_filter="dns.flags.response==1 && (" + " || ".join(
            f'dns.qry.name=="{n}"' for n in m["names"][:5]) + ")" if m["names"] else "dns.flags.response==1")


def _rogue_dhcp(inc: Incident) -> Explanation:
    m = inc.metrics
    rogue, legit = m["rogue_server"], m["legit_server"]
    if inc.verdict == Verdict.FAULT:
        return Explanation(
            title=f"Extra DHCP server on the network ({rogue})",
            summary=(f"Besides {legit}, a second device ({rogue}) is handing out IP addresses. It gives out the "
                     "same router and DNS settings, so it is most likely a misconfigured device rather than an attack."),
            why_it_matters="Devices may get conflicting addresses and lose connectivity at random.",
            likely_cause="A home Wi-Fi router or a VM/host with DHCP enabled plugged into the network.",
            next_steps=[f"Locate {rogue} (MAC {join_list(m['rogue_macs'])}) and disable its DHCP server.",
                        "Enable DHCP snooping on managed switches."],
            wireshark_filter=f"dhcp.option.dhcp_server_id=={rogue}")
    return Explanation(
        title=f"Rogue DHCP server {rogue} is hijacking network settings",
        summary=(f"An unauthorised DHCP server ({rogue}, MAC {join_list(m['rogue_macs'])}) is handing out "
                 f"addresses alongside the real one ({legit}). It tells devices to use router "
                 f"{join_list(m['rogue_router']) or '?'} and DNS {join_list(m['rogue_dns']) or '?'} instead of "
                 f"{join_list(m['legit_router']) or '?'} / {join_list(m['legit_dns']) or '?'}. "
                 f"{plural(m['clients_affected'], 'device')} received its settings." + _symptom_note(inc)),
        why_it_matters="Every device that accepts these settings sends its traffic and DNS lookups through the "
                       "attacker, who can watch, redirect or block everything.",
        likely_cause="An attacker running a rogue DHCP server to become the man in the middle.",
        next_steps=[f"Find and unplug the device with MAC {join_list(m['rogue_macs'])} (switch MAC table).",
                    "Enable DHCP snooping so only the real server's port may answer DHCP.",
                    "Renew the address on affected devices (ipconfig /release && ipconfig /renew).",
                    "Treat traffic from affected devices during this time as possibly intercepted."],
        wireshark_filter=f"dhcp.option.dhcp_server_id=={rogue}")


def _symptom_note(inc: Incident) -> str:
    if not inc.symptoms:
        return ""
    names = {
        "tcp_retransmissions": "lost/re-sent packets", "high_latency": "slow responses",
        "tcp_refused": "refused connections", "tcp_unreachable": "unanswered connections",
        "tcp_reset_midstream": "reset connections", "dns_spoof": "forged DNS answers",
        "dns_slow": "slow DNS", "dns_nxdomain": "failed name lookups",
    }
    parts = sorted({names.get(s.kind, s.kind) for s in inc.symptoms})
    return f" This also explains the {join_list(parts)} seen in the same traffic."


TEMPLATES: dict[str, Callable[[Incident], Explanation]] = {
    "tcp_retransmissions": _retrans, "tcp_refused": _refused, "tcp_unreachable": _unreachable,
    "tcp_reset_midstream": _midstream, "mtu_mismatch": _mtu, "high_latency": _latency,
    "dns_failure": _dns_failure, "dns_slow": _dns_slow, "dns_nxdomain": _nxdomain,
    "dhcp_no_response": _dhcp_none, "arp_conflict": _arp, "port_scan": _scan,
    "dns_spoof": _dns_spoof, "rogue_dhcp": _rogue_dhcp,
}


def explain(inc: Incident) -> Explanation:
    fn = TEMPLATES.get(inc.kind)
    if fn is None:
        return Explanation(inc.kind, "An unusual pattern was detected.", "", "", [], "")
    return fn(inc)
