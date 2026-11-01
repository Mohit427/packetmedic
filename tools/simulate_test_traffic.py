"""Generate a few HARMLESS test patterns so you can check PacketMedic's live capture.

Run this WHILE a live capture is recording (pmtui option 3), on a network you own.

    python tools/simulate_test_traffic.py                      # DNS tests only
    python tools/simulate_test_traffic.py --scan 192.168.1.1   # + tiny scan of YOUR router

What it does (and why it is safe):
  1. Dead DNS server: 4 DNS questions to 192.0.2.53, an address reserved for
     documentation (RFC 5737) that nobody answers.     -> FAULT: DNS failure
  2. Impossible names: 6 lookups of random *.invalid names, a TLD reserved
     to never exist (RFC 6761).                         -> FAULT: failed lookups
  3. Optional mini port scan: TCP connection attempts to 30 ports of ONE
     private address you own (e.g. your home router), ~10 per second.
     Nothing is sent after connecting; open connections are closed at once.
                                                        -> ATTACK: port scan
Only standard-library Python. No packets are forged, no traffic is intercepted.
"""
from __future__ import annotations

import argparse
import ipaddress
import random
import socket
import string
import struct
import sys
import time

DEAD_DNS = "192.0.2.53"          # RFC 5737 TEST-NET-1: never answers
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554, 993, 995,
              1723, 1900, 3306, 3389, 5000, 5353, 5900, 8000, 8008, 8080, 8443, 8888, 9000, 9100, 49152]
MAX_PORTS = 40


def dns_query_packet(name: str) -> bytes:
    txid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)   # standard query, recursion desired
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)            # type A, class IN


def dead_dns_test() -> None:
    print(f"[1/3] Sending 4 DNS questions to {DEAD_DNS} (reserved address, will never answer)...")
    for i in range(4):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        try:
            s.sendto(dns_query_packet(f"packetmedic-test{i}.example.com"), (DEAD_DNS, 53))
            s.recvfrom(512)
        except OSError:
            pass                     # timeout is the expected outcome
        finally:
            s.close()
        time.sleep(0.5)


def invalid_names_test() -> None:
    print("[2/3] Looking up 6 random *.invalid names (reserved TLD, can never exist)...")
    for _ in range(6):
        label = "pm-test-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        try:
            socket.getaddrinfo(f"{label}.invalid", 80)
        except socket.gaierror:
            pass                     # "name does not exist" is the expected outcome
        time.sleep(0.4)


def mini_scan(target: str, ports: list[int]) -> None:
    print(f"[3/3] Trying {len(ports)} TCP ports on {target} (~10 per second)...")
    open_ports = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            if s.connect_ex((target, p)) == 0:
                open_ports.append(p)
        except OSError:
            pass
        finally:
            s.close()
        time.sleep(0.1)
    print(f"      done. open ports seen: {open_ports or 'none'}")


def validate_target(t: str) -> str:
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        raise SystemExit(f"--scan needs an IP address, got {t!r}")
    if not isinstance(ip, ipaddress.IPv4Address) or not ip.is_private or ip.is_loopback \
            or str(ip).endswith(".255") or str(ip).endswith(".0"):
        raise SystemExit("--scan only accepts a single private LAN address you own "
                         "(e.g. 192.168.1.1). Loopback is not captured by NIC-level capture.")
    return str(ip)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scan", metavar="PRIVATE_IP", help="also scan 30 ports of this device you own")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = ap.parse_args()
    target = validate_target(args.scan) if args.scan else None

    print("PacketMedic harmless test-traffic generator")
    print("Make sure a live capture is RECORDING now (pmtui option 3).")
    if target:
        print(f"This will knock on {len(SCAN_PORTS)} ports of {target}. Only do this to a device YOU own.")
    if not args.yes:
        if input("Type 'yes' to continue: ").strip().lower() != "yes":
            print("Cancelled.")
            return 1
    dead_dns_test()
    invalid_names_test()
    if target:
        mini_scan(target, SCAN_PORTS[:MAX_PORTS])
    else:
        print("[3/3] Port scan skipped (use --scan <your router IP> to include it).")
    print("\nFinished. Keep the capture running ~5 more seconds, then let it stop and check the dashboard.")
    print("Expected: FAULT DNS failure (192.0.2.53), FAULT failed lookups" + (", ATTACK port scan" if target else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
