"""
Windows network stealth device detector.

Detects devices on the network that respond to ARP but not to higher-layer
protocols (ICMP, UDP, TCP), which may indicate security configurations,
firewalls, or stealth settings.
"""

from __future__ import annotations

import argparse
import concurrent.futures as fut
import ctypes
import ipaddress
import json
import os
import platform
import socket
import sys
from collections import namedtuple
from datetime import datetime, timezone
from typing import List, Tuple

import psutil
from scapy.all import (
    ARP,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    sr1,
    srp,
)

try:
    from rich import print as rprint
    from rich.table import Table
except ImportError:
    rprint = print
    Table = None

UDP_PROBES: List[Tuple[int, bytes]] = [
    (5353, b"\x00"),  # mDNS
    (1900, b"M-SEARCH * HTTP/1.1\r\n\r\n"),  # SSDP
    (137, b"\x00"),  # NetBIOS
]

TCP_PROBES: List[int] = [80, 443]

ProbeResult = namedtuple(
    "ProbeResult",
    "ip mac replied_icmp replied_udp replied_tcp vendor",
)


def ensure_privileged() -> None:
    system = platform.system()
    if system in {"Linux", "Darwin"}:
        if os.geteuid() != 0:
            sys.exit("[!] Run with sudo/root for raw-socket access")
    elif system == "Windows":
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                sys.exit("[!] Run from an Administrator shell (needed for Npcap)")
        except AttributeError:
            rprint("[!] Unable to confirm Administrator privileges; continuing anyway")
    else:
        rprint(f"[?] Unknown platform {system}; privilege check skipped")


def auto_subnet() -> str:
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith(("127.", "169.254.")):
                try:
                    net = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                    if net.prefixlen < 31:  # Exclude point-to-point connections
                        return str(net)
                except Exception:
                    continue
    raise RuntimeError("Unable to autodetect subnet; please specify one manually")


def run_arp_scan(net: str) -> List[Tuple[str, str]]:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
    answered, _ = srp(pkt, timeout=2, retry=1, verbose=False)
    return [(rcv.psrc, rcv.hwsrc) for _, rcv in answered]


def icmp_probe(ip: str) -> bool:
    pkt = IP(dst=ip) / ICMP()
    return sr1(pkt, timeout=1, verbose=False) is not None


def udp_probe(ip: str) -> bool:
    for port, payload in UDP_PROBES:
        pkt = IP(dst=ip) / UDP(dport=port, sport=port) / payload
        if sr1(pkt, timeout=1, verbose=False):
            return True
    return False


def tcp_syn_probe(ip: str) -> bool:
    for port in TCP_PROBES:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        if sr1(pkt, timeout=1, verbose=False):
            return True
    return False


try:
    import netaddr

    def oui_lookup(mac: str) -> str:
        try:
            return netaddr.EUI(mac).oui.registration().org
        except Exception:
            return "Unknown"
except ImportError:
    def oui_lookup(mac: str) -> str:
        return "Unknown"


def probe_host(ip_mac: Tuple[str, str]) -> ProbeResult:
    ip, mac = ip_mac
    return ProbeResult(
        ip=ip,
        mac=mac,
        replied_icmp=icmp_probe(ip),
        replied_udp=udp_probe(ip),
        replied_tcp=tcp_syn_probe(ip),
        vendor=oui_lookup(mac),
    )


def discover_hidden(net: str) -> List[ProbeResult]:
    arp_entries = run_arp_scan(net)
    hidden: List[ProbeResult] = []
    
    with fut.ThreadPoolExecutor(max_workers=32) as pool:
        for res in pool.map(probe_host, arp_entries):
            if not (res.replied_icmp or res.replied_udp or res.replied_tcp):
                hidden.append(res)
    
    return hidden


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect stealth/hidden devices on Windows networks"
    )
    parser.add_argument(
        "subnet", 
        nargs="?", 
        help="CIDR subnet to scan, e.g. 10.0.0.0/24"
    )
    
    args = parser.parse_args()
    subnet = args.subnet or auto_subnet()
    
    hidden = discover_hidden(subnet)
    
    timestamp = datetime.now(timezone.utc).isoformat()
    report = {
        "timestamp": timestamp,
        "subnet": subnet,
        "hidden_count": len(hidden),
        "devices": [d._asdict() for d in hidden],
    }
    
    if hidden and Table:
        table = Table(title=f"Hidden devices on {subnet} ({len(hidden)})")
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="magenta")
        table.add_column("Vendor", style="green")
        for d in hidden:
            table.add_row(d.ip, d.mac, d.vendor)
        rprint(table)
    else:
        rprint(json.dumps(report, indent=2))
    
    print(json.dumps(report))


if __name__ == "__main__":
    ensure_privileged()
    main()