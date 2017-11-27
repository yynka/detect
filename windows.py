#!/usr/bin/env python3
"""stealth_device_detector.py — Windows‑ready edition

Detect devices on the local network that respond at Layer‑2 (ARP) but stay
silent to typical discovery probes (ICMP, UDP discovery ports, TCP SYNs).
That behaviour is common when hosts run hardening scripts such as the
attached `macos.sh`, many IoT devices in “stealth” mode, or systems behind
strict personal firewalls.

Cross‑platform goals
--------------------
* **Windows 10/11 + Npcap** (Administrator)
* **macOS 13+** (root / sudo)
* **Linux (modern kernels)** (root / sudo)

Python ≥ 3.9.  Absolutely no external shell calls for autodetection — we use
`psutil` & the stdlib for portability.

Usage
-----
```
pip install scapy psutil netaddr rich
# On Windows you must have Npcap in WinPcap‑compatible mode.

# Automatic subnet detection (best‑guess primary interface)
python stealth_device_detector.py   # run from elevated cmd / PowerShell / sudo bash

# Explicit target (works without elevation if you only read ARP cache)
python stealth_device_detector.py 192.168.50.0/24
```

JSON is always printed as the last line so caller scripts can `--json | tail -1
| jq` without parsing ANSI tables.
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
from datetime import datetime
from typing import List, Tuple

import psutil  # cross‑platform NIC inspection
from scapy.all import (ARP, ICMP, IP, TCP, UDP, Ether, sr1,  # type: ignore
                       srp)

# Optional pretty output
try:
    from rich import print as rprint  # type: ignore
    from rich.table import Table  # type: ignore
except ImportError:  # pragma: no cover
    rprint = print  # type: ignore
    Table = None  # type: ignore

# ----- Constants -----------------------------------------------------------

UDP_PROBES: List[Tuple[int, bytes]] = [
    (5353, b"\x00"),  # mDNS
    (1900, b"M-SEARCH * HTTP/1.1\r\n\r\n"),  # SSDP
    (137, b"\x00"),  # NetBIOS Name Service
]
TCP_PROBES: List[int] = [80, 443]

ProbeResult = namedtuple(
    "ProbeResult",
    "ip mac replied_arp replied_icmp replied_udp replied_tcp vendor",
)

# ----- Helper functions ----------------------------------------------------


def ensure_privileged() -> None:
    """Exit with an error if the script lacks raw‑socket privileges."""
    system = platform.system()
    if system in {"Linux", "Darwin"}:
        if os.geteuid() != 0:  # type: ignore[attr-defined]
            sys.exit("[!] Run with sudo/root for raw‑socket access")
    elif system == "Windows":
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
                sys.exit("[!] Run from an Administrator shell (needed for Npcap)")
        except AttributeError:
            # Frozen executables sometimes miss windll; best effort.
            rprint("[!] Unable to confirm Administrator privileges; continuing anyway")
    else:
        rprint(f"[?] Unknown platform {system}; privilege check skipped")


def auto_subnet() -> str:
    """Return the best‑guess primary subnet in CIDR form using psutil."""
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith(("127.", "169.254.")):
                try:
                    net = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                    # Exclude point‑to‑point /32 addresses (e.g. VPNs)
                    if net.prefixlen < 31:
                        return str(net)
                except Exception:
                    continue
    raise RuntimeError("Unable to autodetect a suitable IPv4 subnet; specify one")


# ----- Network probes ------------------------------------------------------


def run_arp_scan(net: str) -> List[Tuple[str, str]]:
    """Return list of (ip, mac) discovered via ARP broadcast."""
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


# Optional OUI/Vendor lookup ------------------------------------------------

try:
    import netaddr  # type: ignore

    def oui_lookup(mac: str) -> str:  # pragma: no cover
        try:
            return netaddr.EUI(mac).oui.registration().org
        except Exception:
            return "Unknown"

except ImportError:  # pragma: no cover

    def oui_lookup(mac: str) -> str:
        return "Unknown"


# ----- Composite probe -----------------------------------------------------


def probe_host(ip_mac: Tuple[str, str]) -> ProbeResult:
    ip, mac = ip_mac
    return ProbeResult(
        ip=ip,
        mac=mac,
        replied_arp=True,
        replied_icmp=icmp_probe(ip),
        replied_udp=udp_probe(ip),
        replied_tcp=tcp_syn_probe(ip),
        vendor=oui_lookup(mac),
    )


# ----- Discovery orchestrator ---------------------------------------------


def discover_hidden(net: str):
    arp_entries = run_arp_scan(net)
    hidden: List[ProbeResult] = []
    with fut.ThreadPoolExecutor(max_workers=32) as pool:
        for res in pool.map(probe_host, arp_entries):
            if not (res.replied_icmp or res.replied_udp or res.replied_tcp):
                hidden.append(res)
    return hidden


# ----- CLI -----------------------------------------------------------------


def main() -> None:  # pragma: no cover
    parser = argparse.ArgumentParser(description="Detect hidden hosts on a network")
    parser.add_argument("subnet", nargs="?", help="CIDR subnet to scan, e.g. 10.0.0.0/24")
    args = parser.parse_args()

    subnet = args.subnet or auto_subnet()

    hidden = discover_hidden(subnet)

    timestamp = datetime.utcnow().isoformat() + "Z"
    report = {
        "timestamp": timestamp,
        "subnet": subnet,
        "hidden_count": len(hidden),
        "devices": [d._asdict() for d in hidden],
    }

    # Fancy table for humans
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

    # Always output machine‑readable JSON on the last line
    print(json.dumps(report))


if __name__ == "__main__":
    ensure_privileged()
    main()