"""
macOS network stealth device detector.

Detects devices on the network that respond to ARP but not to higher-layer
protocols (ICMP, UDP, TCP), which may indicate security configurations,
firewalls, or stealth settings.
"""

from __future__ import annotations

import argparse
import concurrent.futures as fut
import ipaddress
import json
import os
import socket
import sys
from collections import namedtuple
from datetime import datetime
from typing import List, Tuple

import psutil  # cross‑platform NIC inspection

try:
    from scapy.all import (  # type: ignore
        ARP,
        ICMP,
        IP,
        TCP,
        UDP,
        Ether,
        sr1,
        srp,
    )
except ImportError:  # pragma: no cover
    sys.exit("[!] scapy is required: pip install scapy")

# Optional pretty output
try:
    from rich import print as rprint  # type: ignore
    from rich.table import Table  # type: ignore
except ImportError:  # pragma: no cover
    rprint = print  # type: ignore
    Table = None  # type: ignore

# --------------------------- Constants ------------------------------------
UDP_PROBES: List[Tuple[int, bytes]] = [
    (5353, b"\x00"),  # mDNS
    (1900, b"M-SEARCH * HTTP/1.1\r\n\r\n"),  # SSDP
    (137, b"\x00"),  # NetBIOS Name Service
]
TCP_PROBES: List[int] = [80, 443]
ProbeResult = namedtuple(
    "ProbeResult",
    "ip mac replied_icmp replied_udp replied_tcp vendor",
)

# --------------------------- Privilege check ------------------------------

def ensure_root() -> None:
    """Ensure script is running with root privileges for raw socket access."""
    if os.geteuid() != 0:  # type: ignore[attr-defined]
        sys.exit("[!] Run with sudo/root – raw socket access required")

# --------------------------- Subnet autodetection ------------------------

def auto_subnet() -> str:
    """
    Return the first suitable IPv4 subnet in CIDR form.
    
    Uses psutil to detect non-loopback, non-link-local networks.
    """
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith(("127.", "169.254.")):
                try:
                    net = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                    if net.prefixlen < 31:
                        return str(net)
                except ValueError:
                    continue
    raise RuntimeError("Could not autodetect subnet; please specify one manually")

# --------------------------- Network probes -------------------------------

def run_arp_scan(net: str) -> List[Tuple[str, str]]:
    """
    Perform ARP scan on the given network.
    
    Args:
        net: Network in CIDR notation (e.g., '192.168.1.0/24')
        
    Returns:
        List of (ip, mac) tuples for devices that responded to ARP
    """
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=net)
    answered, _ = srp(pkt, timeout=2, retry=1, verbose=False)
    return [(rcv.psrc, rcv.hwsrc) for _, rcv in answered]

def icmp_probe(ip: str) -> bool:
    """Test if device responds to ICMP ping."""
    return sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=False) is not None

def udp_probe(ip: str) -> bool:
    """Test if device responds to UDP probes on common ports."""
    for port, payload in UDP_PROBES:
        if sr1(IP(dst=ip) / UDP(dport=port, sport=port) / payload, timeout=1, verbose=False):
            return True
    return False

def tcp_syn_probe(ip: str) -> bool:
    """Test if device responds to TCP SYN probes on common ports."""
    for port in TCP_PROBES:
        if sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=1, verbose=False):
            return True
    return False

# --------------------------- Optional OUI lookup --------------------------

try:
    import netaddr  # type: ignore

    def vendor(mac: str) -> str:  # pragma: no cover
        """Look up device vendor from MAC address OUI."""
        try:
            return netaddr.EUI(mac).oui.registration().org
        except Exception:
            return "Unknown"
except ImportError:  # pragma: no cover
    def vendor(mac: str) -> str:  # type: ignore[return-value]
        return "Unknown"

# --------------------------- Composite probe ------------------------------

def probe_host(ip_mac: Tuple[str, str]) -> ProbeResult:
    """
    Probe a single host with multiple protocols.
    
    Args:
        ip_mac: Tuple of (ip_address, mac_address)
        
    Returns:
        ProbeResult with response information
    """
    ip, mac = ip_mac
    return ProbeResult(
        ip=ip,
        mac=mac,
        replied_icmp=icmp_probe(ip),
        replied_udp=udp_probe(ip),
        replied_tcp=tcp_syn_probe(ip),
        vendor=vendor(mac),
    )

# --------------------------- Discovery orchestrator ----------------------

def discover_hidden(net: str) -> List[ProbeResult]:
    """
    Discover 'hidden' devices on the network.
    
    Hidden devices are those that respond to ARP but not to higher-layer
    protocols, which may indicate security configurations or stealth settings.
    
    Args:
        net: Network in CIDR notation
        
    Returns:
        List of ProbeResult objects for hidden devices
    """
    arp_entries = run_arp_scan(net)
    hidden: List[ProbeResult] = []
    
    with fut.ThreadPoolExecutor(max_workers=32) as pool:
        for res in pool.map(probe_host, arp_entries):
            # Device is hidden if it responds to ARP but not to higher protocols
            if not (res.replied_icmp or res.replied_udp or res.replied_tcp):
                hidden.append(res)
    
    return hidden

# --------------------------- CLI entry point ------------------------------

def main() -> None:  # pragma: no cover
    """Main entry point for the macOS stealth device detector."""
    parser = argparse.ArgumentParser(
        description="Detect stealth/hidden devices on macOS networks"
    )
    parser.add_argument(
        "subnet", 
        nargs="?", 
        help="CIDR subnet to scan, e.g. 192.168.1.0/24"
    )
    
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
    
    # Human-friendly output
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
    
    # Machine-readable JSON output (final line)
    print(json.dumps(report))

if __name__ == "__main__":
    ensure_root()
    main()
