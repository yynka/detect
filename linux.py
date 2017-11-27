import argparse
import json
import os
import subprocess
import sys
import concurrent.futures as fut
from datetime import datetime

from collections import namedtuple
from ipaddress import ip_network

try:
    from scapy.all import ARP, Ether, srp, sr1, IP, ICMP, UDP, TCP
except ImportError:
    print("[!] Scapy not found – pip install scapy", file=sys.stderr)
    sys.exit(1)

# Optional pretty output
try:
    from rich import print as rprint
    from rich.table import Table
except ImportError:
    rprint = print  # type: ignore
    Table = None    # type: ignore


ProbeResult = namedtuple("ProbeResult", "ip mac replied_arp replied_icmp replied_udp replied_tcp vendor")

UDP_PROBES = [  # port, payload
    (5353, b"\x00"),     # mDNS
    (1900, b"M-SEARCH * HTTP/1.1\r\n\r\n"),  # SSDP
    (137, b"\x00"),      # NetBIOS
]

TCP_PROBES = [80, 443]  # Could be extended


def run_arp_scan(net: str) -> list[tuple[str, str]]:
    """Return list of (ip, mac) discovered via ARP."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
    answered, _ = srp(pkt, timeout=2, retry=1, verbose=False)
    return [(rcv.psrc, rcv.hwsrc) for _, rcv in answered]


def icmp_probe(ip: str) -> bool:
    pkt = IP(dst=ip) / ICMP()
    ans = sr1(pkt, timeout=1, verbose=False)
    return ans is not None


def udp_probe(ip: str) -> bool:
    for port, payload in UDP_PROBES:
        pkt = IP(dst=ip) / UDP(dport=port, sport=port) / payload
        ans = sr1(pkt, timeout=1, verbose=False)
        if ans:
            return True
    return False


def tcp_syn_probe(ip: str) -> bool:
    for port in TCP_PROBES:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        ans = sr1(pkt, timeout=1, verbose=False)
        if ans:
            return True
    return False


def oui_lookup(mac: str) -> str:
    try:
        import netaddr
        return netaddr.EUI(mac).oui.registration().org
    except Exception:
        return "Unknown"


def probe_host(ip_mac: tuple[str, str]) -> ProbeResult:
    ip, mac = ip_mac
    return ProbeResult(
        ip=ip,
        mac=mac,
        replied_arp=True,  # by definition
        replied_icmp=icmp_probe(ip),
        replied_udp=udp_probe(ip),
        replied_tcp=tcp_syn_probe(ip),
        vendor=oui_lookup(mac),
    )


def discover_hidden(net: str):
    arp_entries = run_arp_scan(net)
    hidden = []
    with fut.ThreadPoolExecutor(max_workers=32) as pool:
        for res in pool.map(probe_host, arp_entries):
            # A device is considered hidden if it responded to ARP but not to any higher layer probe
            if not (res.replied_icmp or res.replied_udp or res.replied_tcp):
                hidden.append(res)
    return hidden


def main():
    parser = argparse.ArgumentParser(description="Detect hidden devices on local network")
    parser.add_argument("subnet", nargs="?", help="CIDR subnet to scan, e.g. 192.168.1.0/24")

    args = parser.parse_args()
    subnet = args.subnet

    if not subnet:
        # Attempt to detect active subnet via `ip route`
        try:
            route_out = subprocess.check_output(["ip", "route"], text=True)
            default_line = next(l for l in route_out.splitlines() if "kernel" in l or "src" in l)
            subnet = default_line.split()[0]
        except Exception:
            print("[!] Could not determine subnet automatically – please supply one", file=sys.stderr)
            sys.exit(1)

    hidden = discover_hidden(subnet)

    timestamp = datetime.utcnow().isoformat() + "Z"
    report = {
        "timestamp": timestamp,
        "subnet": subnet,
        "hidden_count": len(hidden),
        "devices": [res._asdict() for res in hidden],
    }

    # Console output
    if Table and hidden:
        table = Table(title=f"Hidden devices on {subnet} ({len(hidden)})")
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="magenta")
        table.add_column("Vendor", style="green")
        for d in hidden:
            table.add_row(d.ip, d.mac, d.vendor)
        rprint(table)
    else:
        print(json.dumps(report, indent=2))

    # Always dump JSON for programmatic use
    print(json.dumps(report))

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] This script needs to run with root privileges to send raw packets", file=sys.stderr)
        sys.exit(1)
    main()
