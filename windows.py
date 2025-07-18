"""
Windows network stealth device detector.

Detects devices on the network that respond to ARP but not to higher-layer
protocols (ICMP, UDP, TCP), which may indicate security configurations,
firewalls, or stealth settings.

For detected stealth devices, gathers comprehensive information including
services, shared resources, platform details, and accessibility.
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
import subprocess
import sys
import re
from collections import namedtuple
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import List, Tuple, Dict, Optional

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

try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import winrm
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False

UDP_PROBES: List[Tuple[int, bytes]] = [
    (5353, b"\x00"),  # mDNS
    (1900, b"M-SEARCH * HTTP/1.1\r\n\r\n"),  # SSDP
    (137, b"\x00"),  # NetBIOS
]

TCP_PROBES: List[int] = [80, 443, 22, 5985]

ProbeResult = namedtuple(
    "ProbeResult",
    "ip mac replied_icmp replied_udp replied_tcp vendor",
)

@dataclass
class ServiceInfo:
    name: str
    display_name: str
    status: str
    start_type: str

@dataclass
class ShareInfo:
    name: str
    path: str
    description: str

@dataclass
class DeviceProfile:
    ip_address: str
    hostname: str = None
    mac_address: str = None
    vendor: str = None
    computer_name: str = None
    os_version: str = None
    last_user: str = None
    first_seen: str = None
    last_seen: str = None
    platform: str = None
    is_accessible: bool = False
    services: List[ServiceInfo] = None
    shared_resources: List[ShareInfo] = None
    open_ports: Dict[str, str] = None

    def __post_init__(self):
        self.services = self.services or []
        self.shared_resources = self.shared_resources or []
        self.open_ports = self.open_ports or {}
        if not self.first_seen:
            self.first_seen = datetime.now(timezone.utc).isoformat()
        if not self.last_seen:
            self.last_seen = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return asdict(self)


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


def test_port_open(ip: str, port: int, timeout: int = 2) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def get_mac_vendor(mac: str) -> str:
    try:
        mac_clean = mac.replace(':', '').replace('-', '').upper()
        if len(mac_clean) < 6:
            return "Unknown"
        
        oui_prefix = mac_clean[:6]
        oui_database = {
            '001560': 'Apple, Inc.',
            '001CF0': 'Apple, Inc.',
            '000D93': 'Apple, Inc.',
            '0014A5': 'Netgear Inc.',
            '0050F2': 'Microsoft Corporation',
            '00A0C9': 'Intel Corporation',
            '001000': 'Cisco Systems, Inc.',
            '3C0630': 'Apple, Inc.',
            '3C15C2': 'Apple, Inc.',
            '081F3F': 'Unknown',
        }
        
        return oui_database.get(oui_prefix, "Unknown")
    except Exception:
        return "Unknown"


def detect_platform_nmap(ip: str) -> Tuple[str, Optional[str]]:
    if not NMAP_AVAILABLE:
        return 'Unknown', None
    
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-sV -O -T4 --version-intensity 3')
        
        if ip in nm.all_hosts():
            host_info = nm[ip]
            
            if 'osmatch' in host_info and host_info['osmatch']:
                os_name = host_info['osmatch'][0]['name']
                if 'Windows' in os_name:
                    return 'Windows', os_name
                elif 'Mac OS' in os_name or 'macOS' in os_name or 'Darwin' in os_name:
                    return 'macOS', os_name
                elif 'Linux' in os_name:
                    return 'Linux', os_name
            
            if 'tcp' in host_info:
                for port, port_info in host_info['tcp'].items():
                    if 'product' in port_info:
                        product = port_info['product']
                        if 'Microsoft' in product or 'Windows' in product:
                            return 'Windows', product
                        elif 'Apple' in product or 'macOS' in product:
                            return 'macOS', product
                        elif 'OpenSSH' in product:
                            if 'OpenSSH_9' in product or 'OpenSSH_8' in product:
                                return 'macOS', product
                            elif 'OpenSSH_7' in product:
                                return 'Linux', product
                    
        return 'Unknown', None
    except Exception:
        return 'Unknown', None


def get_winrm_info(ip: str, username: str = None, password: str = None, port: int = 5985) -> Optional[Dict]:
    if not WINRM_AVAILABLE or not username or not password:
        return None
    
    try:
        session = winrm.Session(f'http://{ip}:{port}/wsman', auth=(username, password))
        info = {'platform': 'Windows', 'services': [], 'shares': []}
        
        try:
            result = session.run_cmd('hostname')
            if result.status_code == 0:
                info['hostname'] = result.std_out.decode().strip()
        except Exception:
            pass
        
        try:
            result = session.run_ps('Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion')
            if result.status_code == 0:
                info['os_version'] = result.std_out.decode().strip()
        except Exception:
            pass
        
        try:
            result = session.run_ps('Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName, Status, StartType -First 10')
            if result.status_code == 0:
                service_lines = result.std_out.decode().strip().split('\n')
                for line in service_lines[3:]:
                    if line.strip():
                        parts = line.split(None, 3)
                        if len(parts) >= 3:
                            info['services'].append(ServiceInfo(
                                name=parts[0],
                                display_name=parts[1] if len(parts) > 1 else parts[0],
                                status=parts[2] if len(parts) > 2 else 'Unknown',
                                start_type=parts[3] if len(parts) > 3 else 'Unknown'
                            ))
        except Exception:
            pass
        
        try:
            result = session.run_ps('Get-SmbShare | Select-Object Name, Path, Description -First 5')
            if result.status_code == 0:
                share_lines = result.std_out.decode().strip().split('\n')
                for line in share_lines[3:]:
                    if line.strip():
                        parts = line.split(None, 2)
                        if len(parts) >= 2:
                            info['shares'].append(ShareInfo(
                                name=parts[0],
                                path=parts[1] if len(parts) > 1 else 'Unknown',
                                description=parts[2] if len(parts) > 2 else 'Windows Share'
                            ))
        except Exception:
            pass
        
        return info
        
    except Exception:
        return None


def scan_common_ports(ip: str) -> Dict[str, str]:
    common_ports = {
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        993: 'IMAPS',
        995: 'POP3S',
        5985: 'WinRM',
        5986: 'WinRM-HTTPS',
        3389: 'RDP'
    }
    
    open_ports = {}
    for port, service in common_ports.items():
        if test_port_open(ip, port, timeout=1):
            open_ports[str(port)] = service
    
    return open_ports


def profile_hidden_device(ip: str, mac: str, username: str = None, password: str = None) -> DeviceProfile:
    profile = DeviceProfile(ip_address=ip, mac_address=mac)
    
    try:
        profile.hostname = socket.getfqdn(ip)
    except Exception:
        profile.hostname = ip
    
    profile.vendor = get_mac_vendor(mac)
    
    try:
        ping_cmd = ['ping', '-n', '1', '-w', '1000', ip]
        result = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        profile.is_accessible = result.returncode == 0
    except Exception:
        profile.is_accessible = False
    
    platform, os_info = detect_platform_nmap(ip)
    profile.platform = platform
    if os_info:
        profile.os_version = os_info
    
    profile.open_ports = scan_common_ports(ip)
    
    # Try WinRM first for Windows
    if test_port_open(ip, 5985):
        winrm_info = get_winrm_info(ip, username, password)
        if winrm_info:
            profile.is_accessible = True
            profile.platform = 'Windows'
            profile.os_version = winrm_info.get('os_version', profile.os_version)
            profile.computer_name = winrm_info.get('hostname', profile.hostname)
            profile.services = winrm_info.get('services', [])
            profile.shared_resources = winrm_info.get('shares', [])
    
    return profile


try:
    import netaddr

    def oui_lookup(mac: str) -> str:
        try:
            return netaddr.EUI(mac).oui.registration().org
        except Exception:
            return get_mac_vendor(mac)
except ImportError:
    def oui_lookup(mac: str) -> str:
        return get_mac_vendor(mac)


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


def discover_hidden(net: str, username: str = None, password: str = None) -> List[DeviceProfile]:
    arp_entries = run_arp_scan(net)
    hidden_profiles: List[DeviceProfile] = []
    
    print(f"[*] Found {len(arp_entries)} devices via ARP scan")
    
    with fut.ThreadPoolExecutor(max_workers=16) as pool:
        probe_results = list(pool.map(probe_host, arp_entries))
    
    hidden_devices = [res for res in probe_results 
                     if not (res.replied_icmp or res.replied_udp or res.replied_tcp)]
    
    if not hidden_devices:
        print("[*] No hidden devices found")
        return []
    
    print(f"[*] Found {len(hidden_devices)} hidden devices, profiling...")
    
    for device in hidden_devices:
        print(f"[*] Profiling {device.ip} ({device.vendor})")
        profile = profile_hidden_device(device.ip, device.mac, username, password)
        hidden_profiles.append(profile)
    
    return hidden_profiles


def save_profiles(profiles: List[DeviceProfile], output_dir: str = "profiles") -> None:
    if not profiles:
        return
    
    os.makedirs(output_dir, exist_ok=True)
    
    for profile in profiles:
        filename = f"{output_dir}/{profile.ip_address.replace('.', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(profile.to_dict(), f, indent=2)
    
    print(f"[*] Saved {len(profiles)} device profiles to {output_dir}/")


def display_profiles(profiles: List[DeviceProfile]) -> None:
    if not profiles:
        return
    
    if Table:
        table = Table(title=f"Hidden Device Profiles ({len(profiles)})")
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="magenta")
        table.add_column("Vendor", style="green")
        table.add_column("Platform", style="yellow")
        table.add_column("Hostname", style="blue")
        table.add_column("Services", style="red")
        
        for profile in profiles:
            table.add_row(
                profile.ip_address,
                profile.mac_address or "N/A",
                profile.vendor or "Unknown",
                profile.platform or "Unknown",
                profile.hostname or "N/A",
                str(len(profile.services))
            )
        
        rprint(table)
    else:
        print(f"\n=== Hidden Device Profiles ({len(profiles)}) ===")
        for i, profile in enumerate(profiles, 1):
            print(f"\n[{i}] {profile.ip_address}")
            print(f"    MAC: {profile.mac_address}")
            print(f"    Vendor: {profile.vendor}")
            print(f"    Platform: {profile.platform}")
            print(f"    Hostname: {profile.hostname}")
            print(f"    Services: {len(profile.services)}")
            print(f"    Open Ports: {list(profile.open_ports.keys())}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect and profile stealth/hidden devices on Windows networks"
    )
    parser.add_argument(
        "subnet", 
        nargs="?", 
        help="CIDR subnet to scan, e.g. 10.0.0.0/24"
    )
    parser.add_argument(
        "--username", 
        help="Username for authentication"
    )
    parser.add_argument(
        "--password", 
        help="Password for authentication"
    )
    parser.add_argument(
        "--output-dir", 
        default="profiles",
        help="Directory to save device profiles"
    )
    parser.add_argument(
        "--detailed", 
        action="store_true",
        help="Show detailed device information"
    )
    
    args = parser.parse_args()
    subnet = args.subnet or auto_subnet()
    
    print(f"[*] Scanning {subnet} for hidden devices...")
    
    hidden_profiles = discover_hidden(subnet, args.username, args.password)
    
    if not hidden_profiles:
        print("[*] No hidden devices found")
        return
    
    timestamp = datetime.now(timezone.utc).isoformat()
    report = {
        "timestamp": timestamp,
        "subnet": subnet,
        "hidden_count": len(hidden_profiles),
        "devices": [profile.to_dict() for profile in hidden_profiles],
    }
    
    if args.detailed:
        display_profiles(hidden_profiles)
    else:
        if hidden_profiles and Table:
            table = Table(title=f"Hidden devices on {subnet} ({len(hidden_profiles)})")
            table.add_column("IP", style="cyan")
            table.add_column("MAC", style="magenta")
            table.add_column("Vendor", style="green")
            for profile in hidden_profiles:
                table.add_row(profile.ip_address, profile.mac_address or "N/A", profile.vendor or "Unknown")
            rprint(table)
        else:
            rprint(json.dumps(report, indent=2))
    
    save_profiles(hidden_profiles, args.output_dir)
    print(json.dumps(report))


if __name__ == "__main__":
    ensure_privileged()
    main()