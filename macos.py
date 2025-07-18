"""
macOS network stealth device detector.

Detects devices on the network that respond to ARP but not to higher-layer
protocols (ICMP, UDP, TCP), which may indicate security configurations,
firewalls, or stealth settings.

For detected stealth devices, gathers comprehensive information including
services, shared resources, platform details, and accessibility.
"""

from __future__ import annotations

import argparse
import concurrent.futures as fut
import ipaddress
import json
import os
import socket
import subprocess
import sys
import re
from collections import namedtuple
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import List, Tuple, Dict, Optional

import psutil

try:
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
except ImportError:
    sys.exit("[!] scapy is required: pip install scapy")

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


def ensure_root() -> None:
    if os.geteuid() != 0:
        sys.exit("[!] Run with sudo/root – raw socket access required")


def auto_subnet() -> str:
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


def run_arp_scan(net: str) -> List[Tuple[str, str]]:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=net)
    answered, _ = srp(pkt, timeout=2, retry=1, verbose=False)
    return [(rcv.psrc, rcv.hwsrc) for _, rcv in answered]


def icmp_probe(ip: str) -> bool:
    return sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=False) is not None


def udp_probe(ip: str) -> bool:
    for port, payload in UDP_PROBES:
        if sr1(IP(dst=ip) / UDP(dport=port, sport=port) / payload, timeout=1, verbose=False):
            return True
    return False


def tcp_syn_probe(ip: str) -> bool:
    for port in TCP_PROBES:
        if sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=1, verbose=False):
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
                if 'Mac OS' in os_name or 'macOS' in os_name or 'Darwin' in os_name:
                    return 'macOS', os_name
                elif 'Linux' in os_name:
                    return 'Linux', os_name
                elif 'Windows' in os_name:
                    return 'Windows', os_name
            
            if 'tcp' in host_info:
                for port, port_info in host_info['tcp'].items():
                    if 'product' in port_info:
                        product = port_info['product']
                        if 'Apple' in product or 'macOS' in product:
                            return 'macOS', product
                        elif 'OpenSSH' in product:
                            if 'OpenSSH_9' in product or 'OpenSSH_8' in product:
                                return 'macOS', product
                            elif 'OpenSSH_7' in product:
                                return 'Linux', product
            
            hostname = host_info.get('hostname', '')
            if hostname:
                if '.local' in hostname or 'macbook' in hostname.lower():
                    return 'macOS', hostname
                elif 'ubuntu' in hostname.lower() or 'debian' in hostname.lower():
                    return 'Linux', hostname
                    
        return 'Unknown', None
    except Exception:
        return 'Unknown', None


def get_ssh_info(ip: str, username: str = None, password: str = None, port: int = 22) -> Optional[Dict]:
    if not SSH_AVAILABLE or not username or not password:
        return None
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password, timeout=10)
        
        info = {'platform': 'Unknown', 'services': [], 'shares': []}
        
        stdin, stdout, stderr = ssh.exec_command('uname -s')
        uname = stdout.read().decode().strip()
        
        if uname == 'Darwin':
            info['platform'] = 'macOS'
            stdin, stdout, stderr = ssh.exec_command('sw_vers')
            info['os_version'] = stdout.read().decode().strip()
            
            stdin, stdout, stderr = ssh.exec_command('launchctl list | head -10')
            for line in stdout:
                line = line.strip()
                if line and not line.startswith('PID'):
                    parts = line.split()
                    if len(parts) >= 3:
                        info['services'].append(ServiceInfo(
                            name=parts[2],
                            display_name=parts[2],
                            status='Running' if parts[0] != "-" else 'Stopped',
                            start_type='Enabled'
                        ))
        
        elif uname == 'Linux':
            info['platform'] = 'Linux'
            stdin, stdout, stderr = ssh.exec_command('cat /etc/os-release | head -5')
            info['os_version'] = stdout.read().decode().strip()
            
            stdin, stdout, stderr = ssh.exec_command('systemctl list-units --type=service --state=running --no-pager | head -10')
            for line in stdout:
                if '.service' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        service_name = parts[0].replace('.service', '')
                        info['services'].append(ServiceInfo(
                            name=service_name,
                            display_name=service_name,
                            status='Running',
                            start_type='Enabled'
                        ))
        
        stdin, stdout, stderr = ssh.exec_command('hostname')
        info['hostname'] = stdout.read().decode().strip()
        
        stdin, stdout, stderr = ssh.exec_command('whoami')
        info['current_user'] = stdout.read().decode().strip()
        
        ssh.close()
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
        5986: 'WinRM-HTTPS'
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
        ping_cmd = ['ping', '-c', '1', '-W', '1000', ip]
        result = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        profile.is_accessible = result.returncode == 0
    except Exception:
        profile.is_accessible = False
    
    platform, os_info = detect_platform_nmap(ip)
    profile.platform = platform
    if os_info:
        profile.os_version = os_info
    
    profile.open_ports = scan_common_ports(ip)
    
    ssh_info = get_ssh_info(ip, username, password)
    if ssh_info:
        profile.is_accessible = True
        profile.platform = ssh_info['platform']
        profile.os_version = ssh_info.get('os_version', profile.os_version)
        profile.computer_name = ssh_info.get('hostname', profile.hostname)
        profile.last_user = ssh_info.get('current_user')
        profile.services = ssh_info.get('services', [])
        profile.shared_resources = ssh_info.get('shares', [])
    
    return profile


try:
    import netaddr

    def vendor(mac: str) -> str:
        try:
            return netaddr.EUI(mac).oui.registration().org
        except Exception:
            return get_mac_vendor(mac)
except ImportError:
    def vendor(mac: str) -> str:
        return get_mac_vendor(mac)


def probe_host(ip_mac: Tuple[str, str]) -> ProbeResult:
    ip, mac = ip_mac
    return ProbeResult(
        ip=ip,
        mac=mac,
        replied_icmp=icmp_probe(ip),
        replied_udp=udp_probe(ip),
        replied_tcp=tcp_syn_probe(ip),
        vendor=vendor(mac),
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
        description="Detect and profile stealth/hidden devices on macOS networks"
    )
    parser.add_argument(
        "subnet", 
        nargs="?", 
        help="CIDR subnet to scan, e.g. 192.168.1.0/24"
    )
    parser.add_argument(
        "--username", 
        help="Username for SSH authentication"
    )
    parser.add_argument(
        "--password", 
        help="Password for SSH authentication"
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
    ensure_root()
    main()
