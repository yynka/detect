# Network Stealth Device Detector

Detects devices on your network that respond to ARP but not to higher-layer protocols (ICMP, UDP, TCP), which may indicate security configurations, firewalls, or stealth settings.

## What It Detects

These scripts identify "hidden" or "stealth" devices that:
- ✅ Respond to ARP requests (Layer 2) 
- ❌ Don't respond to ICMP pings
- ❌ Don't respond to UDP probes (mDNS, SSDP, NetBIOS)
- ❌ Don't respond to TCP SYN probes (ports 80, 443)

Such devices may have:
- Firewall configurations blocking higher-layer protocols
- Security hardening that disables unnecessary services
- Stealth or monitoring configurations
- Industrial/IoT devices with minimal network stacks

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Linux
```bash
sudo python3 linux.py [subnet]
```

### macOS  
```bash
sudo python3 macos.py [subnet]
```

### Windows
```bash
# Run from Administrator command prompt
python windows.py [subnet]
```

### Examples
```bash
# Auto-detect subnet
sudo python3 linux.py

# Specify subnet manually
sudo python3 linux.py 192.168.1.0/24
```

## Output

The scripts provide both human-readable table output (if `rich` is installed) and machine-readable JSON output.

### Example Output
```
Hidden devices on 192.168.1.0/24 (2)
┌─────────────────┬───────────────────┬──────────────────────────┐
│ IP              │ MAC               │ Vendor                   │
├─────────────────┼───────────────────┼──────────────────────────┤
│ 192.168.1.100   │ aa:bb:cc:dd:ee:ff │ Unknown                  │
│ 192.168.1.200   │ 11:22:33:44:55:66 │ Raspberry Pi Foundation  │
└─────────────────┴───────────────────┴──────────────────────────┘
```

## Requirements

- **Root/Administrator privileges** (required for raw socket access)
- **Python 3.7+**
- **scapy** - For packet crafting and network scanning
- **psutil** - For cross-platform network interface detection
- **rich** - For pretty table output (optional)
- **netaddr** - For MAC address vendor lookup (optional)

## Platform Support

- **Linux** - Uses `ip route` command as fallback for subnet detection
- **macOS** - Optimized for macOS network stack  
- **Windows** - Advanced privilege checking with Npcap support 