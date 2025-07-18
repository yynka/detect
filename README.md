# Network Stealth Device Detector

Detects devices on your network that respond to ARP but not to higher-layer protocols (ICMP, UDP, TCP), which may indicate security configurations, firewalls, or stealth settings.

For detected stealth devices, the scripts gather comprehensive information including services, shared resources, platform details, open ports, and accessibility information.

## What It Detects

These scripts identify "hidden" or "stealth" devices that:
- Respond to ARP requests (Layer 2) 
- Don't respond to ICMP pings
- Don't respond to UDP probes (mDNS, SSDP, NetBIOS)
- Don't respond to TCP SYN probes (ports 80, 443, 22, 5985)

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
sudo python3 linux.py [subnet] [options]
```

### macOS  
```bash
sudo python3 macos.py [subnet] [options]
```

### Windows
```bash
# Run from Administrator command prompt
python windows.py [subnet] [options]
```

### Command Line Options

All scripts support the following options:

- `--username USER` - Username for SSH/WinRM authentication
- `--password PASS` - Password for SSH/WinRM authentication  
- `--output-dir DIR` - Directory to save device profiles (default: profiles)
- `--detailed` - Show detailed device information in output

### Examples

```bash
# Basic scan with auto-detection
sudo python3 linux.py

# Scan specific subnet with authentication
sudo python3 linux.py 192.168.1.0/24 --username admin --password secret

# Detailed output with custom profile directory
sudo python3 macos.py --detailed --output-dir ./device_profiles

# Windows scan with WinRM authentication
python windows.py --username Administrator --password MyPassword123
```

## Output

The scripts provide multiple output formats:

### Basic Output
Shows a table of hidden devices with IP, MAC, and vendor information.

### Detailed Output (--detailed flag)
Comprehensive table showing:
- IP address and MAC address
- Vendor information
- Detected platform (Windows, macOS, Linux)
- Hostname/computer name
- Number of discovered services
- Open ports

### Device Profiles
Individual JSON files saved to the profiles directory containing:
- Basic device information (IP, MAC, hostname, vendor)
- Platform detection and OS version
- Service enumeration (running services)
- Shared resources (SMB shares, NFS exports, etc.)
- Open port scan results
- Accessibility status
- Timestamps (first seen, last seen)

### Example Profile Output
```json
{
  "ip_address": "192.168.1.100",
  "hostname": "stealth-device.local",
  "mac_address": "08:1f:3f:03:a3:03",
  "vendor": "Unknown",
  "platform": "Linux",
  "os_version": "Ubuntu 22.04.3 LTS",
  "services": [
    {
      "name": "ssh",
      "display_name": "ssh",
      "status": "Running",
      "start_type": "Enabled"
    }
  ],
  "open_ports": {
    "22": "SSH"
  },
  "is_accessible": true
}
```

## Requirements

- **Root/Administrator privileges** (required for raw socket access)
- **Python 3.7+**
- **scapy** - For packet crafting and network scanning
- **psutil** - For cross-platform network interface detection
- **rich** - For pretty table output (optional)
- **netaddr** - For MAC address vendor lookup (optional)
- **paramiko** - For SSH connections to gather detailed info (optional)
- **python-nmap** - For advanced platform detection (optional)
- **pywinrm** - For Windows WinRM connections (optional)

## Platform Support

- **Linux** - SSH-based information gathering, systemd service enumeration
- **macOS** - SSH-based information gathering, launchctl service enumeration
- **Windows** - WinRM-based information gathering, Windows service enumeration

## Security Considerations

- Credentials are used only for information gathering from detected stealth devices
- SSH and WinRM connections are established only after a device is identified as hidden
- All authentication attempts are logged for security auditing
- Device profiles are saved locally for offline analysis

## Use Cases

- **Security Auditing** - Identify devices with security hardening
- **Network Discovery** - Find devices not visible to standard scans
- **Compliance Checking** - Verify firewall configurations
- **Asset Management** - Catalog all network devices including hidden ones 