<a id="top"></a>
```
     ██████╗ ███████╗████████╗███████╗ ██████╗████████╗
     ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
     ██║  ██║█████╗     ██║   █████╗  ██║        ██║   
     ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   
     ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   
     ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   
```

**Cross-Platform Network Stealth Device Detection & Analysis Tool**

[![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat&logo=windows&logoColor=white)](#windows)
[![macOS](https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white)](#macos)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](#linux)

## Features

▸ **Stealth Detection** - Identify devices that respond to ARP but not higher-layer protocols  
▸ **Multi-Protocol Probing** - Test ICMP, UDP, and TCP responses to classify device behavior  
▸ **Security Analysis** - Detect firewalls, security configurations, and stealth settings  
▸ **Concurrent Scanning** - High-performance threaded scanning with configurable workers  
▸ **Vendor Identification** - MAC address OUI lookup for device manufacturer detection  
▸ **Rich Output** - Beautiful table formatting and machine-readable JSON reports  
▸ **Auto-Discovery** - Automatic subnet detection using network interface analysis  
▸ **Cross-Platform** - Native Python support for Windows, macOS, and Linux  

---

## ◆ Windows <a id="windows"></a>[![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat&logo=windows&logoColor=white)](#top)

### Prerequisites
▪ Windows 10/11 or Windows Server 2016+  
▪ Python 3.8+ ([Download Python](https://www.python.org/downloads/windows/))  
▪ Administrator privileges (required for raw socket access)  
▪ Npcap or WinPcap (for packet capture functionality)  

### Installation
```powershell
# Clone repository
git clone https://github.com/yynka/detect.git
cd detect

# Setup virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install scapy psutil rich netaddr
```

### Usage
```powershell
# Run as Administrator
# Scan default subnet (auto-detected)
python windows.py

# Scan specific subnet
python windows.py 192.168.1.0/24

# Scan with custom subnet range
python windows.py 10.0.0.0/16
```

※ **Note:** Requires running from Administrator Command Prompt or PowerShell for Npcap access

---

## ◆ macOS <a id="macos"></a>[![macOS](https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white)](#top)

### Prerequisites
▪ macOS 10.14+ (Mojave or later)  
▪ Python 3.8+ (use Homebrew for best compatibility)  
▪ Administrator privileges (`sudo` access)  
▪ Raw socket access permissions  

### Installation
```bash
# Install Python via Homebrew (recommended)
brew install python3

# Clone repository
git clone https://github.com/yynka/detect.git
cd detect

# Setup virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip3 install scapy psutil rich netaddr
```

### Usage
```bash
# Scan default subnet (auto-detected)
sudo python3 macos.py

# Scan specific subnet
sudo python3 macos.py 192.168.1.0/24

# Scan with custom subnet range
sudo python3 macos.py 172.16.0.0/12
```

※ **Note:** Requires running with `sudo` for raw socket access and packet crafting

---

## ◆ Linux <a id="linux"></a>[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](#top)

### Prerequisites
▪ Linux distribution with Python 3.8+ support  
▪ `sudo` privileges  
▪ Raw socket capabilities  
▪ Network utilities (ip, route commands)  

### Installation
```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip

# Clone repository
git clone https://github.com/yynka/detect.git
cd detect

# Setup virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install scapy psutil rich netaddr
```

### Usage
```bash
# Scan default subnet (auto-detected)
sudo python3 linux.py

# Scan specific subnet
sudo python3 linux.py 192.168.1.0/24

# Scan with custom subnet range
sudo python3 linux.py 10.0.0.0/8
```

※ **Note:** Requires running with `sudo` for raw socket access and network interface inspection

---

## ※ Command Reference

### Universal Command Format
All platforms support the same command structure:

| Platform | Command Format | Privilege Requirement |
|----------|----------------|----------------------|
| **Windows** | `python windows.py [subnet]` | Administrator shell |
| **macOS** | `sudo python3 macos.py [subnet]` | sudo privileges |
| **Linux** | `sudo python3 linux.py [subnet]` | sudo privileges |

### Subnet Specification
| Format | Description | Example |
|--------|-------------|---------|
| **Auto-detect** | No subnet specified (default) | `python3 linux.py` |
| **CIDR Notation** | Network with prefix length | `python3 linux.py 192.168.1.0/24` |
| **Large Networks** | Enterprise or campus networks | `python3 linux.py 10.0.0.0/8` |

## Usage Examples

### Basic Stealth Detection
```bash
# Auto-detect and scan local subnet
# Windows
python windows.py

# macOS
sudo python3 macos.py

# Linux
sudo python3 linux.py
```

### Targeted Network Scanning
```bash
# Scan specific corporate network
# Windows
python windows.py 172.16.0.0/12

# macOS
sudo python3 macos.py 172.16.0.0/12

# Linux
sudo python3 linux.py 172.16.0.0/12
```

### Home Network Analysis
```bash
# Scan typical home network ranges
# Windows
python windows.py 192.168.1.0/24

# macOS
sudo python3 macos.py 192.168.0.0/24

# Linux
sudo python3 linux.py 10.0.0.0/24
```

## Technical Implementation

### Detection Methodology
▪ **ARP Discovery** - Broadcast ARP requests to identify active Layer 2 devices  
▪ **ICMP Probing** - Send ping requests to test Layer 3 responsiveness  
▪ **UDP Probing** - Test common UDP services (mDNS:5353, SSDP:1900, NetBIOS:137)  
▪ **TCP Probing** - Send SYN packets to common ports (HTTP:80, HTTPS:443)  
▪ **Stealth Classification** - Devices responding to ARP but not higher protocols  

### Windows Implementation
▪ **Technology:** Scapy with Npcap integration  
▪ **Method:** Raw socket packet crafting and analysis  
▪ **Privileges:** Administrator shell required for Npcap access  
▪ **Features:** Cross-platform privilege detection with ctypes  

### macOS Implementation
▪ **Technology:** Scapy with native BSD socket support  
▪ **Method:** Raw socket operations with packet filter integration  
▪ **Privileges:** Root access required for raw socket creation  
▪ **Features:** Native network interface detection via psutil  

### Linux Implementation
▪ **Technology:** Scapy with iptables and netfilter integration  
▪ **Method:** Raw socket packet injection and capture  
▪ **Privileges:** Root access required for socket operations  
▪ **Features:** Fallback subnet detection using ip route command  

## Security Analysis Benefits

▪ **Network Visibility** - Discover devices hiding from standard network scans  
▪ **Security Assessment** - Identify devices with advanced firewall configurations  
▪ **Stealth Detection** - Find devices using network stealth or evasion techniques  
▪ **Compliance Monitoring** - Verify security policy implementation across devices  
▪ **Threat Hunting** - Detect potentially malicious devices avoiding detection  
▪ **Asset Discovery** - Complete network inventory including hidden devices  