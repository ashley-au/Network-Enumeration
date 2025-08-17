# Network Enumeration Tools

![Version](https://img.shields.io/badge/version-3.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)
![Language](https://img.shields.io/badge/language-Bash-red.svg)

Two powerful, verification-based network enumeration scripts designed to improve discovery accuracy by eliminating false positives and providing comprehensive device analysis. Both scripts generate professional-grade HTML reports alongside console and text outputs.

## 🌟 Key Features

- **🔍 Multi-Method Verification**: Uses ARP, ICMP, TCP SYN, UDP, and TCP Connect probes
- **🎯 False Positive Elimination**: Only reports devices that respond to verification probes
- **📊 Professional HTML Reports**: Responsive, mobile-friendly reports with detailed device cards
- **🚀 Stealth Device Detection**: Discovers devices that block standard ping requests
- **🔧 Comprehensive Service Enumeration**: Full port scanning, OS fingerprinting, and application-specific probing
- **📱 Self-Contained Reports**: No external dependencies for viewing reports

---

## 📋 Table of Contents

- [Overview](#overview)
- [Scripts](#scripts)
- [Installation](#installation)
- [Usage](#usage)
- [Output Examples](#output-examples)
- [Methodology](#methodology)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [License](#license)

---

## 🚀 Overview

Traditional network scanning tools often produce a large number of false positives by assuming all IP addresses in a range respond without proper verification. These tools implement a robust, verification-based approach using multiple probing methods to confirm device presence before reporting results.

### The Problem with Traditional Scanners

Most network scanners work by:
1. Generating a list of all possible IPs in a range
2. Sending basic probes (usually just ping)
3. Reporting all IPs that don't explicitly respond as "down"

This leads to:
- ❌ High false positive rates
- ❌ Missed stealth devices that block ping
- ❌ Unreliable results on filtered networks

### Our Solution

These scripts implement a **verification-first approach**:
1. 🔍 **Discovery Phase**: Multiple discovery methods gather candidate IPs
2. ✅ **Verification Phase**: Each candidate tested with 5+ different probe methods
3. 📊 **Analysis Phase**: Only verified devices undergo detailed enumeration
4. 📈 **Reporting Phase**: Professional reports with detailed device information

---

## 📁 Scripts

### `network_discover.sh` - Fast Device Discovery

**Purpose**: Quick and accurate device discovery focusing solely on verifying live devices.

**Key Features**:
- 🔍 Multi-method device verification (ICMP, ARP, TCP SYN, UDP, Advanced ICMP, TCP Connect)
- 📊 Color-coded console output with status indicators (LIVE, FILTERED, DEAD)
- 📱 Professional HTML report generation
- ⚡ Fast execution without requiring root privileges
- 🎯 Designed for quick network assessments

**Best Use Cases**:
- Quick network inventory
- Regular monitoring of known networks
- Pre-assessment before comprehensive scans
- Environments where root access is limited

### `network_enum_v2.sh` - Comprehensive Network Enumeration

**Purpose**: Full-featured network enumeration with verification-based discovery plus extensive port and service scanning.

**Key Features**:
- ✅ Multi-method verification for confirming live devices
- 🔍 Full TCP and UDP port scans on verified hosts only
- 🛠️ Detailed service enumeration with version detection
- 🌐 Application-specific enumeration (SMB shares, NFS exports, HTTP services)
- 🔎 OS fingerprinting and device identification
- 📊 Comprehensive HTML reports with device cards
- 📝 Detailed text reports for technical analysis

**Best Use Cases**:
- Security assessments and penetration testing
- Comprehensive network audits
- Infrastructure documentation
- Compliance and security reporting

---

## 💻 Installation

### Prerequisites

Ensure you have the required tools installed:

**For Fedora/CentOS/RHEL**:
```bash
sudo dnf install nmap samba-client nfs-utils curl
```

**For Ubuntu/Debian**:
```bash
sudo apt update
sudo apt install nmap smbclient nfs-common curl
```

**For Arch Linux**:
```bash
sudo pacman -S nmap smbclient nfs-utils curl
```

### Download Scripts

```bash
# Clone the repository
git clone https://github.com/yourusername/network-enumeration-tools.git
cd network-enumeration-tools

# Make scripts executable
chmod +x network_discover.sh network_enum_v2.sh

# Verify installation
./network_discover.sh --help
```

---

## 📖 Usage

### Quick Device Discovery

```bash
# Basic usage - discover devices on your local network
./network_discover.sh 192.168.1.0/24

# Scan a different network range
./network_discover.sh 10.0.0.0/24

# Scan a smaller subnet
./network_discover.sh 192.168.1.100/28
```

**Example Output**:
```
==============================================
  Accurate Network Device Discovery v3.0
  Verification-Based Approach
==============================================

Starting comprehensive device discovery on 192.168.1.0/24

IP ADDRESS      STATUS     METHOD          DETAILS
----------      ------     ------          -------
192.168.1.1     LIVE       ARP             MAC: aa:bb:cc:dd:ee:ff Router
192.168.1.10    LIVE       TCP             Open ports: 22,80,443
192.168.1.15    FILTERED   TCP             Host up but filtered
192.168.1.20    LIVE       PING            Responds to ICMP

Summary: 3 live devices discovered
Note: FILTERED devices may have firewalls blocking probes

Reports generated:
  HTML Report: network_discovery_20240817_143022.html
```

### Comprehensive Network Enumeration

```bash
# Requires sudo for advanced scanning capabilities
sudo ./network_enum_v2.sh 192.168.1.0/24

# Specify custom output directory
sudo ./network_enum_v2.sh 10.0.0.0/24 /tmp/my_scan_results

# The script will create timestamped directories if none specified
sudo ./network_enum_v2.sh 172.16.0.0/16
```

**Example Output**:
```
==================================================
  Verification-Based Network Enumeration v2.0
  Verification-Based Device Discovery
==================================================

[2024-08-17 14:30:22] [INFO] Output directory: ./network_scan_verified_20240817_143022
[2024-08-17 14:30:22] [SCAN] Phase 1: Verified Discovery - Only confirmed live devices
[2024-08-17 14:30:23] [INFO] Found 45 potential hosts to verify
[2024-08-17 14:30:35] [INFO] Host verification complete: 8 confirmed live hosts
[2024-08-17 14:30:36] [SCAN] Phase 2: Port Scanning - Only on verified live hosts
[2024-08-17 14:31:15] [SCAN] Phase 3: Service Enumeration on verified hosts
[2024-08-17 14:32:22] [SCAN] Phase 4: Application-specific enumeration
[2024-08-17 14:32:45] [SCAN] Phase 5: Generating comprehensive report

=========================================
  VERIFICATION-BASED SCAN COMPLETE
=========================================
Verified Live Hosts: 8
Output Directory: ./network_scan_verified_20240817_143022
Report: ./network_scan_verified_20240817_143022/NETWORK_ENUMERATION_REPORT.txt
=========================================
```

---

## 📊 Output Examples

### HTML Reports

Both scripts generate professional HTML reports:

**Device Discovery Report Features**:
- 📊 Summary cards with device counts and methodology overview
- 🎨 Color-coded status indicators (Live, Filtered, Dead)
- 🏷️ Detection method badges showing how each device was found
- 📱 Responsive design for mobile and desktop viewing

**Comprehensive Enumeration Report Features**:
- 🗃️ Device cards with detailed information (MAC, OS, NetBIOS)
- 🔌 Service listings with port numbers and service names
- 📁 SMB shares and NFS exports when available
- 🔍 Verification method badges for each discovered device
- 📈 Methodology explanation and scan timeline

### Text Reports

The comprehensive enumeration script also generates detailed text reports:

```
=========================================
  VERIFIED NETWORK ENUMERATION REPORT
=========================================
Scan Date: Sat Aug 17 14:30:22 EDT 2024
Network Range: 192.168.1.0/24
Total Verified Hosts: 8

VERIFIED LIVE HOSTS:
-------------------
[1] 192.168.1.1
    MAC: aa:bb:cc:dd:ee:ff Router
    TCP Services: 3 ports open

[2] 192.168.1.10
    MAC: bb:cc:dd:ee:ff:11 Company
    NetBIOS: WORKSTATION01
    OS: Windows 10
    TCP Services: 12 ports open
    UDP Services: 3 ports open
```

---

## 🔬 Methodology

### Verification-Based Discovery Process

#### Phase 1: Candidate Discovery
Multiple discovery methods gather potential host candidates:

1. **ARP Discovery**: Layer 2 probes for local network devices (most reliable)
2. **Multi-Protocol Ping**: Various ICMP probe types with TCP/UDP port probes
3. **Broadcast Discovery**: IGMP and broadcast ping methods
4. **Stealth TCP Discovery**: SYN scans to discover ping-blocking devices
5. **Common IP Testing**: Tests frequently used IP addresses (routers, printers, servers)

#### Phase 2: Multi-Method Verification
Each candidate undergoes rigorous verification using up to 6 different methods:

| Method | Description | Use Case |
|--------|-------------|----------|
| **🏷️ ARP Probes** | Layer 2 discovery using ARP requests | Most reliable for local networks |
| **⚡ TCP SYN Probes** | Half-open connections to common ports | Discovers services without full connection |
| **📡 UDP Probes** | Tests common UDP services (DNS, DHCP, SNMP) | Finds UDP-only devices and services |
| **🎯 Advanced ICMP** | Multiple ICMP types (Echo, Timestamp, Address Mask) | Comprehensive ping-based detection |
| **🔗 TCP Connect** | Full TCP connections to common ports | Last resort for heavily filtered devices |
| **📊 Combined Analysis** | Cross-verification of results | Ensures accurate classification |

#### Phase 3: Comprehensive Analysis (network_enum_v2.sh only)
For verified hosts only:

1. **🔍 Full Port Scanning**: Complete TCP and UDP port enumeration
2. **🛠️ Service Detection**: Version detection and service fingerprinting
3. **🖥️ OS Fingerprinting**: Operating system identification
4. **📁 Application Enumeration**: SMB shares, NFS exports, HTTP services
5. **📊 Report Generation**: Professional HTML and detailed text reports

### Status Classifications

| Status | Description | Color Code | Meaning |
|--------|-------------|------------|---------|
| **🟢 LIVE** | Device responds to probes | Green | Confirmed active device |
| **🟡 FILTERED** | Device detected but filtered | Yellow | Firewall may be blocking probes |
| **🔴 DEAD** | No response to any probe | Red | No device at this address |

---

## 🔧 Dependencies

### Core Requirements
- **Bash 4.0+** (5.2+ recommended for best compatibility)
- **nmap** - Core network scanning engine
- **Standard Linux utilities** (grep, awk, sed, sort, etc.)

### Additional Requirements (for network_enum_v2.sh)
- **smbclient** - SMB/CIFS share enumeration
- **showmount** - NFS export discovery
- **curl** - HTTP service enumeration
- **Root privileges** - Required for advanced scanning techniques

### Installation Commands by Distribution

**Fedora/CentOS/RHEL**:
```bash
sudo dnf install nmap samba-client nfs-utils curl
```

**Ubuntu/Debian**:
```bash
sudo apt install nmap smbclient nfs-common curl
```

**Arch Linux**:
```bash
sudo pacman -S nmap smbclient nfs-utils curl
```

**Alpine Linux**:
```bash
sudo apk add nmap samba-client nfs-utils curl
```

---

## 🎯 Use Cases

### Network Administration
- **Asset Discovery**: Identify all active devices on your network
- **Network Monitoring**: Regular scans to detect new or removed devices
- **Capacity Planning**: Understanding device distribution and services

### Security Assessment
- **Penetration Testing**: Accurate target identification without false positives
- **Vulnerability Assessment**: Comprehensive service enumeration for security analysis
- **Compliance Auditing**: Generate professional reports for security compliance

### IT Support & Troubleshooting
- **Network Troubleshooting**: Quickly identify connectivity issues
- **Service Discovery**: Find specific services across your network
- **Documentation**: Generate comprehensive network documentation

---

## ⚠️ Important Notes

### Security Considerations
- **Use Responsibly**: Only scan networks you own or have explicit permission to scan
- **Rate Limiting**: Scripts include built-in delays to avoid overwhelming network devices
- **Log Review**: Always review generated logs for security incidents
- **False Positives**: While minimized, always verify critical findings manually

### Performance Considerations
- **Network Load**: Comprehensive scans generate significant network traffic
- **Time Requirements**: Full enumeration can take considerable time on large networks
- **Resource Usage**: May consume significant CPU and memory on large networks

### Legal Considerations
- **Authorization Required**: Ensure you have explicit permission to scan target networks
- **Compliance**: Follow your organization's security policies and procedures
- **Documentation**: Keep scan records for audit and compliance purposes

---

## 🔍 Advanced Usage

### Custom Network Ranges

```bash
# Scan specific IP range
./network_discover.sh 192.168.1.100-200

# Multiple small subnets
for subnet in 192.168.{1..5}.0/24; do
    ./network_discover.sh "$subnet"
done

# Large enterprise network
sudo ./network_enum_v2.sh 10.0.0.0/8 /opt/scan_results/enterprise_scan
```

### Automation and Scheduling

```bash
#!/bin/bash
# Weekly network discovery script
SCAN_DIR="/opt/network_scans/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$SCAN_DIR"

# Discover devices
./network_discover.sh 192.168.1.0/24 > "$SCAN_DIR/discovery.txt"

# Full enumeration on critical networks
sudo ./network_enum_v2.sh 192.168.1.0/24 "$SCAN_DIR/enumeration"

# Archive results
tar -czf "$SCAN_DIR.tar.gz" "$SCAN_DIR"
```

### Integration with Other Tools

```bash
# Export discovered IPs for other tools
grep "LIVE" discovery_output.txt | awk '{print $1}' > live_hosts.txt

# Use with nmap for specific scans
nmap -sV -iL live_hosts.txt

# Integration with security tools
cat live_hosts.txt | while read host; do
    nikto -h "$host"
done
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Ways to Contribute
- 🐛 **Bug Reports**: Submit detailed bug reports with reproduction steps
- 💡 **Feature Requests**: Suggest new features or improvements
- 🔧 **Code Contributions**: Submit pull requests with enhancements
- 📝 **Documentation**: Improve documentation and examples
- 🧪 **Testing**: Test on different distributions and network configurations

### Development Guidelines
1. **Code Style**: Follow existing bash scripting conventions
2. **Testing**: Test thoroughly on multiple network configurations
3. **Documentation**: Update README.md for new features
4. **Compatibility**: Ensure compatibility across different Linux distributions

### Submitting Issues
When submitting bug reports, please include:
- Operating system and version
- Script version and command used
- Network configuration details
- Complete error output
- Steps to reproduce the issue

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 📞 Support

### Getting Help
- 📖 **Documentation**: Check this README for comprehensive information
- 🐛 **Issues**: Submit bug reports via GitHub Issues
- 💬 **Discussions**: Use GitHub Discussions for questions and community support

### Troubleshooting

**Common Issues**:

1. **Permission Denied**:
   ```bash
   chmod +x network_discover.sh network_enum_v2.sh
   ```

2. **Missing Dependencies**:
   ```bash
   # Check what's missing
   for tool in nmap smbclient showmount curl; do
       command -v $tool >/dev/null 2>&1 || echo "Missing: $tool"
   done
   ```

3. **No Devices Found**:
   - Verify network range is correct
   - Check if you have network connectivity
   - Try a smaller, known subnet first

4. **Slow Performance**:
   - Use `network_discover.sh` for quick scans
   - Limit network range size for comprehensive scans
   - Check network congestion

---

## 🏆 Acknowledgments

- **nmap Team**: For the powerful network scanning engine
- **Samba Team**: For SMB/CIFS client tools
- **Open Source Community**: For continuous improvements and feedback
- **Security Research Community**: For methodologies and best practices

---

## 🔄 Version History

- **v3.0** (Current): Enhanced HTML reports, improved verification methods
- **v2.0**: Added comprehensive enumeration with application-specific probing
- **v1.0**: Initial verification-based discovery implementation

---

## 🎯 Roadmap

### Upcoming Features
- [ ] IPv6 support
- [ ] Database output options (SQLite, MySQL)
- [ ] JSON output format for API integration
- [ ] Network topology mapping
- [ ] Enhanced stealth scanning options
- [ ] Integration with vulnerability scanners
- [ ] Docker containerization
- [ ] Web dashboard interface

---

*Enhance your network security assessments with these accurate, verified, and visually rich enumeration tools!*

---

**⭐ If you find these tools useful, please consider giving this repository a star!**
