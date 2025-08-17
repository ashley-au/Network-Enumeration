# Comprehensive Network Enumeration Script

## Overview
This script performs comprehensive network enumeration designed to discover stealth devices and enumerate all services on networks you own. It uses multiple reconnaissance techniques to catch devices that block standard ping probes or implement stealth measures.

## Features
- **Multi-Phase Discovery**: Uses 6 different phases to ensure complete coverage
- **Stealth Device Detection**: Specifically designed to catch ping-blocking devices
- **Comprehensive Service Enumeration**: Identifies all TCP/UDP services
- **Application-Specific Enumeration**: Deep dives into SMB, NFS, HTTP, SSH services
- **Automated Reporting**: Generates detailed text and HTML reports
- **Parallel Scanning**: Runs multiple scans concurrently for efficiency

## Usage

### Basic Usage
```bash
sudo ./network_enum.sh 192.168.1.0/24
```

### Advanced Usage
```bash
# Specify custom output directory
sudo ./network_enum.sh 192.168.1.0/24 /tmp/my_scan_results

# Scan different network ranges
sudo ./network_enum.sh 10.0.0.0/24
sudo ./network_enum.sh 172.16.0.0/16
```

## Prerequisites

### Required Tools
The script checks for and requires:
- `nmap` - Network discovery and port scanning
- `smbclient` - SMB share enumeration
- `showmount` - NFS export enumeration  
- `curl` - HTTP service enumeration

### Installation (Fedora/RHEL)
```bash
sudo dnf install nmap samba-client nfs-utils curl
```

### Installation (Ubuntu/Debian)
```bash
sudo apt install nmap smbclient nfs-common curl
```

## Scanning Phases

### Phase 1: Host Discovery
**Techniques Used:**
- ARP scanning for local network discovery
- Aggressive ping with multiple probe types (ICMP, TCP SYN, TCP ACK, UDP)
- Broadcast and multicast discovery (IGMP, mDNS)
- TCP SYN scan with ping bypass (-Pn) to catch stealth devices

**Files Generated:**
- `01_arp_scan.txt` - Initial ARP discovery
- `02_aggressive_ping.txt` - Multi-protocol ping results
- `03_broadcast_discovery.txt` - Broadcast/multicast discovery
- `04_stealth_tcp_scan.txt` - Stealth device detection
- `all_live_hosts.txt` - Final deduplicated host list

### Phase 2: Port Scanning
**Techniques Used:**
- Full TCP port scan (all 65535 ports) on each discovered host
- UDP scan on top 1000 ports for each host
- All scans use ping bypass (-Pn) to ensure stealth devices are scanned

**Files Generated:**
- `tcp_<IP>.txt` - Individual TCP scan results per host
- `udp_<IP>.txt` - Individual UDP scan results per host

### Phase 3: Service Enumeration
**Techniques Used:**
- Aggressive service detection (-A flag)
- OS fingerprinting and version detection
- Script scanning for additional service information

**Files Generated:**
- `services_<IP>.txt` - Detailed service enumeration per host

### Phase 4: Application-Specific Enumeration
**Techniques Used:**
- SMB share enumeration (anonymous and authenticated attempts)
- NFS export listing
- HTTP header enumeration for web services
- SSH banner collection and key fingerprinting

**Files Generated:**
- `smb_<IP>.txt` - SMB share and service details
- `nfs_<IP>.txt` - NFS export information
- `http_<IP>_<PORT>.txt` - HTTP service headers
- `ssh_<IP>.txt` - SSH service information

### Phase 5: Report Generation
**Comprehensive Reports:**
- `NETWORK_ENUMERATION_REPORT.txt` - Detailed text report
- `NETWORK_ENUMERATION_REPORT.html` - HTML version for web viewing
- `scan.log` - Complete execution log with timestamps

## Output Structure

```
network_scan_YYYYMMDD_HHMMSS/
├── 01_arp_scan.txt
├── 02_aggressive_ping.txt
├── 03_broadcast_discovery.txt
├── 04_stealth_tcp_scan.txt
├── all_live_hosts.txt
├── tcp_<IP>.txt (for each discovered host)
├── udp_<IP>.txt (for each discovered host)
├── services_<IP>.txt (for each discovered host)
├── smb_<IP>.txt (if SMB services found)
├── nfs_<IP>.txt (if NFS services found)
├── http_<IP>_<PORT>.txt (if HTTP services found)
├── ssh_<IP>.txt (if SSH services found)
├── scan.log
├── NETWORK_ENUMERATION_REPORT.txt
└── NETWORK_ENUMERATION_REPORT.html
```

## Key Techniques for Stealth Device Discovery

### 1. Multiple Discovery Methods
- **ARP Scanning**: Most reliable for local network segments
- **ICMP Ping**: Standard ping discovery
- **TCP SYN Ping**: Uses SYN packets to common ports
- **TCP ACK Ping**: Uses ACK packets to bypass some firewalls
- **UDP Ping**: Uses UDP packets for discovery

### 2. Ping Bypass Scanning
- Uses `-Pn` flag to skip host discovery and scan directly
- Catches devices that block all ping attempts
- Performs full port scans on entire network ranges

### 3. Broadcast Discovery
- IGMP multicast discovery
- mDNS/Bonjour discovery
- Broadcast ping techniques
- Captures devices advertising services

## Security Considerations

### Legal Use Only
**⚠️ IMPORTANT**: This script should only be used on networks you own or have explicit permission to test. Unauthorized network scanning may violate local laws and regulations.

### Script Safety Features
- Requires root/sudo privileges (standard for network scanning)
- Validates network range format
- Checks for required tools before starting
- Includes comprehensive logging
- Uses reasonable scanning rates to avoid network disruption

### Stealth vs. Speed Trade-offs
- Script prioritizes completeness over speed
- Uses parallel scanning where possible
- Implements reasonable delays to avoid overwhelming targets
- Can be customized for faster scanning if needed

## Customization Options

### Modify Scanning Intensity
Edit these variables in the script:
```bash
# For faster scanning (less thorough)
--min-rate 2000  # Increase packet rate
-T5             # Most aggressive timing

# For stealth scanning (slower but quieter)
--min-rate 100  # Decrease packet rate  
-T2             # Slower timing
```

### Add Custom Ports
Modify the port lists in phases 2 and 4:
```bash
# Add custom TCP ports
-p 1-65535,<custom_ports>

# Add custom UDP ports  
--top-ports 2000  # Scan more UDP ports
```

### Custom Service Scripts
Add additional nmap scripts in Phase 4:
```bash
nmap --script "<additional_scripts>" -p <ports> "$host"
```

## Troubleshooting

### Common Issues
1. **Permission Denied**: Ensure running with sudo/root
2. **Missing Tools**: Install required packages (nmap, smbclient, etc.)
3. **Network Unreachable**: Verify network connectivity and range
4. **Slow Scanning**: Large networks take time; consider smaller ranges
5. **No Hosts Found**: Try different discovery techniques manually first

### Performance Optimization
```bash
# For large networks, consider:
# 1. Scanning subnets individually
./network_enum.sh 192.168.1.0/24
./network_enum.sh 192.168.2.0/24

# 2. Using faster timing (less thorough)
# Edit script to use -T5 instead of -T4

# 3. Limiting port ranges for initial discovery
# Modify script to scan common ports first
```

## Example Scenarios

### Home Network Audit
```bash
sudo ./network_enum.sh 192.168.1.0/24 ~/home_network_audit
```

### Corporate Network Assessment  
```bash
sudo ./network_enum.sh 10.0.0.0/8 /opt/security_scans/corporate_audit
```

### IoT Device Discovery
```bash
# Focus on common IoT subnets
sudo ./network_enum.sh 192.168.0.0/24 ~/iot_discovery
```

## Understanding the Reports

### Device Classification
The script automatically categorizes discovered devices:
- **Linux Systems**: SSH services, NFS exports, typical Linux ports
- **Windows Systems**: SMB services, RPC, Windows-specific ports  
- **Network Devices**: SNMP, web interfaces, management ports
- **IoT/Embedded**: Limited services, specific vendor signatures
- **Stealth Devices**: Ping-blocking, unusual port filtering

### Security Analysis
Reports include:
- **Attack Surface Assessment**: Open services and potential entry points
- **Stealth Capability Detection**: Devices using defensive measures
- **Service Distribution**: Overview of network service landscape
- **Risk Categorization**: High/medium/low risk device classification

## Integration with Other Tools

### Export for Further Analysis
```bash
# Extract just IP addresses for other tools
grep "^\[" NETWORK_ENUMERATION_REPORT.txt | awk '{print $2}' > discovered_hosts.txt

# Create Metasploit workspace
# Import nmap XML files into Metasploit for exploitation testing
```

### Continuous Monitoring
```bash
# Set up cron job for regular scanning
echo "0 2 * * 0 /path/to/network_enum.sh 192.168.1.0/24 /var/log/network_scans/weekly" | sudo crontab -
```

This comprehensive script provides a complete solution for network enumeration and device discovery, specifically designed to catch stealth devices that might be missed by standard scanning tools.
