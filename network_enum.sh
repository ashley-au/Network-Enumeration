#!/bin/bash
# Comprehensive Network Enumeration Script
# Designed to discover stealth devices and enumerate services
# Usage: ./network_enum.sh <network_range> [output_dir]
# Example: ./network_enum.sh 192.168.1.0/24 /tmp/scan_results

VERSION="1.0"
SCRIPT_NAME="Network Stealth Enumeration"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] This script requires sudo/root privileges for comprehensive scanning${NC}"
        echo "Please run: sudo $0 $@"
        exit 1
    fi
}

# Print banner
print_banner() {
    echo -e "${CYAN}"
    echo "=================================================="
    echo "  $SCRIPT_NAME v$VERSION"
    echo "  Comprehensive Network Device Discovery"
    echo "=================================================="
    echo -e "${NC}"
}

# Usage information
usage() {
    echo -e "${YELLOW}Usage: $0 <network_range> [output_directory]${NC}"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.0/24"
    echo "  $0 10.0.0.0/24 /tmp/scan_results"
    echo "  $0 172.16.0.0/16 ~/network_scans"
    echo ""
    echo "Network range formats supported:"
    echo "  - CIDR notation: 192.168.1.0/24"
    echo "  - IP ranges: 192.168.1.1-254"
    echo "  - Single IP: 192.168.1.1"
    exit 1
}

# Create output directory
setup_output_dir() {
    local output_dir="$1"
    if [[ ! -d "$output_dir" ]]; then
        mkdir -p "$output_dir" || {
            echo -e "${RED}[ERROR] Cannot create output directory: $output_dir${NC}"
            exit 1
        }
    fi
    echo -e "${GREEN}[INFO] Output directory: $output_dir${NC}"
}

# Log function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")  color=$GREEN ;;
        "WARN")  color=$YELLOW ;;
        "ERROR") color=$RED ;;
        "SCAN")  color=$BLUE ;;
        *)       color=$NC ;;
    esac
    
    echo -e "${color}[$timestamp] [$level] $message${NC}"
    echo "[$timestamp] [$level] $message" >> "$OUTPUT_DIR/scan.log"
}

# Phase 1: Host Discovery
phase1_host_discovery() {
    local network="$1"
    log "SCAN" "Phase 1: Host Discovery - Starting comprehensive host enumeration"
    
    # ARP scan for local network
    log "INFO" "Running ARP scan for initial discovery..."
    nmap -sn -PR "$network" > "$OUTPUT_DIR/01_arp_scan.txt" 2>&1
    
    # Extract live hosts from ARP scan
    grep "Host is up" "$OUTPUT_DIR/01_arp_scan.txt" -B1 | grep "Nmap scan report" | awk '{print $5}' | sed 's/[()]//g' > "$OUTPUT_DIR/live_hosts_arp.txt"
    
    # Aggressive ping discovery for stealth devices
    log "INFO" "Running aggressive ping discovery with multiple probe types..."
    nmap -sn -PE -PP -PS21,22,23,25,53,80,113,443,993,995 -PA80,113,443,10042 -PO "$network" > "$OUTPUT_DIR/02_aggressive_ping.txt" 2>&1
    
    # Broadcast discovery
    log "INFO" "Running broadcast and multicast discovery..."
    nmap -sn --script discovery "$network" > "$OUTPUT_DIR/03_broadcast_discovery.txt" 2>&1
    
    # Extract additional hosts from broadcast discovery
    grep -E "(IP: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|Host is up)" "$OUTPUT_DIR/03_broadcast_discovery.txt" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort -u >> "$OUTPUT_DIR/live_hosts_broadcast.txt"
    
    # TCP SYN scan for stealth devices (no ping)
    log "INFO" "Running stealth TCP scan to catch ping-blocking devices..."
    nmap -sS -T4 -Pn --top-ports 1000 "$network" > "$OUTPUT_DIR/04_stealth_tcp_scan.txt" 2>&1
    
    # Extract hosts from stealth scan
    grep "Host is up" "$OUTPUT_DIR/04_stealth_tcp_scan.txt" -B1 | grep "Nmap scan report" | awk '{print $5}' | sed 's/[()]//g' >> "$OUTPUT_DIR/live_hosts_stealth.txt"
    
    # Combine and deduplicate all discovered hosts
    cat "$OUTPUT_DIR/live_hosts_"*.txt 2>/dev/null | grep -E "^([0-9]{1,3}\.){3}[0-9]{1,3}$" | sort -u > "$OUTPUT_DIR/all_live_hosts.txt"
    
    local host_count=$(cat "$OUTPUT_DIR/all_live_hosts.txt" | wc -l)
    log "INFO" "Host discovery complete. Found $host_count unique hosts"
    
    if [[ $host_count -eq 0 ]]; then
        log "WARN" "No hosts discovered. Check network connectivity and try a different range."
        return 1
    fi
    
    return 0
}

# Phase 2: Port Scanning
phase2_port_scanning() {
    log "SCAN" "Phase 2: Port Scanning - Comprehensive TCP and UDP enumeration"
    
    local hosts_file="$OUTPUT_DIR/all_live_hosts.txt"
    
    if [[ ! -f "$hosts_file" ]]; then
        log "ERROR" "No hosts file found. Run host discovery first."
        return 1
    fi
    
    # Full TCP port scan on all hosts
    log "INFO" "Running full TCP port scan (all 65535 ports)..."
    while IFS= read -r host; do
        if [[ -n "$host" ]]; then
            log "INFO" "TCP scanning $host..."
            nmap -sS -T4 -Pn -p- --min-rate 1000 "$host" > "$OUTPUT_DIR/tcp_${host}.txt" 2>&1 &
        fi
    done < "$hosts_file"
    
    # Wait for TCP scans to complete (with timeout)
    log "INFO" "Waiting for TCP scans to complete..."
    wait
    
    # UDP scan on top ports
    log "INFO" "Running UDP port scan on top 1000 ports..."
    while IFS= read -r host; do
        if [[ -n "$host" ]]; then
            log "INFO" "UDP scanning $host..."
            nmap -sU -T4 -Pn --top-ports 1000 "$host" > "$OUTPUT_DIR/udp_${host}.txt" 2>&1 &
        fi
    done < "$hosts_file"
    
    log "INFO" "Waiting for UDP scans to complete..."
    wait
    
    log "INFO" "Port scanning complete"
    return 0
}

# Phase 3: Service Enumeration
phase3_service_enumeration() {
    log "SCAN" "Phase 3: Service Enumeration - Detailed service and OS detection"
    
    local hosts_file="$OUTPUT_DIR/all_live_hosts.txt"
    
    # Service detection and OS fingerprinting
    while IFS= read -r host; do
        if [[ -n "$host" ]]; then
            log "INFO" "Running service enumeration on $host..."
            
            # Extract open TCP ports from previous scan
            local open_ports=$(grep "open" "$OUTPUT_DIR/tcp_${host}.txt" | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
            
            if [[ -n "$open_ports" ]]; then
                nmap -sS -T4 -A -p "$open_ports" "$host" > "$OUTPUT_DIR/services_${host}.txt" 2>&1
            else
                # If no specific ports, do default service scan
                nmap -sS -T4 -A "$host" > "$OUTPUT_DIR/services_${host}.txt" 2>&1
            fi
        fi
    done < "$hosts_file"
    
    log "INFO" "Service enumeration complete"
    return 0
}

# Phase 4: Application-Specific Enumeration
phase4_application_enumeration() {
    log "SCAN" "Phase 4: Application Enumeration - SMB, NFS, HTTP services"
    
    local hosts_file="$OUTPUT_DIR/all_live_hosts.txt"
    
    while IFS= read -r host; do
        if [[ -n "$host" ]]; then
            log "INFO" "Running application enumeration on $host..."
            
            # Check for SMB services
            if grep -q "445/tcp.*open" "$OUTPUT_DIR/tcp_${host}.txt" 2>/dev/null; then
                log "INFO" "Enumerating SMB shares on $host..."
                smbclient -L "//$host" -N > "$OUTPUT_DIR/smb_${host}.txt" 2>&1 || true
                
                # Additional SMB enumeration
                nmap --script smb-enum-shares,smb-enum-users,smb-os-discovery -p 445 "$host" >> "$OUTPUT_DIR/smb_${host}.txt" 2>&1 || true
            fi
            
            # Check for NFS services
            if grep -q "2049/tcp.*open" "$OUTPUT_DIR/tcp_${host}.txt" 2>/dev/null; then
                log "INFO" "Enumerating NFS exports on $host..."
                showmount -e "$host" > "$OUTPUT_DIR/nfs_${host}.txt" 2>&1 || true
                nmap --script nfs-showmount -p 2049 "$host" >> "$OUTPUT_DIR/nfs_${host}.txt" 2>&1 || true
            fi
            
            # Check for HTTP services
            for port in 80 443 8008 8080 8443; do
                if grep -q "${port}/tcp.*open" "$OUTPUT_DIR/tcp_${host}.txt" 2>/dev/null; then
                    log "INFO" "Enumerating HTTP service on $host:$port..."
                    curl -I -m 10 "http://$host:$port" > "$OUTPUT_DIR/http_${host}_${port}.txt" 2>&1 || true
                    if [[ $port -eq 443 ]] || [[ $port -eq 8443 ]]; then
                        curl -I -k -m 10 "https://$host:$port" >> "$OUTPUT_DIR/http_${host}_${port}.txt" 2>&1 || true
                    fi
                fi
            done
            
            # Check for SSH
            if grep -q "22/tcp.*open" "$OUTPUT_DIR/tcp_${host}.txt" 2>/dev/null; then
                log "INFO" "Gathering SSH banner from $host..."
                nmap --script ssh-hostkey -p 22 "$host" > "$OUTPUT_DIR/ssh_${host}.txt" 2>&1 || true
            fi
        fi
    done < "$hosts_file"
    
    log "INFO" "Application enumeration complete"
    return 0
}

# Phase 5: Report Generation
phase5_generate_report() {
    log "SCAN" "Phase 5: Report Generation - Creating comprehensive inventory"
    
    local report_file="$OUTPUT_DIR/NETWORK_ENUMERATION_REPORT.txt"
    local html_report="$OUTPUT_DIR/NETWORK_ENUMERATION_REPORT.html"
    
    {
        echo "========================================="
        echo "  COMPREHENSIVE NETWORK ENUMERATION REPORT"
        echo "========================================="
        echo "Scan Date: $(date)"
        echo "Network Range: $NETWORK_RANGE"
        echo "Total Hosts Discovered: $(cat "$OUTPUT_DIR/all_live_hosts.txt" | wc -l)"
        echo ""
        echo "========================================="
        echo "  DISCOVERY SUMMARY"
        echo "========================================="
        
        # Host summary
        echo ""
        echo "DISCOVERED HOSTS:"
        echo "-----------------"
        local host_num=1
        while IFS= read -r host; do
            if [[ -n "$host" ]]; then
                echo "[$host_num] $host"
                
                # Extract device info from service scan
                if [[ -f "$OUTPUT_DIR/services_${host}.txt" ]]; then
                    local mac_addr=$(grep "MAC Address:" "$OUTPUT_DIR/services_${host}.txt" | head -1 | awk '{print $3" "$4}' | sed 's/[()]//g')
                    local os_info=$(grep -E "(OS details|Running|OS CPE)" "$OUTPUT_DIR/services_${host}.txt" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
                    local netbios_name=$(grep "NetBIOS name:" "$OUTPUT_DIR/services_${host}.txt" | head -1 | awk '{print $3}' | sed 's/,$//')
                    
                    [[ -n "$mac_addr" ]] && echo "    MAC: $mac_addr"
                    [[ -n "$netbios_name" ]] && echo "    NetBIOS: $netbios_name"
                    [[ -n "$os_info" ]] && echo "    OS: $os_info"
                fi
                
                # Extract key services
                if [[ -f "$OUTPUT_DIR/tcp_${host}.txt" ]]; then
                    local tcp_services=$(grep "open" "$OUTPUT_DIR/tcp_${host}.txt" | wc -l)
                    echo "    TCP Services: $tcp_services open ports"
                fi
                
                echo ""
                ((host_num++))
            fi
        done < "$OUTPUT_DIR/all_live_hosts.txt"
        
        echo ""
        echo "========================================="
        echo "  DETAILED HOST ANALYSIS"
        echo "========================================="
        
        # Detailed analysis for each host
        while IFS= read -r host; do
            if [[ -n "$host" ]]; then
                echo ""
                echo "HOST: $host"
                echo "$(echo "$host" | sed 's/./=/g')======="
                
                # Service summary
                if [[ -f "$OUTPUT_DIR/services_${host}.txt" ]]; then
                    echo ""
                    echo "SERVICES:"
                    grep -E "^[0-9]+/(tcp|udp).*open" "$OUTPUT_DIR/services_${host}.txt" | head -20
                fi
                
                # SMB shares if available
                if [[ -f "$OUTPUT_DIR/smb_${host}.txt" ]] && grep -q "Sharename" "$OUTPUT_DIR/smb_${host}.txt"; then
                    echo ""
                    echo "SMB SHARES:"
                    grep -A10 "Sharename" "$OUTPUT_DIR/smb_${host}.txt"
                fi
                
                # NFS exports if available
                if [[ -f "$OUTPUT_DIR/nfs_${host}.txt" ]] && grep -q "Export list" "$OUTPUT_DIR/nfs_${host}.txt"; then
                    echo ""
                    echo "NFS EXPORTS:"
                    cat "$OUTPUT_DIR/nfs_${host}.txt"
                fi
                
                echo ""
                echo "----------------------------------------"
            fi
        done < "$OUTPUT_DIR/all_live_hosts.txt"
        
        echo ""
        echo "========================================="
        echo "  SECURITY ANALYSIS"
        echo "========================================="
        
        echo ""
        echo "STEALTH CAPABILITIES DETECTED:"
        echo "------------------------------"
        
        # Check for ping-blocking hosts
        local arp_hosts=$(cat "$OUTPUT_DIR/live_hosts_arp.txt" 2>/dev/null | wc -l)
        local stealth_hosts=$(cat "$OUTPUT_DIR/live_hosts_stealth.txt" 2>/dev/null | wc -l)
        local total_hosts=$(cat "$OUTPUT_DIR/all_live_hosts.txt" | wc -l)
        local ping_blockers=$((total_hosts - arp_hosts))
        
        if [[ $ping_blockers -gt 0 ]]; then
            echo "- $ping_blockers device(s) block ping probes (stealth behavior)"
        fi
        
        echo ""
        echo "SERVICE DISTRIBUTION:"
        echo "--------------------"
        local ssh_count=$(grep -l "22/tcp.*open" "$OUTPUT_DIR"/tcp_*.txt 2>/dev/null | wc -l)
        local smb_count=$(grep -l "445/tcp.*open" "$OUTPUT_DIR"/tcp_*.txt 2>/dev/null | wc -l)
        local http_count=$(grep -l -E "(80|8080|8008)/tcp.*open" "$OUTPUT_DIR"/tcp_*.txt 2>/dev/null | wc -l)
        local https_count=$(grep -l -E "(443|8443)/tcp.*open" "$OUTPUT_DIR"/tcp_*.txt 2>/dev/null | wc -l)
        
        echo "- SSH: $ssh_count hosts"
        echo "- SMB/CIFS: $smb_count hosts"
        echo "- HTTP: $http_count hosts"
        echo "- HTTPS: $https_count hosts"
        
        echo ""
        echo "========================================="
        echo "  SCAN METHODOLOGY"
        echo "========================================="
        echo ""
        echo "This scan used multiple techniques to discover stealth devices:"
        echo "1. ARP scanning for local network discovery"
        echo "2. Aggressive ping with multiple probe types (ICMP, TCP, UDP)"
        echo "3. Broadcast and multicast discovery (IGMP, mDNS)"
        echo "4. Full TCP port scanning with ping bypass (-Pn)"
        echo "5. UDP service discovery on top 1000 ports"
        echo "6. Comprehensive service enumeration and OS fingerprinting"
        echo "7. Application-specific enumeration (SMB, NFS, HTTP, SSH)"
        echo ""
        echo "Files generated:"
        echo "- Individual TCP/UDP scans per host"
        echo "- Service enumeration results"
        echo "- Application-specific enumeration"
        echo "- Comprehensive scan logs"
        echo ""
        echo "Scan completed: $(date)"
        
    } > "$report_file"
    
    # Generate simple HTML report
    {
        echo "<html><head><title>Network Enumeration Report</title></head><body>"
        echo "<pre>"
        cat "$report_file"
        echo "</pre></body></html>"
    } > "$html_report"
    
    log "INFO" "Reports generated:"
    log "INFO" "  Text Report: $report_file"
    log "INFO" "  HTML Report: $html_report"
    
    return 0
}

# Main execution
main() {
    print_banner
    
    # Parse arguments
    if [[ $# -lt 1 ]]; then
        usage
    fi
    
    NETWORK_RANGE="$1"
    OUTPUT_DIR="${2:-./network_scan_$(date +%Y%m%d_%H%M%S)}"
    
    # Validate network range format
    if [[ ! "$NETWORK_RANGE" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] && 
       [[ ! "$NETWORK_RANGE" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}$ ]]; then
        log "ERROR" "Invalid network range format: $NETWORK_RANGE"
        usage
    fi
    
    # Check for required tools
    local required_tools=("nmap" "smbclient" "showmount" "curl")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log "ERROR" "Required tool not found: $tool"
            log "ERROR" "Please install: sudo dnf install nmap samba-client nfs-utils curl"
            exit 1
        fi
    done
    
    check_root
    setup_output_dir "$OUTPUT_DIR"
    
    log "INFO" "Starting comprehensive network enumeration"
    log "INFO" "Target network: $NETWORK_RANGE"
    
    # Execute phases
    if ! phase1_host_discovery "$NETWORK_RANGE"; then
        log "ERROR" "Host discovery failed"
        exit 1
    fi
    
    if ! phase2_port_scanning; then
        log "ERROR" "Port scanning failed"
        exit 1
    fi
    
    if ! phase3_service_enumeration; then
        log "ERROR" "Service enumeration failed"
        exit 1
    fi
    
    if ! phase4_application_enumeration; then
        log "ERROR" "Application enumeration failed"
        exit 1
    fi
    
    if ! phase5_generate_report; then
        log "ERROR" "Report generation failed"
        exit 1
    fi
    
    log "INFO" "Network enumeration completed successfully!"
    log "INFO" "Results saved in: $OUTPUT_DIR"
    
    # Display quick summary
    local host_count=$(cat "$OUTPUT_DIR/all_live_hosts.txt" | wc -l)
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}  SCAN COMPLETE${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${YELLOW}Hosts Discovered: ${NC}$host_count"
    echo -e "${YELLOW}Output Directory: ${NC}$OUTPUT_DIR"
    echo -e "${YELLOW}Main Report: ${NC}$OUTPUT_DIR/NETWORK_ENUMERATION_REPORT.txt"
    echo -e "${GREEN}=========================================${NC}"
}

# Execute main function
main "$@"
