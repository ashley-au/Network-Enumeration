#!/bin/bash
# Enhanced Network Enumeration Script v2.0
# Verification-Based Device Discovery
# Usage: ./network_enum_v2.sh <network_range> [output_dir]

VERSION="2.0"
SCRIPT_NAME="Verification-Based Network Enumeration"

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
        echo -e "${RED}[ERROR] This script requires sudo/root privileges${NC}"
        echo "Please run: sudo $0 $@"
        exit 1
    fi
}

# Print banner
print_banner() {
    echo -e "${CYAN}"
    echo "=================================================="
    echo "  $SCRIPT_NAME v$VERSION"
    echo "  Verification-Based Device Discovery"
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
        "VERIFY") color=$PURPLE ;;
        *)       color=$NC ;;
    esac
    
    echo -e "${color}[$timestamp] [$level] $message${NC}"
    [[ -n "${OUTPUT_DIR:-}" ]] && echo "[$timestamp] [$level] $message" >> "$OUTPUT_DIR/scan.log"
}

# Verify if a host is actually alive using multiple methods
verify_host_alive() {
    local ip="$1"
    local verification_file="$2"
    
    # Method 1: ARP probe (most reliable for local network)
    if nmap -sn -PR "$ip" 2>/dev/null | grep -q "Host is up"; then
        echo "$ip|ARP_RESPONSIVE" >> "$verification_file"
        return 0
    fi
    
    # Method 2: TCP SYN probe on common ports
    if nmap -sS -Pn -p 22,80,135,139,443,445,8008,8080,8443 "$ip" --max-retries 1 2>/dev/null | grep -q "Host is up"; then
        echo "$ip|TCP_RESPONSIVE" >> "$verification_file"
        return 0
    fi
    
    # Method 3: UDP probe on common services
    if nmap -sU -Pn -p 53,67,123,137,161,1900,5353 "$ip" --max-retries 1 2>/dev/null | grep -q "Host is up"; then
        echo "$ip|UDP_RESPONSIVE" >> "$verification_file"
        return 0
    fi
    
    # Method 4: ICMP probes (various types)
    if nmap -sn -PE -PP -PM "$ip" 2>/dev/null | grep -q "Host is up"; then
        echo "$ip|ICMP_RESPONSIVE" >> "$verification_file"
        return 0
    fi
    
    # Method 5: TCP Connect scan (for very defensive devices)
    if nmap -sT -Pn -p 80,443,22 "$ip" --max-retries 1 2>/dev/null | grep -q "Host is up"; then
        echo "$ip|TCP_CONNECT_RESPONSIVE" >> "$verification_file"
        return 0
    fi
    
    return 1
}

# Phase 1: Discovery and Verification
phase1_verified_discovery() {
    local network="$1"
    log "SCAN" "Phase 1: Verified Discovery - Only confirmed live devices"
    
    # Initialize files
    > "$OUTPUT_DIR/candidates.txt"
    > "$OUTPUT_DIR/verified_hosts.txt"
    
    # Step 1: Initial broad discovery to get candidates
    log "INFO" "Step 1: Gathering host candidates from multiple sources..."
    
    # ARP scan - most reliable for local network
    log "INFO" "Running ARP discovery..."
    nmap -sn -PR "$network" > "$OUTPUT_DIR/discovery_arp.txt" 2>&1
    grep "Nmap scan report for" "$OUTPUT_DIR/discovery_arp.txt" | \
        grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" >> "$OUTPUT_DIR/candidates.txt"
    
    # Aggressive ping with multiple probe types
    log "INFO" "Running multi-protocol ping discovery..."
    nmap -sn -PE -PP -PS21,22,23,25,53,80,113,443,993,995,8008,8080,8443 \
        -PA80,113,443,8008,8080,10042 -PO "$network" > "$OUTPUT_DIR/discovery_ping.txt" 2>&1
    grep "Nmap scan report for" "$OUTPUT_DIR/discovery_ping.txt" | \
        grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" >> "$OUTPUT_DIR/candidates.txt"
    
    # Broadcast discovery
    log "INFO" "Running broadcast discovery..."
    nmap -sn --script discovery,broadcast-ping,broadcast-igmp-discovery "$network" \
        > "$OUTPUT_DIR/discovery_broadcast.txt" 2>&1
    grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" "$OUTPUT_DIR/discovery_broadcast.txt" \
        >> "$OUTPUT_DIR/candidates.txt"
    
    # TCP stealth scan for ping-blocking devices
    log "INFO" "Running stealth TCP discovery..."
    nmap -sS -T4 -Pn --top-ports 100 "$network" > "$OUTPUT_DIR/discovery_stealth.txt" 2>&1
    grep "Nmap scan report for" "$OUTPUT_DIR/discovery_stealth.txt" | \
        grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" >> "$OUTPUT_DIR/candidates.txt"
    
    # Extract network base and test common IPs
    local network_base=$(echo "$network" | cut -d'/' -f1 | cut -d'.' -f1-3)
    local common_ips="1 2 10 15 50 69 100 101 150 190 195 200 209 210 211 214 219 220 230 243 247 250 251 252 253 254"
    
    log "INFO" "Testing common device IP addresses..."
    for ip in $common_ips; do
        echo "${network_base}.${ip}" >> "$OUTPUT_DIR/candidates.txt"
    done
    
    # Deduplicate candidates
    sort -u "$OUTPUT_DIR/candidates.txt" > "$OUTPUT_DIR/candidates_unique.txt"
    local candidate_count=$(cat "$OUTPUT_DIR/candidates_unique.txt" | wc -l)
    log "INFO" "Found $candidate_count potential hosts to verify"
    
    # Step 2: Verify each candidate is actually alive
    log "VERIFY" "Step 2: Verifying each candidate host..."
    
    local verified_count=0
    while IFS= read -r ip; do
        if [[ -n "$ip" ]] && [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            log "VERIFY" "Verifying $ip..."
            if verify_host_alive "$ip" "$OUTPUT_DIR/verified_hosts.txt"; then
                ((verified_count++))
                log "INFO" "✓ Confirmed: $ip is alive"
            fi
        fi
    done < "$OUTPUT_DIR/candidates_unique.txt"
    
    # Extract just the IPs from verified hosts
    cut -d'|' -f1 "$OUTPUT_DIR/verified_hosts.txt" | sort -u > "$OUTPUT_DIR/live_hosts.txt"
    
    log "INFO" "Host verification complete: $verified_count confirmed live hosts"
    return 0
}

# Phase 2: Comprehensive Port Scanning (only on verified hosts)
phase2_port_scanning() {
    log "SCAN" "Phase 2: Port Scanning - Only on verified live hosts"
    
    local hosts_file="$OUTPUT_DIR/live_hosts.txt"
    if [[ ! -f "$hosts_file" ]] || [[ ! -s "$hosts_file" ]]; then
        log "ERROR" "No verified hosts found for port scanning"
        return 1
    fi
    
    # TCP scanning
    log "INFO" "Starting TCP port scans on verified hosts..."
    while IFS= read -r host; do
        if [[ -n "$host" ]]; then
            log "INFO" "TCP scanning $host..."
            nmap -sS -T4 -Pn -p- --min-rate 1000 "$host" > "$OUTPUT_DIR/tcp_${host}.txt" 2>&1 &
        fi
    done < "$hosts_file"
    
    log "INFO" "Waiting for TCP scans to complete..."
    wait
    
    # UDP scanning
    log "INFO" "Starting UDP port scans on verified hosts..."
    while IFS= read -r host; do
        if [[ -n "$host" ]]; then
            log "INFO" "UDP scanning $host..."
            nmap -sU -T4 -Pn --top-ports 1000 "$host" > "$OUTPUT_DIR/udp_${host}.txt" 2>&1 &
        fi
    done < "$hosts_file"
    
    log "INFO" "Waiting for UDP scans to complete..."
    wait
    
    log "INFO" "Port scanning complete on all verified hosts"
    return 0
}

# Phase 3: Service Enumeration
phase3_service_enumeration() {
    log "SCAN" "Phase 3: Service Enumeration on verified hosts"
    
    local hosts_file="$OUTPUT_DIR/live_hosts.txt"
    
    while IFS= read -r host; do
        if [[ -n "$host" ]]; then
            log "INFO" "Service enumeration on $host..."
            
            # Get open ports from TCP scan
            local open_ports=""
            if [[ -f "$OUTPUT_DIR/tcp_${host}.txt" ]]; then
                open_ports=$(grep "^[0-9]*/tcp.*open" "$OUTPUT_DIR/tcp_${host}.txt" | \
                    awk '{print $1}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
            fi
            
            if [[ -n "$open_ports" ]]; then
                nmap -sS -T4 -A -p "$open_ports" "$host" > "$OUTPUT_DIR/services_${host}.txt" 2>&1
            else
                nmap -sS -T4 -A "$host" > "$OUTPUT_DIR/services_${host}.txt" 2>&1
            fi
        fi
    done < "$hosts_file"
    
    log "INFO" "Service enumeration complete"
    return 0
}

# Phase 4: Application Enumeration
phase4_application_enumeration() {
    log "SCAN" "Phase 4: Application-specific enumeration"
    
    local hosts_file="$OUTPUT_DIR/live_hosts.txt"
    
    while IFS= read -r host; do
        if [[ -n "$host" ]]; then
            log "INFO" "Application enumeration on $host..."
            
            # SMB enumeration
            if [[ -f "$OUTPUT_DIR/tcp_${host}.txt" ]] && grep -q "445/tcp.*open" "$OUTPUT_DIR/tcp_${host}.txt"; then
                log "INFO" "Enumerating SMB on $host..."
                smbclient -L "//$host" -N > "$OUTPUT_DIR/smb_${host}.txt" 2>&1 || true
                nmap --script smb-enum-shares,smb-os-discovery -p 445 "$host" >> "$OUTPUT_DIR/smb_${host}.txt" 2>&1 || true
            fi
            
            # NFS enumeration
            if [[ -f "$OUTPUT_DIR/tcp_${host}.txt" ]] && grep -q "2049/tcp.*open" "$OUTPUT_DIR/tcp_${host}.txt"; then
                log "INFO" "Enumerating NFS on $host..."
                showmount -e "$host" > "$OUTPUT_DIR/nfs_${host}.txt" 2>&1 || true
                nmap --script nfs-showmount -p 2049 "$host" >> "$OUTPUT_DIR/nfs_${host}.txt" 2>&1 || true
            fi
            
            # HTTP enumeration
            for port in 80 443 8008 8080 8443; do
                if [[ -f "$OUTPUT_DIR/tcp_${host}.txt" ]] && grep -q "${port}/tcp.*open" "$OUTPUT_DIR/tcp_${host}.txt"; then
                    log "INFO" "Enumerating HTTP on $host:$port..."
                    curl -I -m 10 "http://$host:$port" > "$OUTPUT_DIR/http_${host}_${port}.txt" 2>&1 || true
                    [[ $port -eq 443 ]] || [[ $port -eq 8443 ]] && \
                        curl -I -k -m 10 "https://$host:$port" >> "$OUTPUT_DIR/http_${host}_${port}.txt" 2>&1 || true
                fi
            done
        fi
    done < "$hosts_file"
    
    log "INFO" "Application enumeration complete"
    return 0
}

# Generate comprehensive HTML report
generate_html_report() {
    local text_report="$1"
    local hosts_file="$2"
    local html_file="${text_report%.*}.html"
    
    cat > "$html_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comprehensive Network Enumeration Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            color: #333;
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-align: center;
            padding: 40px 20px;
        }
        .header h1 {
            margin: 0;
            font-size: 2.8em;
            font-weight: 300;
        }
        .header .subtitle {
            font-size: 1.3em;
            margin-top: 10px;
            opacity: 0.9;
        }
        .content {
            padding: 30px;
        }
        .scan-info {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 30px;
            border-left: 5px solid #667eea;
        }
        .scan-info h2 {
            margin: 0 0 15px 0;
            color: #2c3e50;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .info-item {
            display: flex;
            align-items: center;
        }
        .info-label {
            font-weight: 600;
            color: #667eea;
            margin-right: 10px;
        }
        .hosts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-top: 30px;
        }
        .host-card {
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            border: 1px solid #e9ecef;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .host-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        .host-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f1f3f4;
        }
        .host-ip {
            font-size: 1.4em;
            font-weight: 600;
            color: #2c3e50;
        }
        .verification-badge {
            background: linear-gradient(135deg, #4ecdc4 0%, #44a08d 100%);
            color: white;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
        }
        .host-details {
            margin-bottom: 20px;
        }
        .detail-item {
            margin: 8px 0;
            display: flex;
            align-items: center;
        }
        .detail-label {
            font-weight: 600;
            color: #6c757d;
            width: 80px;
            font-size: 0.9em;
        }
        .detail-value {
            color: #495057;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.9em;
        }
        .services-section {
            margin-top: 20px;
        }
        .services-title {
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        .services-list {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.85em;
            line-height: 1.6;
            max-height: 200px;
            overflow-y: auto;
        }
        .service-item {
            padding: 3px 0;
            border-bottom: 1px dotted #dee2e6;
        }
        .service-item:last-child {
            border-bottom: none;
        }
        .port-number {
            color: #dc3545;
            font-weight: 600;
        }
        .service-name {
            color: #28a745;
            margin-left: 10px;
        }
        .shares-section {
            margin-top: 20px;
        }
        .shares-list {
            background: #fff3cd;
            border-radius: 8px;
            padding: 15px;
            border-left: 4px solid #ffc107;
        }
        .methodology {
            background: #e3f2fd;
            border-radius: 12px;
            padding: 25px;
            margin: 30px 0;
        }
        .methodology h2 {
            color: #1565c0;
            margin-top: 0;
        }
        .method-steps {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .method-step {
            background: white;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #2196f3;
        }
        .method-step h4 {
            margin: 0 0 8px 0;
            color: #1565c0;
        }
        .footer {
            text-align: center;
            padding: 30px;
            background: #f8f9fa;
            color: #6c757d;
            border-top: 1px solid #e9ecef;
        }
    </style>
</head>
<body>
EOF

    # Add dynamic content
    cat >> "$html_file" << EOF
    <div class="container">
        <div class="header">
            <h1>Network Enumeration Report</h1>
            <div class="subtitle">Comprehensive Verification-Based Analysis</div>
        </div>
        
        <div class="content">
            <div class="scan-info">
                <h2>Scan Information</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Network:</span>
                        <span>$NETWORK_RANGE</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Date:</span>
                        <span>$(date)</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Hosts Found:</span>
                        <span>$(cat "$hosts_file" | wc -l)</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Method:</span>
                        <span>Verification-Based Discovery</span>
                    </div>
                </div>
            </div>
            
            <div class="methodology">
                <h2>Verification Methodology</h2>
                <p>This scan uses a multi-phase verification approach to ensure only genuine responsive devices are included:</p>
                <div class="method-steps">
                    <div class="method-step">
                        <h4>ARP Discovery</h4>
                        <p>Layer 2 probes for local network devices</p>
                    </div>
                    <div class="method-step">
                        <h4>TCP SYN Probes</h4>
                        <p>Tests common service ports without full connection</p>
                    </div>
                    <div class="method-step">
                        <h4>UDP Probes</h4>
                        <p>Discovers UDP-only services and devices</p>
                    </div>
                    <div class="method-step">
                        <h4>ICMP Probes</h4>
                        <p>Multiple ICMP types for comprehensive coverage</p>
                    </div>
                    <div class="method-step">
                        <h4>Port Scanning</h4>
                        <p>Full TCP and UDP enumeration on verified hosts</p>
                    </div>
                    <div class="method-step">
                        <h4>Service Analysis</h4>
                        <p>Detailed service identification and enumeration</p>
                    </div>
                </div>
            </div>
            
            <h2>Discovered Devices</h2>
            <div class="hosts-grid">
EOF

    # Add host cards
    while IFS= read -r host; do
        if [[ -n "$host" ]]; then
            # Extract host information
            local verification_method="Unknown"
            if [[ -f "$OUTPUT_DIR/verified_hosts.txt" ]]; then
                verification_method=$(grep "^$host|" "$OUTPUT_DIR/verified_hosts.txt" | cut -d'|' -f2 | head -1)
            fi
            
            cat >> "$html_file" << EOF
                <div class="host-card">
                    <div class="host-header">
                        <div class="host-ip">$host</div>
                        <div class="verification-badge">$verification_method</div>
                    </div>
                    
                    <div class="host-details">
EOF
            
            # Add device details if available
            if [[ -f "$OUTPUT_DIR/services_${host}.txt" ]]; then
                local mac_addr=$(grep "MAC Address:" "$OUTPUT_DIR/services_${host}.txt" | head -1 | awk '{print $3" "$4}' | sed 's/[()]//g')
                local os_info=$(grep -E "(OS details|Running)" "$OUTPUT_DIR/services_${host}.txt" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//' | head -c 60)
                local netbios_name=$(grep "NetBIOS name:" "$OUTPUT_DIR/services_${host}.txt" | head -1 | awk '{print $3}' | sed 's/,$//')
                
                [[ -n "$mac_addr" ]] && echo "                        <div class='detail-item'><span class='detail-label'>MAC:</span><span class='detail-value'>$mac_addr</span></div>" >> "$html_file"
                [[ -n "$netbios_name" ]] && echo "                        <div class='detail-item'><span class='detail-label'>NetBIOS:</span><span class='detail-value'>$netbios_name</span></div>" >> "$html_file"
                [[ -n "$os_info" ]] && echo "                        <div class='detail-item'><span class='detail-label'>OS:</span><span class='detail-value'>$os_info</span></div>" >> "$html_file"
            fi
            
            cat >> "$html_file" << 'EOF'
                    </div>
                    
EOF
            
            # Add services
            if [[ -f "$OUTPUT_DIR/services_${host}.txt" ]]; then
                local services=$(grep -E "^[0-9]+/(tcp|udp).*open" "$OUTPUT_DIR/services_${host}.txt" | head -10)
                if [[ -n "$services" ]]; then
                    cat >> "$html_file" << 'EOF'
                    <div class="services-section">
                        <div class="services-title">Open Services</div>
                        <div class="services-list">
EOF
                    echo "$services" | while IFS= read -r service_line; do
                        if [[ -n "$service_line" ]]; then
                            local port=$(echo "$service_line" | awk '{print $1}' | sed 's/\/tcp\|/udp//')
                            local service=$(echo "$service_line" | awk '{print $3}')
                            echo "                            <div class='service-item'><span class='port-number'>$port</span><span class='service-name'>$service</span></div>" >> "$html_file"
                        fi
                    done
                    echo "                        </div>" >> "$html_file"
                    echo "                    </div>" >> "$html_file"
                fi
            fi
            
            # Add SMB shares if available
            if [[ -f "$OUTPUT_DIR/smb_${host}.txt" ]] && grep -q "Sharename" "$OUTPUT_DIR/smb_${host}.txt"; then
                cat >> "$html_file" << 'EOF'
                    <div class="shares-section">
                        <div class="services-title">SMB Shares</div>
                        <div class="shares-list">
EOF
                grep -A5 "Sharename" "$OUTPUT_DIR/smb_${host}.txt" | head -10 | sed 's/</\&lt;/g; s/>/\&gt;/g' >> "$html_file"
                cat >> "$html_file" << 'EOF'
                        </div>
                    </div>
EOF
            fi
            
            echo "                </div>" >> "$html_file"
        fi
    done < "$hosts_file"
    
    # Close HTML
    cat >> "$html_file" << 'EOF'
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by Comprehensive Network Enumeration v2.0</p>
            <p>Verification-based approach ensures accurate results with comprehensive analysis</p>
        </div>
    </div>
</body>
</html>
EOF
}

# Phase 5: Generate comprehensive report
phase5_generate_report() {
    log "SCAN" "Phase 5: Generating comprehensive report"
    
    local report_file="$OUTPUT_DIR/NETWORK_ENUMERATION_REPORT.txt"
    local hosts_file="$OUTPUT_DIR/live_hosts.txt"
    
    if [[ ! -f "$hosts_file" ]]; then
        log "ERROR" "No hosts file found for report generation"
        return 1
    fi
    
    {
        echo "========================================="
        echo "  VERIFIED NETWORK ENUMERATION REPORT"
        echo "========================================="
        echo "Scan Date: $(date)"
        echo "Network Range: $NETWORK_RANGE"
        echo "Total Verified Hosts: $(cat "$hosts_file" | wc -l)"
        echo ""
        echo "========================================="
        echo "  DISCOVERY VERIFICATION SUMMARY"
        echo "========================================="
        echo ""
        
        if [[ -f "$OUTPUT_DIR/verified_hosts.txt" ]]; then
            echo "HOST VERIFICATION METHODS:"
            echo "--------------------------"
            while IFS='|' read -r ip method; do
                echo "$ip - Verified via $method"
            done < "$OUTPUT_DIR/verified_hosts.txt"
            echo ""
        fi
        
        echo "VERIFIED LIVE HOSTS:"
        echo "-------------------"
        local host_num=1
        while IFS= read -r host; do
            if [[ -n "$host" ]]; then
                echo "[$host_num] $host"
                
                # Extract device information
                if [[ -f "$OUTPUT_DIR/services_${host}.txt" ]]; then
                    local mac_addr=$(grep "MAC Address:" "$OUTPUT_DIR/services_${host}.txt" | head -1 | \
                        awk '{print $3" "$4}' | sed 's/[()]//g')
                    local os_info=$(grep -E "(OS details|Running)" "$OUTPUT_DIR/services_${host}.txt" | \
                        head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
                    local netbios_name=$(grep "NetBIOS name:" "$OUTPUT_DIR/services_${host}.txt" | \
                        head -1 | awk '{print $3}' | sed 's/,$//')
                    
                    [[ -n "$mac_addr" ]] && echo "    MAC: $mac_addr"
                    [[ -n "$netbios_name" ]] && echo "    NetBIOS: $netbios_name"
                    [[ -n "$os_info" ]] && echo "    OS: $os_info"
                fi
                
                # Service summary
                if [[ -f "$OUTPUT_DIR/tcp_${host}.txt" ]]; then
                    local tcp_count=$(grep "^[0-9]*/tcp.*open" "$OUTPUT_DIR/tcp_${host}.txt" | wc -l)
                    [[ $tcp_count -gt 0 ]] && echo "    TCP Services: $tcp_count ports open"
                fi
                
                if [[ -f "$OUTPUT_DIR/udp_${host}.txt" ]]; then
                    local udp_count=$(grep "^[0-9]*/udp.*open" "$OUTPUT_DIR/udp_${host}.txt" | wc -l)
                    [[ $udp_count -gt 0 ]] && echo "    UDP Services: $udp_count ports open"
                fi
                
                echo ""
                ((host_num++))
            fi
        done < "$hosts_file"
        
        echo ""
        echo "========================================="
        echo "  DETAILED HOST ANALYSIS"
        echo "========================================="
        
        while IFS= read -r host; do
            if [[ -n "$host" ]]; then
                echo ""
                echo "HOST: $host"
                echo "$(printf '%.0s=' $(seq 1 ${#host}))======="
                
                # Services
                if [[ -f "$OUTPUT_DIR/services_${host}.txt" ]]; then
                    echo ""
                    echo "SERVICES:"
                    grep -E "^[0-9]+/(tcp|udp).*open" "$OUTPUT_DIR/services_${host}.txt" | head -20
                fi
                
                # SMB shares
                if [[ -f "$OUTPUT_DIR/smb_${host}.txt" ]] && grep -q "Sharename" "$OUTPUT_DIR/smb_${host}.txt"; then
                    echo ""
                    echo "SMB SHARES:"
                    grep -A10 "Sharename" "$OUTPUT_DIR/smb_${host}.txt" | head -15
                fi
                
                # NFS exports
                if [[ -f "$OUTPUT_DIR/nfs_${host}.txt" ]] && grep -q "Export list" "$OUTPUT_DIR/nfs_${host}.txt"; then
                    echo ""
                    echo "NFS EXPORTS:"
                    cat "$OUTPUT_DIR/nfs_${host}.txt"
                fi
                
                echo ""
                echo "----------------------------------------"
            fi
        done < "$hosts_file"
        
        echo ""
        echo "========================================="
        echo "  SCAN METHODOLOGY & VERIFICATION"
        echo "========================================="
        echo ""
        echo "This scan uses VERIFICATION-BASED discovery:"
        echo "1. Multiple discovery methods gather host candidates"
        echo "2. Each candidate is verified using 5 different techniques:"
        echo "   - ARP probes (most reliable for local network)"
        echo "   - TCP SYN probes on common ports"
        echo "   - UDP probes on common services"
        echo "   - ICMP probes (various types)"
        echo "   - TCP connect scans (for defensive devices)"
        echo "3. Only VERIFIED responsive hosts are included"
        echo "4. Comprehensive port scanning on verified hosts only"
        echo "5. Service enumeration and application-specific discovery"
        echo ""
        echo "This approach eliminates false positives by requiring"
        echo "actual response verification before including any host."
        echo ""
        echo "Scan completed: $(date)"
        
    } > "$report_file"
    
    # Generate HTML report
    generate_html_report "$report_file" "$hosts_file"
    
    log "INFO" "Reports generated:"
    log "INFO" "  Text Report: $report_file"
    log "INFO" "  HTML Report: ${report_file%.*}.html"
    return 0
}

# Main execution
main() {
    print_banner
    
    if [[ $# -lt 1 ]]; then
        usage
    fi
    
    NETWORK_RANGE="$1"
    OUTPUT_DIR="${2:-./network_scan_verified_$(date +%Y%m%d_%H%M%S)}"
    
    # Validate network range
    if [[ ! "$NETWORK_RANGE" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
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
    
    log "INFO" "Starting VERIFICATION-BASED network enumeration"
    log "INFO" "Target network: $NETWORK_RANGE"
    
    # Execute phases
    if ! phase1_verified_discovery "$NETWORK_RANGE"; then
        log "ERROR" "Verified discovery failed"
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
    
    log "INFO" "Verification-based enumeration completed successfully!"
    
    # Display summary
    local host_count=$(cat "$OUTPUT_DIR/live_hosts.txt" 2>/dev/null | wc -l)
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}  VERIFICATION-BASED SCAN COMPLETE${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${YELLOW}Verified Live Hosts: ${NC}$host_count"
    echo -e "${YELLOW}Output Directory: ${NC}$OUTPUT_DIR"
    echo -e "${YELLOW}Report: ${NC}$OUTPUT_DIR/NETWORK_ENUMERATION_REPORT.txt"
    echo -e "${GREEN}=========================================${NC}"
}

# Execute main function
main "$@"
