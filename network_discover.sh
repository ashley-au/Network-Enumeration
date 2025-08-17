#!/bin/bash
# Accurate Network Device Discovery Script
# Focuses on actual device verification rather than assumptions
# Usage: ./network_discover.sh <network_range>

VERSION="3.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Global variables for HTML report data
declare -a HTML_RESULTS=()
declare -a LIVE_DEVICES=()
declare -a FILTERED_DEVICES=()
declare -a DEAD_DEVICES=()

# Generate HTML report
generate_html_report() {
    local network="$1"
    local all_candidates="$2"
    local live_count="$3"
    local html_file="network_discovery_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$html_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Device Discovery Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            padding: 30px;
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2c3e50;
            margin: 0;
            font-size: 2.5em;
        }
        .header .subtitle {
            color: #7f8c8d;
            font-size: 1.2em;
            margin-top: 10px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        .summary-card h3 {
            margin: 0;
            font-size: 2em;
        }
        .summary-card p {
            margin: 10px 0 0 0;
            font-size: 1.1em;
        }
        .methodology {
            background-color: #ecf0f1;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .methodology h2 {
            color: #2c3e50;
            margin-top: 0;
        }
        .method-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .method-item {
            background: white;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        .method-item h4 {
            margin: 0 0 8px 0;
            color: #2c3e50;
        }
        .results-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .results-table th {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }
        .results-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #ecf0f1;
        }
        .results-table tr:hover {
            background-color: #f8f9fa;
        }
        .status-live {
            background-color: #d4edda;
            color: #155724;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        .status-filtered {
            background-color: #fff3cd;
            color: #856404;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        .status-dead {
            background-color: #f8d7da;
            color: #721c24;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        .method-badge {
            background-color: #6c757d;
            color: white;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 500;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            color: #7f8c8d;
        }
        .scan-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .scan-info strong {
            color: #2c3e50;
        }
    </style>
</head>
<body>
EOF

    # Add dynamic content
    cat >> "$html_file" << EOF
    <div class="container">
        <div class="header">
            <h1>Network Device Discovery Report</h1>
            <div class="subtitle">Verification-Based Network Enumeration</div>
        </div>
        
        <div class="scan-info">
            <strong>Network Range:</strong> $network<br>
            <strong>Scan Date:</strong> $(date)<br>
            <strong>Scan Method:</strong> Multi-Protocol Verification
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>$live_count</h3>
                <p>Live Devices Found</p>
            </div>
            <div class="summary-card">
                <h3>6</h3>
                <p>Verification Methods</p>
            </div>
            <div class="summary-card">
                <h3>$(echo "$all_candidates" | wc -w)</h3>
                <p>Total Candidates Tested</p>
            </div>
        </div>
        
        <div class="methodology">
            <h2>Verification Methodology</h2>
            <p>Each device candidate is tested using multiple methods to ensure accurate detection:</p>
            <div class="method-list">
                <div class="method-item">
                    <h4>ICMP Ping</h4>
                    <p>Standard ping test for basic connectivity</p>
                </div>
                <div class="method-item">
                    <h4>ARP Probes</h4>
                    <p>Layer 2 discovery, most reliable for local networks</p>
                </div>
                <div class="method-item">
                    <h4>TCP SYN Probes</h4>
                    <p>Tests common service ports (22,80,443,8008,etc.)</p>
                </div>
                <div class="method-item">
                    <h4>UDP Probes</h4>
                    <p>Tests UDP services (DNS, DHCP, SNMP, etc.)</p>
                </div>
                <div class="method-item">
                    <h4>Advanced ICMP</h4>
                    <p>Multiple ICMP types for stealth devices</p>
                </div>
                <div class="method-item">
                    <h4>TCP Connect</h4>
                    <p>Direct connection attempts as last resort</p>
                </div>
            </div>
        </div>
        
        <h2>Device Discovery Results</h2>
        <table class="results-table">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>Detection Method</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
EOF

    # Add results from the HTML_RESULTS array
    printf '%s\n' "${HTML_RESULTS[@]}" >> "$html_file"
    
    # Close HTML
    cat >> "$html_file" << 'EOF'
            </tbody>
        </table>
        
        <div class="footer">
            <p>Report generated by Network Device Discovery v3.0</p>
            <p>Verification-based approach ensures accurate results with minimal false positives</p>
        </div>
    </div>
</body>
</html>
EOF

    echo -e "\n${GREEN}Reports generated:${NC}"
    echo -e "${BLUE}  HTML Report: ${html_file}${NC}"
}

# Print results
print_result() {
    local ip="$1"
    local status="$2"
    local method="$3"
    local info="$4"
    
    case $status in
        "LIVE") color=$GREEN ;;
        "FILTERED") color=$YELLOW ;;
        "DEAD") color=$RED ;;
        *) color=$NC ;;
    esac
    
    printf "${color}%-15s %-10s %-15s %s${NC}\n" "$ip" "$status" "$method" "$info"
    
    # Add to HTML report data
    local html_status_class="status-$(echo "$status" | tr '[:upper:]' '[:lower:]')"
    HTML_RESULTS+=("                <tr>")
    HTML_RESULTS+=("                    <td>$ip</td>")
    HTML_RESULTS+=("                    <td><span class=\"$html_status_class\">$status</span></td>")
    HTML_RESULTS+=("                    <td><span class=\"method-badge\">$method</span></td>")
    HTML_RESULTS+=("                    <td>$info</td>")
    HTML_RESULTS+=("                </tr>")
}

# Comprehensive device verification
verify_device() {
    local ip="$1"
    
    # Method 1: Ping test
    if ping -c 1 -W 1 "$ip" &>/dev/null; then
        print_result "$ip" "LIVE" "PING" "Responds to ICMP"
        return 0
    fi
    
    # Method 2: ARP probe (local network)
    if nmap -sn -PR "$ip" 2>/dev/null | grep -q "Host is up"; then
        local mac=$(nmap -sn -PR "$ip" 2>/dev/null | grep "MAC Address" | awk '{print $3" "$4}')
        print_result "$ip" "LIVE" "ARP" "MAC: ${mac:-Unknown}"
        return 0
    fi
    
    # Method 3: TCP probe common ports
    local tcp_result=$(nmap -sS -Pn -p 22,80,135,139,443,445,8008,8080,8443 "$ip" --max-retries 2 --host-timeout 3s 2>/dev/null)
    if echo "$tcp_result" | grep -q "Host is up"; then
        local open_ports=$(echo "$tcp_result" | grep "^[0-9]*/tcp.*open" | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
        if [[ -n "$open_ports" ]]; then
            print_result "$ip" "LIVE" "TCP" "Open ports: $open_ports"
            return 0
        else
            print_result "$ip" "FILTERED" "TCP" "Host up but filtered"
            return 0
        fi
    fi
    
    # Method 4: UDP probe common services
    local udp_result=$(nmap -sU -Pn -p 53,67,123,137,161,1900,5353 "$ip" --max-retries 1 --host-timeout 3s 2>/dev/null)
    if echo "$udp_result" | grep -q "Host is up"; then
        local udp_ports=$(echo "$udp_result" | grep "^[0-9]*/udp.*open" | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
        print_result "$ip" "LIVE" "UDP" "UDP services: ${udp_ports:-filtered}"
        return 0
    fi
    
    # Method 5: Advanced ICMP probes
    if nmap -sn -PE -PP -PM -PS80,443,22 -PA80,443 "$ip" 2>/dev/null | grep -q "Host is up"; then
        print_result "$ip" "LIVE" "ICMP_ADV" "Advanced ICMP response"
        return 0
    fi
    
    # Method 6: TCP Connect (last resort)
    local connect_test=""
    for port in 80 443 22 8008 8080; do
        if timeout 2 bash -c "</dev/tcp/$ip/$port" 2>/dev/null; then
            connect_test="$port,$connect_test"
        fi
    done
    
    if [[ -n "$connect_test" ]]; then
        print_result "$ip" "LIVE" "TCP_CONNECT" "Connect: ${connect_test%,}"
        return 0
    fi
    
    return 1
}

# Main scanning function
scan_network() {
    local network="$1"
    local base_ip=$(echo "$network" | cut -d'/' -f1 | cut -d'.' -f1-3)
    
    echo -e "${BLUE}Starting comprehensive device discovery on $network${NC}"
    echo ""
    printf "%-15s %-10s %-15s %s\n" "IP ADDRESS" "STATUS" "METHOD" "DETAILS"
    printf "%-15s %-10s %-15s %s\n" "----------" "------" "------" "-------"
    
    # Step 1: Fast ARP scan to get obvious candidates
    echo -e "\n${YELLOW}[1/3] Fast ARP discovery...${NC}"
    local arp_hosts=$(nmap -sn -PR "$network" 2>/dev/null | grep "Nmap scan report" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort -u)
    
    # Step 2: Broadcast discovery
    echo -e "${YELLOW}[2/3] Broadcast discovery...${NC}"
    local broadcast_hosts=$(nmap -sn --script broadcast-ping,broadcast-igmp-discovery "$network" 2>/dev/null | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort -u)
    
    # Step 3: Common IP testing  
    echo -e "${YELLOW}[3/3] Testing common device IPs...${NC}"
    local common_ips="1 2 10 15 50 69 100 101 110 150 190 195 200 209 210 211 214 219 220 230 243 247 250 251 252 253 254"
    local common_hosts=""
    for ip in $common_ips; do
        common_hosts="$common_hosts ${base_ip}.${ip}"
    done
    
    echo -e "\n${GREEN}Device Verification Results:${NC}"
    printf "%-15s %-10s %-15s %s\n" "IP ADDRESS" "STATUS" "METHOD" "DETAILS"
    printf "%-15s %-10s %-15s %s\n" "----------" "------" "------" "-------"
    
    # Combine all candidates and verify each one
    local all_candidates=$(echo -e "$arp_hosts\n$broadcast_hosts\n$common_hosts" | tr ' ' '\n' | sort -u | grep -E "^([0-9]{1,3}\.){3}[0-9]{1,3}$")
    
    local live_count=0
    local filtered_count=0
    
    while IFS= read -r ip; do
        if [[ -n "$ip" ]]; then
            if verify_device "$ip"; then
                if [[ $? -eq 0 ]]; then
                    ((live_count++))
                fi
            else
                # Only show dead results for IPs that were found by discovery methods
                if echo -e "$arp_hosts\n$broadcast_hosts" | grep -q "$ip"; then
                    print_result "$ip" "DEAD" "NO_RESPONSE" "No response to any probe"
                fi
            fi
        fi
    done <<< "$all_candidates"
    
    echo ""
    echo -e "${GREEN}Summary: $live_count live devices discovered${NC}"
    echo -e "${YELLOW}Note: FILTERED devices may have firewalls blocking probes${NC}"
    
    # Generate HTML report
    generate_html_report "$network" "$all_candidates" "$live_count"
}

# Usage
usage() {
    echo "Usage: $0 <network_range>"
    echo "Examples:"
    echo "  $0 192.168.1.0/24"
    echo "  $0 10.0.0.0/24"
    exit 1
}

# Main
main() {
    echo -e "${BLUE}"
    echo "=============================================="
    echo "  Accurate Network Device Discovery v$VERSION"
    echo "  Verification-Based Approach"
    echo "=============================================="
    echo -e "${NC}"
    
    if [[ $# -ne 1 ]]; then
        usage
    fi
    
    local network="$1"
    
    # Validate network format
    if [[ ! "$network" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        echo -e "${RED}Error: Invalid network format. Use CIDR notation (e.g., 192.168.1.0/24)${NC}"
        exit 1
    fi
    
    # Check if nmap is available
    if ! command -v nmap &> /dev/null; then
        echo -e "${RED}Error: nmap is required but not installed${NC}"
        echo "Install with: sudo dnf install nmap"
        exit 1
    fi
    
    scan_network "$network"
}

main "$@"
