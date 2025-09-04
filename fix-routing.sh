#!/bin/bash

# Complete Sing-Box VPN Routing Fix
# This script fixes all routing issues for proper VPN operation

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

print_status "Starting complete VPN routing fix..."

# 1. Stop everything first
print_status "Stopping existing services..."
systemctl stop singbox-vpn 2>/dev/null || true
pkill -f sing-box 2>/dev/null || true
sleep 2

# 2. Fix system networking settings
print_status "Configuring system networking..."

# Enable IP forwarding
cat > /etc/sysctl.d/99-sing-box.conf << EOF
# Sing-Box VPN Settings
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.default.accept_source_route = 1

# Performance
net.core.default_qdisc = fq
net.ipv4.tcp_congestion = bbr
net.ipv4.tcp_fastopen = 3
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_mem = 786432 1048576 26777216
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432

# DNS
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
EOF

sysctl -p /etc/sysctl.d/99-sing-box.conf

print_success "System networking configured"

# 3. Clean and setup iptables
print_status "Setting up firewall rules..."

# Clean existing rules
iptables -t nat -F
iptables -t mangle -F
iptables -t filter -F
iptables -X

# Set default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Enable NAT for all possible TUN interfaces
for tun in tun0 tun1 utun singbox0; do
    iptables -t nat -A POSTROUTING -o $tun -j MASQUERADE 2>/dev/null || true
done

# Enable NAT for the subnet
iptables -t nat -A POSTROUTING -s 172.19.0.0/30 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 198.18.0.0/15 -j MASQUERADE

# Allow forwarding
iptables -A FORWARD -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -j ACCEPT

# Fix MSS clamping for PPPoE/tunnels
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# Save rules
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
elif command -v iptables-save &> /dev/null; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
fi

print_success "Firewall rules configured"

# 4. Fix UFW if present
if command -v ufw &> /dev/null; then
    print_status "Fixing UFW..."
    
    # Backup UFW config
    cp /etc/default/ufw /etc/default/ufw.backup 2>/dev/null || true
    
    # Enable forwarding in UFW
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    
    # Add rules before UFW loads
    cat > /etc/ufw/before.rules.new << 'EOF'
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 172.19.0.0/30 -j MASQUERADE
-A POSTROUTING -o tun0 -j MASQUERADE
-A POSTROUTING -o tun+ -j MASQUERADE
COMMIT

# Allow forwarding for TUN
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
-A ufw-before-forward -j ACCEPT
COMMIT
EOF
    
    # Prepend to existing rules
    if [ -f /etc/ufw/before.rules ]; then
        cp /etc/ufw/before.rules /etc/ufw/before.rules.backup
        cat /etc/ufw/before.rules.new /etc/ufw/before.rules.backup > /etc/ufw/before.rules
    fi
    
    # Reload UFW
    ufw --force disable
    ufw --force enable
    
    print_success "UFW fixed"
fi

# 5. Download and update GeoIP databases
print_status "Downloading GeoIP databases..."

mkdir -p /usr/share/sing-box

# Download with error handling
download_file() {
    local url=$1
    local output=$2
    local name=$3
    
    if wget -q --timeout=10 --tries=2 -O "$output" "$url"; then
        print_success "$name downloaded"
    else
        print_warning "Failed to download $name (not critical)"
    fi
}

download_file \
    "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db" \
    "/usr/share/sing-box/geoip.db" \
    "GeoIP database"

download_file \
    "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db" \
    "/usr/share/sing-box/geosite.db" \
    "GeoSite database"

# 6. Create test configuration
print_status "Creating test configuration..."

cat > /etc/singbox-vpn/test-direct.json << 'EOF'
{
  "log": {
    "level": "debug",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "google",
        "address": "8.8.8.8"
      }
    ],
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun0",
      "inet4_address": "172.19.0.1/30",
      "mtu": 9000,
      "auto_route": true,
      "strict_route": false,
      "stack": "system"
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "auto_detect_interface": true
  }
}
EOF

# 7. Create advanced routing script
print_status "Creating advanced routing script..."

cat > /usr/local/bin/fix-vpn-routing << 'EOF'
#!/bin/bash

# Advanced VPN Routing Fixer

case "$1" in
    check)
        echo "=== Checking VPN Routing ==="
        
        # Check IP forwarding
        echo -n "IP Forwarding: "
        if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
            echo "✓ Enabled"
        else
            echo "✗ Disabled - Fixing..."
            sysctl -w net.ipv4.ip_forward=1
        fi
        
        # Check TUN interface
        echo -n "TUN Interface: "
        if ip link show tun0 &>/dev/null; then
            echo "✓ Active"
            ip addr show tun0
        else
            echo "✗ Not found"
        fi
        
        # Check NAT rules
        echo -n "NAT Rules: "
        if iptables -t nat -L POSTROUTING -n | grep -q MASQUERADE; then
            echo "✓ Present"
        else
            echo "✗ Missing - Fixing..."
            iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
        fi
        
        # Check default route
        echo "Default Route:"
        ip route | grep default
        
        # Check DNS
        echo "DNS Servers:"
        cat /etc/resolv.conf | grep nameserver
        ;;
        
    fix)
        echo "Applying comprehensive routing fix..."
        
        # Enable forwarding
        sysctl -w net.ipv4.ip_forward=1
        sysctl -w net.ipv6.conf.all.forwarding=1
        
        # Clear and set iptables
        iptables -t nat -F
        iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
        iptables -t nat -A POSTROUTING -s 172.19.0.0/30 -j MASQUERADE
        
        iptables -F FORWARD
        iptables -A FORWARD -j ACCEPT
        
        # Add route if TUN exists
        if ip link show tun0 &>/dev/null; then
            # Get default gateway
            GW=$(ip route | grep default | awk '{print $3}')
            DEV=$(ip route | grep default | awk '{print $5}')
            
            # Add specific routes for VPN server (prevents routing loop)
            # You'll need to add your VPN server IP here
            # ip route add YOUR_VPN_SERVER_IP via $GW dev $DEV
            
            # Force all traffic through TUN
            ip route add default dev tun0 metric 1 2>/dev/null || true
        fi
        
        echo "Routing fix applied!"
        ;;
        
    test)
        echo "Testing connectivity..."
        
        # Test local network
        echo -n "Local network: "
        if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
            echo "✓ OK"
        else
            echo "✗ Failed"
        fi
        
        # Test DNS
        echo -n "DNS resolution: "
        if nslookup google.com &>/dev/null; then
            echo "✓ OK"
        else
            echo "✗ Failed"
        fi
        
        # Test HTTP
        echo -n "HTTP connection: "
        if curl -s --max-time 5 http://www.google.com &>/dev/null; then
            echo "✓ OK"
        else
            echo "✗ Failed"
        fi
        
        # Show current IP
        echo "Current public IP:"
        curl -s --max-time 5 ifconfig.io || echo "Failed to get IP"
        ;;
        
    *)
        echo "Usage: $0 {check|fix|test}"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/fix-vpn-routing

print_success "Advanced routing script created"

# 8. Create working Sing-Box runner
print_status "Creating Sing-Box runner script..."

cat > /usr/local/bin/run-sing-box << 'EOF'
#!/bin/bash

CONFIG_FILE="${1:-/etc/singbox-vpn/config.json}"

# Pre-flight checks
echo "Starting Sing-Box VPN..."

# Ensure routing is ready
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
iptables -t nat -C POSTROUTING -o tun0 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE

# Kill any existing sing-box
pkill -f sing-box 2>/dev/null || true
sleep 1

# Start sing-box with proper permissions
exec /usr/local/bin/sing-box run -c "$CONFIG_FILE"
EOF

chmod +x /usr/local/bin/run-sing-box

# 9. Fix DNS resolution
print_status "Fixing DNS resolution..."

# Disable systemd-resolved if it's interfering
if systemctl is-active systemd-resolved >/dev/null 2>&1; then
    print_warning "Configuring systemd-resolved..."
    
    mkdir -p /etc/systemd/resolved.conf.d/
    cat > /etc/systemd/resolved.conf.d/sing-box.conf << EOF
[Resolve]
DNS=8.8.8.8 1.1.1.1
FallbackDNS=8.8.4.4
Domains=~.
DNSOverTLS=no
Cache=yes
DNSStubListener=no
EOF
    
    systemctl restart systemd-resolved
    
    # Link resolv.conf properly
    rm -f /etc/resolv.conf
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null || \
        echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > /etc/resolv.conf
fi

# Ensure we have working DNS
if ! grep -q "8.8.8.8\|1.1.1.1" /etc/resolv.conf; then
    cp /etc/resolv.conf /etc/resolv.conf.backup
    echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > /etc/resolv.conf
fi

print_success "DNS configured"

# 10. Test basic connectivity
print_status "Testing basic connectivity..."

# Test DNS
if nslookup google.com >/dev/null 2>&1; then
    print_success "DNS resolution working"
else
    print_warning "DNS resolution may have issues"
fi

# Test internet
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
    print_success "Internet connectivity OK"
else
    print_warning "Internet connectivity issues detected"
fi

# 11. Restart service with proper config
print_status "Restarting VPN service..."

# Make sure we have a valid config
if [ ! -f /etc/singbox-vpn/config.json ]; then
    print_warning "No config.json found. You need to import a server first."
else
    # Try to start the service
    systemctl restart singbox-vpn 2>/dev/null || true
    sleep 3
    
    if systemctl is-active singbox-vpn >/dev/null 2>&1; then
        print_success "VPN service started"
    else
        print_warning "VPN service not running. Start it manually after importing a server."
    fi
fi

# 12. Show diagnostic info
echo ""
echo "========================================"
echo "         DIAGNOSTIC INFORMATION"
echo "========================================"
echo ""

# Show network interfaces
echo "Network Interfaces:"
ip -brief addr show | grep -E "tun|UP"
echo ""

# Show routing table
echo "Main routes:"
ip route | head -5
echo ""

# Show NAT rules
echo "NAT rules:"
iptables -t nat -L POSTROUTING -n | grep MASQUE
echo ""

# Test commands
echo "========================================"
echo "         TESTING COMMANDS"
echo "========================================"
echo ""
echo "1. Check routing status:"
echo "   fix-vpn-routing check"
echo ""
echo "2. Test connectivity:"
echo "   fix-vpn-routing test"
echo ""
echo "3. Fix routing issues:"
echo "   fix-vpn-routing fix"
echo ""
echo "4. Check VPN logs:"
echo "   journalctl -u singbox-vpn -f"
echo ""
echo "5. Run Sing-Box manually:"
echo "   run-sing-box /etc/singbox-vpn/config.json"
echo ""
echo "6. Test with direct config:"
echo "   sing-box run -c /etc/singbox-vpn/test-direct.json"
echo ""

print_success "Complete routing fix applied!"
echo ""
print_warning "IMPORTANT: After importing a VPN server in the web UI:"
echo "1. Click 'Connect' on the server"
echo "2. Click 'Start VPN'"
echo "3. Run: fix-vpn-routing fix"
echo "4. Test with: fix-vpn-routing test"
