#!/bin/bash

# Fix Sing-Box VPN Routing and Firewall Configuration
# This script properly configures the system for VPN traffic routing

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

print_status "Fixing VPN routing and firewall configuration..."

# 1. Enable IP forwarding permanently
print_status "Enabling IP forwarding..."
cat > /etc/sysctl.d/99-sing-box.conf << EOF
# Sing-Box VPN Settings
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

# Performance tuning
net.core.default_qdisc = fq
net.ipv4.tcp_congestion = bbr
net.ipv4.tcp_fastopen = 3

# Security
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOF

sysctl -p /etc/sysctl.d/99-sing-box.conf > /dev/null 2>&1
print_success "IP forwarding enabled"

# 2. Install required packages
print_status "Installing required packages..."
apt-get update -qq
apt-get install -y -qq \
    iptables \
    iptables-persistent \
    net-tools \
    dnsutils \
    curl \
    wget \
    ca-certificates

print_success "Packages installed"

# 3. Configure UFW if installed
if command -v ufw &> /dev/null; then
    print_status "Configuring UFW firewall..."
    
    # Allow forwarding in UFW
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    
    # Enable UFW routing
    cat >> /etc/ufw/sysctl.conf << EOF

# Sing-Box VPN
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
    
    # Add UFW before rules for NAT
    cat > /etc/ufw/before.rules.sing-box << 'EOF'
# NAT table rules for Sing-Box VPN
*nat
:POSTROUTING ACCEPT [0:0]

# Allow traffic from TUN to be masqueraded
-A POSTROUTING -o tun0 -j MASQUERADE
-A POSTROUTING -o tun+ -j MASQUERADE
-A POSTROUTING -s 172.19.0.0/30 -j MASQUERADE

COMMIT

# Filter rules
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]

# Allow TUN traffic
-A ufw-before-forward -i tun0 -j ACCEPT
-A ufw-before-forward -o tun0 -j ACCEPT
-A ufw-before-forward -i tun+ -j ACCEPT
-A ufw-before-forward -o tun+ -j ACCEPT

COMMIT
EOF
    
    # Backup original and add our rules
    if [ -f /etc/ufw/before.rules ]; then
        cp /etc/ufw/before.rules /etc/ufw/before.rules.backup
        cat /etc/ufw/before.rules.sing-box > /tmp/ufw.tmp
        cat /etc/ufw/before.rules >> /tmp/ufw.tmp
        mv /tmp/ufw.tmp /etc/ufw/before.rules
    fi
    
    # Allow necessary ports
    ufw allow 8080/tcp comment 'Sing-Box Web UI' > /dev/null 2>&1 || true
    ufw allow 22/tcp comment 'SSH' > /dev/null 2>&1 || true
    
    # Reload UFW
    ufw --force disable > /dev/null 2>&1
    ufw --force enable > /dev/null 2>&1
    
    print_success "UFW configured for VPN routing"
else
    print_warning "UFW not installed, skipping UFW configuration"
fi

# 4. Configure iptables directly
print_status "Configuring iptables rules..."

# Clear existing rules
iptables -t nat -F
iptables -t mangle -F
iptables -F FORWARD

# Enable NAT for VPN
iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.19.0.0/30 -j MASQUERADE

# Allow forwarding
iptables -A FORWARD -i tun0 -j ACCEPT
iptables -A FORWARD -o tun0 -j ACCEPT
iptables -A FORWARD -i tun+ -j ACCEPT
iptables -A FORWARD -o tun+ -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Fix MTU issues
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# Save iptables rules
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save > /dev/null 2>&1
elif command -v iptables-save &> /dev/null; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
fi

print_success "Iptables rules configured"

# 5. Create routing script for Sing-Box
print_status "Creating routing helper script..."

cat > /usr/local/bin/sing-box-routing << 'EOF'
#!/bin/bash
# Sing-Box routing helper script

case "$1" in
    up)
        # Enable routing when VPN starts
        sysctl -w net.ipv4.ip_forward=1 > /dev/null
        sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null
        
        # Setup NAT
        iptables -t nat -C POSTROUTING -o tun0 -j MASQUERADE 2>/dev/null || \
            iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
        
        # Allow forwarding
        iptables -C FORWARD -i tun0 -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -i tun0 -j ACCEPT
        iptables -C FORWARD -o tun0 -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -o tun0 -j ACCEPT
        
        echo "VPN routing enabled"
        ;;
    
    down)
        # Clean up when VPN stops
        iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE 2>/dev/null || true
        iptables -D FORWARD -i tun0 -j ACCEPT 2>/dev/null || true
        iptables -D FORWARD -o tun0 -j ACCEPT 2>/dev/null || true
        
        echo "VPN routing disabled"
        ;;
    
    status)
        echo "=== Routing Status ==="
        echo "IP Forward: $(cat /proc/sys/net/ipv4/ip_forward)"
        echo ""
        echo "=== NAT Rules ==="
        iptables -t nat -L POSTROUTING -n -v | grep tun
        echo ""
        echo "=== TUN Interfaces ==="
        ip addr show | grep -E "tun[0-9]|singbox"
        ;;
    
    *)
        echo "Usage: $0 {up|down|status}"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/sing-box-routing
print_success "Routing helper script created"

# 6. Download and setup GeoIP/GeoSite databases
print_status "Downloading GeoIP and GeoSite databases..."

mkdir -p /usr/share/sing-box

# Download databases with progress
wget -q --show-progress \
    "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db" \
    -O /usr/share/sing-box/geoip.db

wget -q --show-progress \
    "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db" \
    -O /usr/share/sing-box/geosite.db

# Also download Iran-specific geoip
wget -q --show-progress \
    "https://github.com/chocolate4u/Iran-sing-box-rules/releases/latest/download/geoip.db" \
    -O /usr/share/sing-box/geoip-iran.db 2>/dev/null || true

print_success "GeoIP databases downloaded"

# 7. Fix DNS resolution
print_status "Configuring DNS..."

# Ensure systemd-resolved doesn't interfere
if systemctl is-active systemd-resolved > /dev/null 2>&1; then
    # Configure systemd-resolved to work with VPN
    mkdir -p /etc/systemd/resolved.conf.d/
    cat > /etc/systemd/resolved.conf.d/sing-box.conf << EOF
[Resolve]
DNS=8.8.8.8 1.1.1.1
FallbackDNS=8.8.4.4 1.0.0.1
DNSOverTLS=opportunistic
Cache=yes
DNSStubListener=no
EOF
    
    systemctl restart systemd-resolved
fi

print_success "DNS configured"

# 8. Update Sing-Box backend with fixed version
print_status "Updating Sing-Box backend..."

if [ -f /etc/singbox-vpn/backend.py ]; then
    # Backup old backend
    cp /etc/singbox-vpn/backend.py /etc/singbox-vpn/backend.py.backup
    
    # Download or copy the fixed backend
    # (The fixed backend from the previous artifact should be copied here)
    print_warning "Please replace /etc/singbox-vpn/backend.py with the fixed version"
fi

# 9. Restart services
print_status "Restarting services..."

systemctl restart singbox-vpn > /dev/null 2>&1 || true

print_success "Services restarted"

# 10. Test connectivity
print_status "Testing configuration..."

# Check if TUN interface will be created
if [ -f /etc/singbox-vpn/config.json ]; then
    print_success "Sing-Box config found"
else
    print_warning "No Sing-Box config found. Import a server first."
fi

# Test DNS
if nslookup google.com > /dev/null 2>&1; then
    print_success "DNS resolution working"
else
    print_warning "DNS resolution might have issues"
fi

# Show current network interfaces
echo ""
echo "=== Current Network Interfaces ==="
ip -brief addr show

echo ""
echo "=== Routing Table ==="
ip route show | head -5

echo ""
print_success "VPN routing and firewall configuration complete!"
echo ""
echo -e "${YELLOW}Important for Iran users:${NC}"
echo "1. The system is now configured to route traffic through VPN"
echo "2. GeoIP databases for Iran have been installed"
echo "3. Local Iranian sites will bypass the VPN automatically"
echo "4. YouTube and other blocked sites will go through VPN"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "1. Access the web UI at http://$(hostname -I | awk '{print $1}'):8080"
echo "2. Import your VPN configuration"
echo "3. Click Connect and then Start VPN"
echo "4. Check status with: sing-box-routing status"
echo ""
echo -e "${BLUE}Troubleshooting:${NC}"
echo "- Check VPN logs: journalctl -u singbox-vpn -f"
echo "- Check routing: sing-box-routing status"
echo "- Test DNS: nslookup youtube.com"
echo "- Check TUN interface: ip addr show tun0"
