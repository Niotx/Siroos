#!/bin/bash

# Sing-Box VPN Manager Installation Script
# One-line install: curl -fsSL https://your-domain.com/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/etc/singbox-vpn"
WEB_DIR="$INSTALL_DIR/web"
SERVICE_NAME="singbox-vpn"
SINGBOX_VERSION="1.8.0"
ARCH=$(uname -m)

# Functions
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    exit 1
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        print_error "Cannot detect OS"
    fi
    
    if [[ "$OS" != "debian" && "$OS" != "ubuntu" && "$OS" != "raspbian" ]]; then
        print_error "This script only supports Debian/Ubuntu/Raspbian"
    fi
}

install_dependencies() {
    print_status "Installing dependencies..."
    
    apt-get update -qq
    apt-get install -y -qq \
        curl \
        wget \
        unzip \
        python3 \
        python3-pip \
        python3-venv \
        iptables \
        ca-certificates \
        gnupg \
        lsb-release \
        systemd \
        net-tools \
        jq \
        git
    
    print_success "Dependencies installed"
}

install_singbox() {
    print_status "Installing Sing-Box core..."
    
    # Determine architecture
    case $ARCH in
        x86_64)
            SING_ARCH="amd64"
            ;;
        aarch64)
            SING_ARCH="arm64"
            ;;
        armv7l)
            SING_ARCH="armv7"
            ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            ;;
    esac
    
    # Download Sing-Box
    DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${SING_ARCH}.tar.gz"
    
    print_status "Downloading Sing-Box from $DOWNLOAD_URL..."
    wget -q --show-progress "$DOWNLOAD_URL" -O /tmp/sing-box.tar.gz
    
    # Extract and install
    tar -xzf /tmp/sing-box.tar.gz -C /tmp
    mv /tmp/sing-box-*/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    # Clean up
    rm -rf /tmp/sing-box*
    
    # Verify installation
    if ! command -v sing-box &> /dev/null; then
        print_error "Sing-Box installation failed"
    fi
    
    INSTALLED_VERSION=$(sing-box version | head -n1)
    print_success "Sing-Box installed: $INSTALLED_VERSION"
}

setup_python_env() {
    print_status "Setting up Python environment..."
    
    # Create virtual environment
    python3 -m venv $INSTALL_DIR/venv
    
    # Activate and install packages
    source $INSTALL_DIR/venv/bin/activate
    pip install --upgrade pip -q
    pip install -q \
        flask==3.0.0 \
        flask-cors==4.0.0 \
        requests==2.31.0 \
        psutil==5.9.6
    
    deactivate
    
    print_success "Python environment ready"
}

install_backend() {
    print_status "Installing backend service..."
    
    # Create directories
    mkdir -p $INSTALL_DIR/{configs,web}
    
    # Download backend script
    cat > $INSTALL_DIR/backend.py << 'EOF'
#!/usr/bin/env python3
"""
Sing-Box VPN Manager Backend Service
A lightweight REST API for managing Sing-Box VPN configurations
"""

import os
import json
import base64
import subprocess
import threading
import time
import uuid
import requests
import psutil
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Configuration paths
BASE_DIR = Path("/etc/singbox-vpn")
CONFIG_DIR = BASE_DIR / "configs"
SINGBOX_CONFIG = BASE_DIR / "config.json"
DB_FILE = BASE_DIR / "servers.json"
LOG_FILE = BASE_DIR / "vpn.log"
WEB_DIR = BASE_DIR / "web"

# Ensure directories exist
BASE_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_DIR.mkdir(exist_ok=True)
WEB_DIR.mkdir(exist_ok=True)

# Global state
current_config = None
vpn_status = {
    "connected": False,
    "server": None,
    "start_time": None,
    "download_speed": 0,
    "upload_speed": 0,
    "total_traffic": 0
}
logs = []
servers_db = []

class V2RayParser:
    """Parse V2Ray/VMess/VLESS/Trojan/Reality configs"""
    
    @staticmethod
    def parse_vmess(url: str) -> Dict:
        """Parse VMess URL"""
        try:
            # Remove vmess:// prefix and decode
            data = base64.b64decode(url.replace("vmess://", "")).decode()
            config = json.loads(data)
            
            return {
                "type": "vmess",
                "tag": config.get("ps", "VMess Server"),
                "server": config.get("add"),
                "server_port": int(config.get("port", 443)),
                "uuid": config.get("id"),
                "security": config.get("scy", "auto"),
                "alter_id": int(config.get("aid", 0)),
                "transport": {
                    "type": config.get("net", "tcp"),
                    "host": config.get("host", ""),
                    "path": config.get("path", "/"),
                },
                "tls": {
                    "enabled": config.get("tls") == "tls",
                    "server_name": config.get("sni", config.get("add")),
                    "insecure": True
                }
            }
        except Exception as e:
            raise ValueError(f"Invalid VMess config: {e}")
    
    @staticmethod
    def parse_vless(url: str) -> Dict:
        """Parse VLESS URL"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            return {
                "type": "vless",
                "tag": params.get("remarks", ["VLESS Server"])[0],
                "server": parsed.hostname,
                "server_port": parsed.port or 443,
                "uuid": parsed.username,
                "flow": params.get("flow", [""])[0],
                "transport": {
                    "type": params.get("type", ["tcp"])[0],
                    "host": params.get("host", [""])[0],
                    "path": params.get("path", ["/"])[0],
                },
                "tls": {
                    "enabled": params.get("security", ["tls"])[0] == "tls",
                    "server_name": params.get("sni", [parsed.hostname])[0],
                    "insecure": True,
                    "reality": {
                        "enabled": params.get("security", [""])[0] == "reality",
                        "public_key": params.get("pbk", [""])[0],
                        "short_id": params.get("sid", [""])[0]
                    }
                }
            }
        except Exception as e:
            raise ValueError(f"Invalid VLESS config: {e}")
    
    @staticmethod
    def parse_trojan(url: str) -> Dict:
        """Parse Trojan URL"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            return {
                "type": "trojan",
                "tag": params.get("remarks", ["Trojan Server"])[0],
                "server": parsed.hostname,
                "server_port": parsed.port or 443,
                "password": parsed.username,
                "transport": {
                    "type": params.get("type", ["tcp"])[0],
                    "host": params.get("host", [""])[0],
                    "path": params.get("path", ["/"])[0],
                },
                "tls": {
                    "enabled": True,
                    "server_name": params.get("sni", [parsed.hostname])[0],
                    "insecure": True
                }
            }
        except Exception as e:
            raise ValueError(f"Invalid Trojan config: {e}")
    
    @staticmethod
    def parse_config(url: str) -> Dict:
        """Auto-detect and parse config"""
        if url.startswith("vmess://"):
            return V2RayParser.parse_vmess(url)
        elif url.startswith("vless://"):
            return V2RayParser.parse_vless(url)
        elif url.startswith("trojan://"):
            return V2RayParser.parse_trojan(url)
        else:
            raise ValueError(f"Unsupported protocol: {url.split('://')[0]}")

class SingBoxManager:
    """Manage Sing-Box core"""
    
    @staticmethod
    def generate_config(outbound: Dict) -> Dict:
        """Generate Sing-Box config from parsed outbound"""
        config = {
            "log": {
                "level": "info",
                "timestamp": True
            },
            "dns": {
                "servers": [
                    {
                        "tag": "google",
                        "address": "tls://8.8.8.8"
                    },
                    {
                        "tag": "local",
                        "address": "223.5.5.5",
                        "detour": "direct"
                    }
                ],
                "rules": [
                    {
                        "geosite": "cn",
                        "server": "local"
                    }
                ],
                "strategy": "prefer_ipv4"
            },
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "singbox0",
                    "inet4_address": "172.19.0.1/30",
                    "auto_route": True,
                    "strict_route": True,
                    "stack": "system",
                    "sniff": True
                }
            ],
            "outbounds": [
                outbound,
                {
                    "type": "direct",
                    "tag": "direct"
                },
                {
                    "type": "block",
                    "tag": "block"
                },
                {
                    "type": "dns",
                    "tag": "dns-out"
                }
            ],
            "route": {
                "rules": [
                    {
                        "protocol": "dns",
                        "outbound": "dns-out"
                    },
                    {
                        "geosite": "cn",
                        "geoip": ["cn", "private"],
                        "outbound": "direct"
                    }
                ],
                "auto_detect_interface": True
            }
        }
        
        return config
    
    @staticmethod
    def start():
        """Start Sing-Box service"""
        try:
            # Stop existing instance
            SingBoxManager.stop()
            
            # Start new instance
            cmd = ["systemctl", "start", "sing-box"]
            subprocess.run(cmd, check=True)
            
            # Wait for service to start
            time.sleep(2)
            
            # Check if running
            result = subprocess.run(
                ["systemctl", "is-active", "sing-box"],
                capture_output=True,
                text=True
            )
            
            return result.stdout.strip() == "active"
        except Exception as e:
            log_message(f"Failed to start Sing-Box: {e}", "error")
            return False
    
    @staticmethod
    def stop():
        """Stop Sing-Box service"""
        try:
            subprocess.run(["systemctl", "stop", "sing-box"], check=True)
            return True
        except:
            return False
    
    @staticmethod
    def restart():
        """Restart Sing-Box service"""
        SingBoxManager.stop()
        time.sleep(1)
        return SingBoxManager.start()
    
    @staticmethod
    def test_config(config: Dict) -> tuple:
        """Test configuration"""
        try:
            # Save temp config
            temp_config = BASE_DIR / "test_config.json"
            with open(temp_config, "w") as f:
                json.dump(config, f, indent=2)
            
            # Test config syntax
            result = subprocess.run(
                ["sing-box", "check", "-c", str(temp_config)],
                capture_output=True,
                text=True
            )
            
            # Clean up
            temp_config.unlink()
            
            return result.returncode == 0, result.stderr
        except Exception as e:
            return False, str(e)

def log_message(message: str, level: str = "info"):
    """Add log message"""
    global logs
    entry = {
        "time": datetime.now().isoformat(),
        "level": level,
        "message": message
    }
    logs.append(entry)
    
    # Keep only last 100 logs
    if len(logs) > 100:
        logs = logs[-100:]
    
    # Also write to file
    with open(LOG_FILE, "a") as f:
        f.write(f"{entry['time']} [{level.upper()}] {message}\n")

def load_servers():
    """Load servers from database"""
    global servers_db
    if DB_FILE.exists():
        with open(DB_FILE, "r") as f:
            servers_db = json.load(f)
    return servers_db

def save_servers():
    """Save servers to database"""
    with open(DB_FILE, "w") as f:
        json.dump(servers_db, f, indent=2)

def import_subscription(url: str) -> List[Dict]:
    """Import configs from subscription URL"""
    try:
        response = requests.get(url, timeout=10)
        content = response.text
        
        # Decode base64 if needed
        try:
            content = base64.b64decode(content).decode()
        except:
            pass
        
        # Parse configs
        configs = []
        for line in content.split('\n'):
            line = line.strip()
            if line and '://' in line:
                try:
                    config = V2RayParser.parse_config(line)
                    configs.append(config)
                except Exception as e:
                    log_message(f"Failed to parse config: {e}", "warning")
        
        return configs
    except Exception as e:
        raise ValueError(f"Failed to import subscription: {e}")

def test_server_connection(server: Dict) -> Dict:
    """Test server connection"""
    try:
        # Generate test config
        config = SingBoxManager.generate_config(server)
        
        # Test config validity
        valid, error = SingBoxManager.test_config(config)
        if not valid:
            return {"alive": False, "error": error}
        
        # Try to connect and measure latency
        start_time = time.time()
        
        # Simple TCP connection test
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((server["server"], server["server_port"]))
        sock.close()
        
        latency = int((time.time() - start_time) * 1000)
        
        return {
            "alive": result == 0,
            "latency": latency if result == 0 else None,
            "error": None if result == 0 else "Connection failed"
        }
    except Exception as e:
        return {"alive": False, "error": str(e)}

# Flask Routes

@app.route('/')
def index():
    """Serve web UI"""
    return send_from_directory(WEB_DIR, 'index.html')

@app.route('/api/import', methods=['POST'])
def import_config():
    """Import configuration"""
    try:
        data = request.json
        import_type = data.get('type')
        import_data = data.get('data')
        
        configs = []
        
        if import_type == 'url':
            configs = import_subscription(import_data)
        elif import_type == 'text':
            # Parse single or multiple configs
            for line in import_data.split('\n'):
                line = line.strip()
                if line and '://' in line:
                    config = V2RayParser.parse_config(line)
                    configs.append(config)
        elif import_type == 'file':
            # Handle file content
            try:
                # Try parsing as JSON first
                configs = [json.loads(import_data)]
            except:
                # Try parsing as URL list
                for line in import_data.split('\n'):
                    line = line.strip()
                    if line and '://' in line:
                        config = V2RayParser.parse_config(line)
                        configs.append(config)
        
        # Add configs to database
        for config in configs:
            server_id = str(uuid.uuid4())
            server_entry = {
                "id": server_id,
                "name": config.get("tag", "Unknown"),
                "type": config["type"],
                "address": config["server"],
                "port": config["server_port"],
                "config": config,
                "active": False,
                "latency": None,
                "added": datetime.now().isoformat()
            }
            servers_db.append(server_entry)
        
        save_servers()
        log_message(f"Imported {len(configs)} servers")
        
        return jsonify({"success": True, "count": len(configs)})
    
    except Exception as e:
        log_message(f"Import failed: {e}", "error")
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/servers', methods=['GET'])
def get_servers():
    """Get all servers"""
    return jsonify(servers_db)

@app.route('/api/servers/<server_id>', methods=['DELETE'])
def delete_server(server_id):
    """Delete a server"""
    global servers_db
    servers_db = [s for s in servers_db if s["id"] != server_id]
    save_servers()
    return jsonify({"success": True})

@app.route('/api/test/<server_id>', methods=['POST'])
def test_server(server_id):
    """Test server connection"""
    server = next((s for s in servers_db if s["id"] == server_id), None)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404
    
    result = test_server_connection(server["config"])
    
    # Update latency in database
    server["latency"] = result.get("latency")
    save_servers()
    
    return jsonify({
        "success": True,
        "alive": result["alive"],
        "latency": result.get("latency"),
        "error": result.get("error")
    })

@app.route('/api/connect/<server_id>', methods=['POST'])
def connect_server(server_id):
    """Connect to a server"""
    global current_config, vpn_status
    
    server = next((s for s in servers_db if s["id"] == server_id), None)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404
    
    try:
        # Generate and save config
        config = SingBoxManager.generate_config(server["config"])
        with open(SINGBOX_CONFIG, "w") as f:
            json.dump(config, f, indent=2)
        
        # Update server status
        for s in servers_db:
            s["active"] = s["id"] == server_id
        save_servers()
        
        # Start VPN
        if SingBoxManager.start():
            current_config = server_id
            vpn_status["connected"] = True
            vpn_status["server"] = server["name"]
            vpn_status["start_time"] = datetime.now().isoformat()
            
            log_message(f"Connected to {server['name']}")
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Failed to start VPN"}), 500
    
    except Exception as e:
        log_message(f"Connection failed: {e}", "error")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/start', methods=['POST'])
def start_vpn():
    """Start VPN"""
    if SingBoxManager.start():
        vpn_status["connected"] = True
        vpn_status["start_time"] = datetime.now().isoformat()
        log_message("VPN started")
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Failed to start"}), 500

@app.route('/api/stop', methods=['POST'])
def stop_vpn():
    """Stop VPN"""
    if SingBoxManager.stop():
        vpn_status["connected"] = False
        vpn_status["server"] = None
        vpn_status["start_time"] = None
        log_message("VPN stopped")
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Failed to stop"}), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get VPN status"""
    # Get network stats if connected
    if vpn_status["connected"]:
        try:
            # Get interface stats
            stats = psutil.net_io_counters(pernic=True).get("singbox0", None)
            if stats:
                vpn_status["download_speed"] = stats.bytes_recv
                vpn_status["upload_speed"] = stats.bytes_sent
                vpn_status["total_traffic"] = stats.bytes_recv + stats.bytes_sent
        except:
            pass
    
    return jsonify({
        **vpn_status,
        "logs": logs[-20:]  # Last 20 logs
    })

if __name__ == '__main__':
    load_servers()
    log_message("Sing-Box VPN Manager started")
    app.run(host='0.0.0.0', port=8080, debug=False)
EOF

    chmod +x $INSTALL_DIR/backend.py
    print_success "Backend installed"
}

install_web_ui() {
    print_status "Installing web UI..."
    
    # Save the web UI HTML (from the first artifact)
    # This would normally be downloaded from a repository
    # For now, we'll create a placeholder that tells users to copy the HTML
    
    cat > $WEB_DIR/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Sing-Box VPN Manager</title>
</head>
<body>
    <h1>Please replace this file with the actual web UI from the first artifact</h1>
</body>
</html>
EOF
    
    print_warning "Remember to copy the web UI HTML to $WEB_DIR/index.html"
    print_success "Web UI directory prepared"
}

create_systemd_services() {
    print_status "Creating systemd services..."
    
    # Create Sing-Box service
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=Sing-Box Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c $INSTALL_DIR/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    # Create backend service
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=Sing-Box VPN Manager Backend
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/backend.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload
    
    # Enable services
    systemctl enable $SERVICE_NAME.service
    
    print_success "Systemd services created"
}

configure_system() {
    print_status "Configuring system..."
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.conf
    sysctl -p > /dev/null 2>&1
    
    # Configure firewall rules for TUN
    iptables -t nat -A POSTROUTING -o singbox0 -j MASQUERADE
    iptables -A FORWARD -i singbox0 -j ACCEPT
    iptables -A FORWARD -o singbox0 -j ACCEPT
    
    # Save iptables rules
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save
    elif command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4
    fi
    
    print_success "System configured"
}

start_services() {
    print_status "Starting services..."
    
    systemctl start $SERVICE_NAME
    
    # Wait for service to start
    sleep 3
    
    # Check if service is running
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_success "Services started successfully"
    else
        print_warning "Service may have failed to start. Check logs with: journalctl -u $SERVICE_NAME -n 50"
    fi
}

print_summary() {
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    
    echo
    echo "========================================="
    echo -e "${GREEN}Installation Complete!${NC}"
    echo "========================================="
    echo
    echo -e "${BLUE}Web Interface:${NC} http://$LOCAL_IP:8080"
    echo -e "${BLUE}Service Status:${NC} systemctl status $SERVICE_NAME"
    echo -e "${BLUE}View Logs:${NC} journalctl -u $SERVICE_NAME -f"
    echo
    echo -e "${YELLOW}Important:${NC}"
    echo "1. Copy the web UI HTML from the first artifact to $WEB_DIR/index.html"
    echo "2. Access the web interface to import VPN configurations"
    echo "3. The system is configured for TUN mode (system-wide VPN)"
    echo
    echo -e "${GREEN}Quick Commands:${NC}"
    echo "  Start Service: systemctl start $SERVICE_NAME"
    echo "  Stop Service:  systemctl stop $SERVICE_NAME"
    echo "  Restart:       systemctl restart $SERVICE_NAME"
    echo "  Uninstall:     $INSTALL_DIR/uninstall.sh"
    echo
}

create_uninstall_script() {
    cat > $INSTALL_DIR/uninstall.sh << 'EOF'
#!/bin/bash

echo "Uninstalling Sing-Box VPN Manager..."

# Stop services
systemctl stop singbox-vpn
systemctl stop sing-box
systemctl disable singbox-vpn
systemctl disable sing-box

# Remove service files
rm -f /etc/systemd/system/singbox-vpn.service
rm -f /etc/systemd/system/sing-box.service
systemctl daemon-reload

# Remove files
rm -rf /etc/singbox-vpn
rm -f /usr/local/bin/sing-box

echo "Uninstallation complete!"
EOF
    
    chmod +x $INSTALL_DIR/uninstall.sh
}

# Main installation flow
main() {
    echo
    echo "========================================="
    echo " Sing-Box VPN Manager Installation"
    echo "========================================="
    echo
    
    check_root
    detect_os
    
    install_dependencies
    install_singbox
    setup_python_env
    install_backend
    install_web_ui
    create_systemd_services
    configure_system
    create_uninstall_script
    start_services
    
    print_summary
}

# Run main function
main