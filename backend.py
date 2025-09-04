#!/usr/bin/env python3
"""
Sing-Box VPN Manager Backend - Complete No-CORS Version
Works without flask-cors by implementing CORS manually
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
import signal
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from flask import Flask, request, jsonify, send_from_directory, make_response

app = Flask(__name__)

# Manual CORS implementation
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.after_request
def after_request(response):
    return add_cors_headers(response)

# Configuration paths
BASE_DIR = Path("/etc/singbox-vpn")
CONFIG_DIR = BASE_DIR / "configs"
SINGBOX_CONFIG = BASE_DIR / "config.json"
DB_FILE = BASE_DIR / "servers.json"
LOG_FILE = BASE_DIR / "vpn.log"
WEB_DIR = BASE_DIR / "web"
PID_FILE = BASE_DIR / "sing-box.pid"

# Ensure directories exist
BASE_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_DIR.mkdir(exist_ok=True)
WEB_DIR.mkdir(exist_ok=True)

# Global state
current_config = None
singbox_process = None
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
traffic_monitor_thread = None
last_traffic_stats = {"bytes_sent": 0, "bytes_recv": 0, "time": time.time()}

class V2RayParser:
    """Parse V2Ray/VMess/VLESS/Trojan/Reality configs"""
    
    @staticmethod
    def parse_vmess(url: str) -> Dict:
        """Parse VMess URL"""
        try:
            # Remove vmess:// prefix and decode
            data = base64.b64decode(url.replace("vmess://", "") + "==").decode()
            config = json.loads(data)
            
            outbound = {
                "type": "vmess",
                "tag": config.get("ps", "VMess Server"),
                "server": config.get("add"),
                "server_port": int(config.get("port", 443)),
                "uuid": config.get("id"),
                "security": config.get("scy", "auto"),
                "alter_id": int(config.get("aid", 0))
            }
            
            # Add transport settings
            net_type = config.get("net", "tcp")
            if net_type == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": config.get("path", "/"),
                    "headers": {
                        "Host": config.get("host", "")
                    }
                }
            elif net_type == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": config.get("path", "")
                }
            
            # Add TLS if enabled
            if config.get("tls") == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": config.get("sni", config.get("host", config.get("add"))),
                    "insecure": True
                }
            
            return outbound
        except Exception as e:
            raise ValueError(f"Invalid VMess config: {e}")
    
    @staticmethod
    def parse_vless(url: str) -> Dict:
        """Parse VLESS URL"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            outbound = {
                "type": "vless",
                "tag": params.get("remarks", [parsed.fragment or "VLESS Server"])[0],
                "server": parsed.hostname,
                "server_port": parsed.port or 443,
                "uuid": parsed.username
            }
            
            # Add flow if present
            flow = params.get("flow", [""])[0]
            if flow:
                outbound["flow"] = flow
            
            # Transport settings
            transport_type = params.get("type", ["tcp"])[0]
            if transport_type == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": params.get("path", ["/"])[0],
                    "headers": {
                        "Host": params.get("host", [""])[0]
                    }
                }
            elif transport_type == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": params.get("serviceName", [""])[0]
                }
            
            # Security settings
            security = params.get("security", ["none"])[0]
            if security == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": params.get("sni", [parsed.hostname])[0],
                    "insecure": True
                }
            elif security == "reality":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": params.get("sni", [""])[0],
                    "reality": {
                        "enabled": True,
                        "public_key": params.get("pbk", [""])[0],
                        "short_id": params.get("sid", [""])[0]
                    }
                }
            
            return outbound
        except Exception as e:
            raise ValueError(f"Invalid VLESS config: {e}")
    
    @staticmethod
    def parse_trojan(url: str) -> Dict:
        """Parse Trojan URL"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            outbound = {
                "type": "trojan",
                "tag": params.get("remarks", [parsed.fragment or "Trojan Server"])[0],
                "server": parsed.hostname,
                "server_port": parsed.port or 443,
                "password": parsed.username
            }
            
            # Transport settings
            transport_type = params.get("type", ["tcp"])[0]
            if transport_type == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": params.get("path", ["/"])[0],
                    "headers": {
                        "Host": params.get("host", [""])[0]
                    }
                }
            
            # TLS is always enabled for Trojan
            outbound["tls"] = {
                "enabled": True,
                "server_name": params.get("sni", [parsed.hostname])[0],
                "insecure": True
            }
            
            return outbound
        except Exception as e:
            raise ValueError(f"Invalid Trojan config: {e}")
    
    @staticmethod
    def parse_config(url: str) -> Dict:
        """Auto-detect and parse config"""
        url = url.strip()
        if url.startswith("vmess://"):
            return V2RayParser.parse_vmess(url)
        elif url.startswith("vless://"):
            return V2RayParser.parse_vless(url)
        elif url.startswith("trojan://"):
            return V2RayParser.parse_trojan(url)
        else:
            raise ValueError(f"Unsupported protocol: {url.split('://')[0]}")

class SingBoxManager:
    """Manage Sing-Box core with proper routing"""
    
    @staticmethod
    def generate_config(outbound: Dict) -> Dict:
        """Generate Sing-Box config with proper TUN routing"""
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
                        "tag": "cloudflare", 
                        "address": "https://1.1.1.1/dns-query"
                    },
                    {
                        "tag": "local",
                        "address": "8.8.8.8",
                        "detour": "direct"
                    }
                ],
                "rules": [
                    {
                        "outbound": "any",
                        "server": "google"
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
                    "auto_route": True,
                    "strict_route": False,
                    "stack": "system",
                    "sniff": True,
                    "sniff_override_destination": True
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
                        "ip_cidr": ["127.0.0.1/8", "::1/128", "192.168.0.0/16", "10.0.0.0/8"],
                        "outbound": "direct"
                    }
                ],
                "final": outbound["tag"],
                "auto_detect_interface": True
            }
        }
        
        return config
    
    @staticmethod
    def setup_routing():
        """Setup proper IP routing and firewall rules"""
        commands = [
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "tun0", "-j", "MASQUERADE"],
            ["iptables", "-A", "FORWARD", "-i", "tun0", "-j", "ACCEPT"],
            ["iptables", "-A", "FORWARD", "-o", "tun0", "-j", "ACCEPT"]
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd, check=False, capture_output=True)
            except Exception as e:
                log_message(f"Failed to execute {' '.join(cmd)}: {e}", "warning")
    
    @staticmethod
    def start():
        """Start Sing-Box with direct process management"""
        global singbox_process, vpn_status
        
        try:
            # Stop existing instance
            SingBoxManager.stop()
            
            # Setup routing
            SingBoxManager.setup_routing()
            
            # Start Sing-Box process directly
            cmd = ["/usr/local/bin/sing-box", "run", "-c", str(SINGBOX_CONFIG)]
            singbox_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Save PID
            with open(PID_FILE, 'w') as f:
                f.write(str(singbox_process.pid))
            
            # Wait a moment for process to start
            time.sleep(3)
            
            # Check if process is running
            if singbox_process.poll() is None:
                vpn_status["connected"] = True
                vpn_status["start_time"] = datetime.now().isoformat()
                
                # Start traffic monitoring
                start_traffic_monitor()
                
                log_message("Sing-Box started successfully")
                return True
            else:
                stderr = singbox_process.stderr.read() if singbox_process.stderr else ""
                log_message(f"Sing-Box failed to start: {stderr}", "error")
                return False
                
        except Exception as e:
            log_message(f"Failed to start Sing-Box: {e}", "error")
            return False
    
    @staticmethod
    def stop():
        """Stop Sing-Box process"""
        global singbox_process, vpn_status, traffic_monitor_thread
        
        try:
            # Stop traffic monitor
            if traffic_monitor_thread:
                traffic_monitor_thread = None
            
            # Stop process by PID file
            if PID_FILE.exists():
                with open(PID_FILE, 'r') as f:
                    pid = int(f.read().strip())
                try:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(1)
                except ProcessLookupError:
                    pass
                PID_FILE.unlink()
            
            # Stop subprocess if exists
            if singbox_process:
                singbox_process.terminate()
                time.sleep(1)
                if singbox_process.poll() is None:
                    singbox_process.kill()
                singbox_process = None
            
            # Kill any remaining sing-box processes
            subprocess.run(["pkill", "-f", "sing-box"], check=False)
            
            vpn_status["connected"] = False
            vpn_status["server"] = None
            vpn_status["start_time"] = None
            
            log_message("Sing-Box stopped")
            return True
            
        except Exception as e:
            log_message(f"Error stopping Sing-Box: {e}", "warning")
            return False

def monitor_traffic():
    """Monitor network traffic in background"""
    global last_traffic_stats, vpn_status
    
    while traffic_monitor_thread:
        try:
            # Check multiple possible interface names
            interfaces = ["tun0", "singbox0", "utun"]
            stats = None
            
            for iface in interfaces:
                iface_stats = psutil.net_io_counters(pernic=True)
                if iface in iface_stats:
                    stats = iface_stats[iface]
                    break
            
            if stats:
                current_time = time.time()
                time_diff = current_time - last_traffic_stats["time"]
                
                if time_diff > 0:
                    # Calculate speeds
                    download_speed = (stats.bytes_recv - last_traffic_stats["bytes_recv"]) / time_diff
                    upload_speed = (stats.bytes_sent - last_traffic_stats["bytes_sent"]) / time_diff
                    
                    # Update status
                    vpn_status["download_speed"] = max(0, int(download_speed))
                    vpn_status["upload_speed"] = max(0, int(upload_speed))
                    vpn_status["total_traffic"] = stats.bytes_recv + stats.bytes_sent
                    
                    # Save current stats
                    last_traffic_stats = {
                        "bytes_recv": stats.bytes_recv,
                        "bytes_sent": stats.bytes_sent,
                        "time": current_time
                    }
        except Exception as e:
            pass
        
        time.sleep(1)

def start_traffic_monitor():
    """Start traffic monitoring thread"""
    global traffic_monitor_thread
    
    if not traffic_monitor_thread:
        traffic_monitor_thread = threading.Thread(target=monitor_traffic, daemon=True)
        traffic_monitor_thread.start()

def log_message(message: str, level: str = "info"):
    """Add log message"""
    global logs
    entry = {
        "time": datetime.now().isoformat(),
        "level": level,
        "message": message
    }
    logs.append(entry)
    
    if len(logs) > 100:
        logs = logs[-100:]
    
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{entry['time']} [{level.upper()}] {message}\n")
    except:
        pass

def load_servers():
    """Load servers from database"""
    global servers_db
    if DB_FILE.exists():
        try:
            with open(DB_FILE, "r") as f:
                servers_db = json.load(f)
        except:
            servers_db = []
    return servers_db

def save_servers():
    """Save servers to database"""
    try:
        with open(DB_FILE, "w") as f:
            json.dump(servers_db, f, indent=2)
    except Exception as e:
        log_message(f"Failed to save servers: {e}", "error")

def import_subscription(url: str) -> List[Dict]:
    """Import configs from subscription URL"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, timeout=10, headers=headers)
        content = response.text
        
        # Try base64 decode
        try:
            content = base64.b64decode(content + "==").decode()
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
                    log_message(f"Failed to parse line: {e}", "warning")
        
        return configs
    except Exception as e:
        raise ValueError(f"Failed to import subscription: {e}")

def test_server_connection(server: Dict) -> Dict:
    """Test server connection"""
    try:
        import socket
        start_time = time.time()
        
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
                config = json.loads(import_data)
                if isinstance(config, dict):
                    configs = [config]
                elif isinstance(config, list):
                    configs = config
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
    if result["alive"]:
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
            vpn_status["server"] = server["name"]
            
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
    if not current_config:
        # Try to use the active server from database
        active_server = next((s for s in servers_db if s.get("active")), None)
        if not active_server:
            return jsonify({"success": False, "error": "No server selected"}), 400
        
        # Generate config for active server
        config = SingBoxManager.generate_config(active_server["config"])
        with open(SINGBOX_CONFIG, "w") as f:
            json.dump(config, f, indent=2)
        
        current_config = active_server["id"]
        vpn_status["server"] = active_server["name"]
    
    if SingBoxManager.start():
        log_message("VPN started")
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Failed to start"}), 500

@app.route('/api/stop', methods=['POST'])
def stop_vpn():
    """Stop VPN"""
    if SingBoxManager.stop():
        log_message("VPN stopped")
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Failed to stop"}), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get VPN status"""
    return jsonify({
        **vpn_status,
        "logs": logs[-20:]  # Last 20 logs
    })

# Handle OPTIONS requests for CORS
@app.route('/api/<path:path>', methods=['OPTIONS'])
def handle_api_options(path):
    response = make_response()
    return add_cors_headers(response)

if __name__ == '__main__':
    load_servers()
    log_message("Sing-Box VPN Manager started (No-CORS version)")
    
    # Check for running VPN on startup
    if PID_FILE.exists():
        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            # Check if process is running
            os.kill(pid, 0)
            vpn_status["connected"] = True
            start_traffic_monitor()
            log_message("Found existing VPN connection")
        except:
            PID_FILE.unlink()
    
    app.run(host='0.0.0.0', port=8080, debug=False)
