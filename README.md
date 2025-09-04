# Siroos

# Sing-Box VPN Client System Documentation

## Overview

A production-ready, headless V2Ray VPN client system for Debian-based Linux devices using Sing-Box as the core engine. This system provides system-wide VPN functionality through TUN mode with a modern web interface for management.

## Features

- ✅ **Sing-Box Core**: Latest Sing-Box engine for optimal performance
- ✅ **Protocol Support**: VMess, VLESS, Trojan, Reality
- ✅ **Subscription Support**: Import configs via subscription URLs
- ✅ **System-Wide VPN**: All traffic routed through VPN using TUN mode
- ✅ **Web Interface**: Modern, responsive UI for easy management
- ✅ **Connection Testing**: Built-in latency and connectivity tests
- ✅ **Auto-Start**: Systemd integration for reliability
- ✅ **Zero Configuration**: Works out-of-the-box after installation

## System Requirements

- **OS**: Debian 11+, Ubuntu 20.04+, or Raspberry Pi OS
- **Architecture**: x86_64, ARM64, or ARMv7
- **Memory**: Minimum 512MB RAM
- **Network**: Internet connectivity
- **Privileges**: Root access required for installation

## Installation

### One-Line Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Siroos/singbox-vpn/main/install.sh | sudo bash
```

Or download and run manually:

```bash
wget https://raw.githubusercontent.com/your-repo/singbox-vpn/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

### Manual Installation

1. **Clone the repository:**
```bash
git clone https://github.com/your-repo/singbox-vpn.git
cd singbox-vpn
```

2. **Run the installation script:**
```bash
sudo ./install.sh
```

3. **Copy the web UI:**
```bash
sudo cp web/index.html /etc/singbox-vpn/web/
```

## Post-Installation Setup

### 1. Access the Web Interface

After installation, access the web interface at:
```
http://YOUR_SERVER_IP:8080
```

Replace `YOUR_SERVER_IP` with your server's IP address. You can find it using:
```bash
hostname -I
```

### 2. Initial Configuration

1. Open the web interface in your browser
2. The interface will show "No servers available"
3. Import your first VPN configuration (see below)

## Using the Web Interface

### Importing Configurations

The system supports three methods for importing VPN configurations:

#### Method 1: Subscription URL
1. Click the **URL** tab in the Import Configuration section
2. Enter your subscription URL (e.g., `https://provider.com/subscription`)
3. Click **Import from URL**
4. Multiple servers will be imported automatically

#### Method 2: Configuration Text
1. Click the **Text** tab
2. Paste your VMess/VLESS/Trojan configuration string
3. Click **Import Config**
4. The server will be added to your list

#### Method 3: Configuration File
1. Click the **File** tab
2. Select a `.json` or `.txt` file containing configurations
3. Click **Upload File**
4. Configurations will be imported

### Managing Servers

#### Testing Connections
- Click **Test** next to any server to check connectivity
- Results show latency, online status, and speed
- Tests do not affect your current connection

#### Connecting to a Server
1. Click **Connect** next to your desired server
2. The server becomes active (highlighted)
3. Click **Start VPN** to establish the connection
4. Status indicator turns green when connected

#### Deleting Servers
- Click the **×** button next to any server to remove it
- Active connections will be maintained until stopped

### Quick Actions

- **Start VPN**: Begins VPN connection with selected server
- **Stop VPN**: Disconnects and restores normal routing
- **Restart**: Quickly reconnects to current server

### Monitoring

The interface provides real-time monitoring:
- **Connection Status**: Green = Connected, Red = Disconnected
- **Active Server**: Shows currently connected server
- **Uptime**: Connection duration
- **Traffic Stats**: Download/Upload speeds and total traffic
- **System Logs**: Real-time connection logs

## Configuration Examples

### VMess Configuration
```
vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOjQ0MywiaWQiOiJ1dWlkLWhlcmUiLCJwcyI6Ik15IFNlcnZlciJ9
```

### VLESS Configuration
```
vless://uuid@example.com:443?encryption=none&security=tls&type=ws&path=/path#My%20Server
```

### Trojan Configuration
```
trojan://password@example.com:443?security=tls&type=tcp#My%20Server
```

### VLESS with Reality
```
vless://uuid@example.com:443?encryption=none&security=reality&pbk=publickey&sid=shortid#Reality%20Server
```

## System Management

### Service Commands

```bash
# Check service status
sudo systemctl status singbox-vpn

# Start the service
sudo systemctl start singbox-vpn

# Stop the service
sudo systemctl stop singbox-vpn

# Restart the service
sudo systemctl restart singbox-vpn

# View logs
sudo journalctl -u singbox-vpn -f

# Enable auto-start
sudo systemctl enable singbox-vpn

# Disable auto-start
sudo systemctl disable singbox-vpn
```

### File Locations

- **Configuration Directory**: `/etc/singbox-vpn/`
- **Server Database**: `/etc/singbox-vpn/servers.json`
- **Sing-Box Config**: `/etc/singbox-vpn/config.json`
- **Web UI**: `/etc/singbox-vpn/web/index.html`
- **Backend Script**: `/etc/singbox-vpn/backend.py`
- **Logs**: `/etc/singbox-vpn/vpn.log`

## API Reference

The backend exposes a REST API on port 8080:

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Serve web UI |
| POST | `/api/import` | Import configuration |
| GET | `/api/servers` | List all servers |
| DELETE | `/api/servers/{id}` | Delete a server |
| POST | `/api/test/{id}` | Test server connection |
| POST | `/api/connect/{id}` | Connect to server |
| POST | `/api/start` | Start VPN |
| POST | `/api/stop` | Stop VPN |
| GET | `/api/status` | Get VPN status |

### Import Configuration Request

```json
POST /api/import
{
  "type": "url|text|file",
  "data": "configuration_data"
}
```

### Status Response

```json
{
  "connected": true,
  "server": "Server Name",
  "start_time": "2025-01-01T00:00:00",
  "download_speed": 1024000,
  "upload_speed": 512000,
  "total_traffic": 10485760,
  "logs": [...]
}
```

## Troubleshooting

### VPN Won't Start

1. Check service status:
```bash
sudo systemctl status sing-box
sudo systemctl status singbox-vpn
```

2. Check logs for errors:
```bash
sudo journalctl -u singbox-vpn -n 100
```

3. Verify Sing-Box installation:
```bash
sing-box version
```

### Cannot Access Web Interface

1. Check if service is running:
```bash
sudo systemctl status singbox-vpn
```

2. Check if port 8080 is open:
```bash
sudo netstat -tlnp | grep 8080
```

3. Check firewall rules:
```bash
sudo ufw status
```

### Connection Issues

1. Test server connectivity:
   - Use the **Test** button in the web interface
   - Check server address and port

2. Verify configuration format:
   - Ensure URLs are properly formatted
   - Check for special characters in passwords

3. Check DNS resolution:
```bash
nslookup your-server.com
```

### Performance Issues

1. Check system resources:
```bash
htop
```

2. Monitor network interface:
```bash
ip link show singbox0
```

3. Check routing table:
```bash
ip route show
```

## Security Considerations

1. **Access Control**: The web interface binds to all interfaces (0.0.0.0). Consider:
   - Using a firewall to restrict access
   - Setting up nginx as a reverse proxy with authentication
   - Using SSH tunneling for remote access

2. **Configuration Security**:
   - Server configurations are stored in plaintext
   - Ensure proper file permissions (600) on sensitive files
   - Regularly rotate VPN credentials

3. **System Updates**:
   - Keep the system updated: `sudo apt update && sudo apt upgrade`
   - Monitor Sing-Box releases for security updates

## Extending the System

### Adding Custom Routes

Edit `/etc/singbox-vpn/config.json` and add custom routing rules:

```json
{
  "route": {
    "rules": [
      {
        "domain": ["example.com"],
        "outbound": "direct"
      }
    ]
  }
}
```

### Custom DNS Servers

Modify the DNS configuration in the backend:

```python
"dns": {
  "servers": [
    {
      "tag": "custom",
      "address": "1.1.1.1"
    }
  ]
}
```

### Backend Modifications

The backend is written in Python and can be extended:
- Location: `/etc/singbox-vpn/backend.py`
- Restart after changes: `sudo systemctl restart singbox-vpn`

## Uninstallation

To completely remove the system:

```bash
sudo /etc/singbox-vpn/uninstall.sh
```

This will:
- Stop and disable all services
- Remove all configuration files
- Remove Sing-Box binary
- Clean up systemd services

## Support and Contributing

### Getting Help

1. Check the documentation above
2. Review system logs
3. Search existing issues on GitHub
4. Create a new issue with:
   - System information (OS, architecture)
   - Error messages
   - Steps to reproduce

### Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test your changes
4. Submit a pull request

## License

This project is open source and available under the MIT License.

## Acknowledgments

- Sing-Box Project: https://github.com/SagerNet/sing-box
- V2Ray Community: https://www.v2ray.com
- Contributors and testers

---

**Version**: 1.0.0  
**Last Updated**: January 2025  
**Author**: Sing-Box VPN Manager Team
