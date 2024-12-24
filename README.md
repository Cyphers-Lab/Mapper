# Advanced Port Scanner

A feature-rich, asynchronous network port scanner with vulnerability detection, service identification, automated monitoring capabilities, and interactive network visualization.

## Features

- **Multi-Protocol Scanning**
  - TCP connect scanning
  - UDP scanning
  - Service banner grabbing
  - OS detection via TTL analysis

- **Enhanced Detection**
  - CVE vulnerability database integration
  - Service version detection
  - OS fingerprinting
  - MAC address discovery
  - GeoIP location

- **Firewall/IDS Evasion**
  - Target randomization to avoid sequential scanning patterns
  - Configurable timing profiles for stealth
  - Packet fragmentation to evade detection
  - Decoy IP generation to obscure source
  - Custom packet crafting to mimic legitimate traffic
  - Multiple timing profiles (paranoid, sneaky, normal, aggressive)

- **Automated Monitoring**
  - Scheduled scanning
  - Configurable scan intervals
  - Email notifications
  - Webhook integration
  - Customizable alert conditions

- **Interactive Visualization**
  - Network topology mapping
  - Geographic mapping of discovered hosts
  - Real-time scan visualization
  - Interactive node exploration
  - Customizable visualization layouts
  - Drill-down capability for detailed host information
  - Export visualizations as images

- **Web Interface**
  - Dashboard for scan management
  - Real-time scan progress monitoring
  - Historical scan results viewer
  - Configuration management
  - Interactive network maps
  - Responsive design for mobile access

- **Rich Output Formats**
  - CSV export
  - JSON export
  - XML export
  - SQLite database storage
  - Visual topology exports

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Cyphers-Lab/Mapper.git
cd port_scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
npm install
```

## Usage

The scanner supports three modes of operation: immediate scanning, scheduled monitoring, and web interface.

### Web Interface

Start the web interface:

```bash
npm start
```

Access the dashboard at `http://localhost:3000`. The web interface provides:
- Scan configuration and execution
- Real-time network topology visualization
- Geographic mapping of discovered hosts
- Historical scan results
- Configuration management
- Interactive network exploration

### Immediate Scanning

Run an immediate scan using the `scan` command:

```bash
# Basic TCP scan
python main.py scan 192.168.1.1

# Scan with evasion techniques
python main.py scan 192.168.1.1 --evasion

# Scan with specific timing profile 
python main.py scan 192.168.1.1 --evasion --timing-profile sneaky

# Scan multiple IPs and CIDR ranges
python main.py scan "192.168.1.1,10.0.0.0/24"

# Specify ports to scan
python main.py scan 192.168.1.1 -p "80,443,8000-8080"

# Enable UDP scanning
python main.py scan 192.168.1.1 -u

# Export results
python main.py scan 192.168.1.1 -o results.json -f json
```

Options:
- `-p, --ports`: Ports to scan (e.g., "80,443,8000-8080")
- `-c, --concurrent`: Maximum concurrent scans (default: 1000)
- `-t, --timeout`: Timeout in seconds for each port scan (default: 1.0)
- `-o, --output`: Export results to file
- `-f, --format`: Output format (csv, json, xml, or topology)
- `-u, --udp`: Enable UDP scanning
- `--evasion`: Enable firewall/IDS evasion techniques
- `--timing-profile`: Select timing profile (paranoid, sneaky, normal, aggressive)
- `--visualize`: Open results in network topology viewer

### Scheduled Monitoring

Run the scanner in scheduled monitoring mode:

```bash
python main.py schedule -c scan_config.yaml
```

The scheduler uses a YAML configuration file (`scan_config.yaml`) to define:
- Scan intervals and timing
- Target IPs and ports
- Notification settings
- Alert conditions
- Evasion settings
- Visualization preferences

Example configuration:
```yaml
schedule:
  interval: daily  # daily, hourly, or cron expression
  time: "00:00"   # For daily scans

evasion:
  enabled: true   # Enable/disable evasion techniques
  timing_profile: "normal"  # paranoid, sneaky, normal, aggressive
  decoy_count: 3  # Number of decoy IPs to use
  fragment_size: 380  # Size of packet fragments
  randomize_targets: true  # Randomize scan order
  min_delay: 0.1  # Minimum delay between scans (seconds)
  max_delay: 1.0  # Maximum delay between scans (seconds)

visualization:
  enabled: true
  layout: "force"  # force, hierarchical, circular
  save_topology: true
  geo_mapping: true
  node_colors:
    vulnerable: "red"
    secure: "green"
    unknown: "gray"

targets:
  - ip: 192.168.1.1
    ports: [80, 443, 8080]
  - ip: 10.0.0.0/24
    ports: [22, 80, 443]

notifications:
  email:
    enabled: true
    smtp_server: smtp.gmail.com
    smtp_port: 587
    username: your-email@gmail.com
    password: your-app-password
    from_address: your-email@gmail.com
    to_addresses:
      - admin@example.com

alert_conditions:
  new_ports: true
  closed_ports: true
  service_changes: true
  critical_vulnerabilities: true
```

### Timing Profiles

The scanner includes four predefined timing profiles for evasion:

1. **Paranoid**
   - Maximum stealth
   - 5-15 second delays between scans
   - Single concurrent scan
   - Ideal for avoiding any detection

2. **Sneaky**
   - High stealth
   - 1-5 second delays
   - Low concurrency (3 max)
   - Good for careful scanning

3. **Normal**
   - Balanced approach
   - 0.1-1.0 second delays
   - Moderate concurrency (10 max)
   - Default profile

4. **Aggressive**
   - Faster scanning
   - 0.01-0.1 second delays
   - High concurrency (50 max)
   - May trigger IDS alerts

## Output Formats

### CSV Format
```csv
id,ip_address,port,protocol,status,service,os,hostname,isp,mac_address,geo_location,cve_data,timestamp
1,192.168.1.1,80,TCP,open,Apache/2.4.41,Linux,host.example.com,Example ISP,00:11:22:33:44:55,"New York, USA",CVE-2021-1234,2024-01-01 00:00:00
```

### JSON Format
```json
{
  "scan_results": [
    {
      "ip_address": "192.168.1.1",
      "port": 80,
      "protocol": "TCP",
      "status": "open",
      "service": "Apache/2.4.41",
      "os": "Linux",
      "hostname": "host.example.com",
      "isp": "Example ISP",
      "mac_address": "00:11:22:33:44:55",
      "geo_location": "New York, USA",
      "cve_data": [
        {
          "id": "CVE-2021-1234",
          "score": 9.8,
          "description": "..."
        }
      ]
    }
  ]
}
```

### XML Format
```xml
<?xml version="1.0" encoding="UTF-8"?>
<ScanResults>
  <Result>
    <ip_address>192.168.1.1</ip_address>
    <port>80</port>
    <protocol>TCP</protocol>
    <status>open</status>
    <service>Apache/2.4.41</service>
    <os>Linux</os>
    <hostname>host.example.com</hostname>
    <isp>Example ISP</isp>
    <mac_address>00:11:22:33:44:55</mac_address>
    <geo_location>New York, USA</geo_location>
    <cve_data>[...]</cve_data>
  </Result>
</ScanResults>
```

## Security Notes

1. Always ensure you have permission to scan the target systems
2. Be aware that port scanning may be logged by target systems
3. Some networks may block or rate-limit scanning activities
4. UDP scanning may be less reliable due to protocol characteristics
5. Even with evasion techniques, scanning may still be detected
6. Use timing profiles appropriate for your target and requirements
7. Consider legal implications before using evasion techniques

## License

This project is licensed under the MIT License - see the LICENSE file for details.
