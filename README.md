# Mapper

A network mapping tool that performs port scanning and service detection with geolocation and vulnerability enrichment.

## Project Structure

The project has been refactored into modular components:

### Database Module
- `database/models.py`: Data models for scan results
- `database/schema.py`: Database schema definitions
- `database/connection.py`: Database connection management
- `database/operations.py`: CRUD operations
- `database/__init__.py`: Main database interface

### Scanner Module
- `scanner/base.py`: Base scanner implementation
- `scanner/models.py`: Scanner configuration and result models
- `scanner/tcp.py`: TCP port scanner
- `scanner/udp.py`: UDP port scanner
- `scanner/__init__.py`: Main scanner interface

### Utils Module
- `utils/network/ip.py`: IP address utilities
- `utils/geo/`: Geolocation services
  - `models.py`: Geolocation data models
  - `service.py`: IP geolocation service
- `utils/vulnerabilities/`: Vulnerability scanning
  - `models.py`: Vulnerability data models
  - `service.py`: CVE lookup service
- `utils/enrichment.py`: Service enrichment coordinator

## Features

- TCP and UDP port scanning
- Service banner detection
- OS fingerprinting
- Geolocation enrichment
- CVE vulnerability lookup
- Evasion techniques support
- Batch processing
- Async I/O for performance

## Usage

```python
from scanner import Scanner, ScanConfig

# Create scanner with custom config
config = ScanConfig(
    max_concurrent_scans=1000,
    timeout=0.1,
    timing_profile='normal',
    use_evasion=False,
    fast_mode=True
)
scanner = Scanner(config)

# Scan single IP
await scanner.scan_ports("192.168.1.1", ports=[80, 443], protocol="TCP")

# Scan multiple IPs
ips = ["192.168.1.1", "192.168.1.2"]
await scanner.scan_multiple_ips(ips, protocol="TCP")

# Scan both TCP and UDP
await scanner.scan_all(ips)
```

## Dependencies

- aiosqlite: Async SQLite database
- aiohttp: Async HTTP client
- scapy: Network packet manipulation
- ipwhois: IP WHOIS lookups
