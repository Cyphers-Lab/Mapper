"""Test script for scanning IP ranges"""
import asyncio
import signal
import ipaddress
from contextlib import asynccontextmanager
from scanner import Scanner, ScanConfig

async def cleanup(scanner):
    """Cleanup resources"""
    if hasattr(scanner, 'tcp_scanner'):
        await scanner.tcp_scanner.db.close()
    if hasattr(scanner, 'udp_scanner'):
        await scanner.udp_scanner.db.close()

@asynccontextmanager
async def get_scanner():
    """Create and cleanup scanner"""
    config = ScanConfig(
        max_concurrent_scans=50,    # Lower for subnet scanning
        timeout=1.0,                # Higher timeout for network ranges
        timing_profile='normal',
        use_evasion=False,
        fast_mode=True
    )
    scanner = Scanner(config)
    try:
        yield scanner
    finally:
        await cleanup(scanner)

async def scan_subnet(scanner, subnet: str, ports: list, protocol: str):
    """Scan an entire subnet range"""
    network = ipaddress.ip_network(subnet)
    print(f"\nScanning subnet {subnet} for {protocol} ports {ports}")
    
    for ip in network.hosts():
        ip_str = str(ip)
        print(f"\nScanning {ip_str}...")
        results = await scanner.scan_ports(ip_str, ports, protocol=protocol)
        if results:
            print(f"Results for {ip_str}:")
            for result in results:
                print(f"Port {result.port}: {result.scan_status} ({result.service})")

async def main():
    # Handle keyboard interrupt gracefully
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, lambda: loop.stop())
    
    try:
        async with get_scanner() as scanner:
            # Test with local subnet - adjust as needed
            subnet = "192.168.1.0/24"  # Example subnet
            common_ports = [22, 80, 443, 3306, 5432]  # SSH, HTTP, HTTPS, MySQL, PostgreSQL
            
            # Scan subnet
            await scan_subnet(scanner, subnet, common_ports, "TCP")
            
    except asyncio.CancelledError:
        print("\nScan cancelled by user")
    except Exception as e:
        print(f"\nError during scan: {str(e)}")
    finally:
        print("\nSubnet scan complete")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
