"""Test script for scanning specific service ports"""
import asyncio
import signal
from contextlib import asynccontextmanager
from scanner import Scanner, ScanConfig

# Common service ports
DATABASE_PORTS = {
    'MySQL': [3306],
    'PostgreSQL': [5432],
    'MongoDB': [27017, 27018, 27019],
    'Redis': [6379],
    'MS SQL': [1433, 1434],
    'Oracle': [1521, 1522, 1525]
}

WEB_PORTS = {
    'HTTP': [80, 8080, 8000, 8081],
    'HTTPS': [443, 8443],
    'Tomcat': [8005, 8009, 8080],
    'Django': [8000],
    'Node': [3000, 3001]
}

MAIL_PORTS = {
    'SMTP': [25, 465, 587],
    'POP3': [110, 995],
    'IMAP': [143, 993]
}

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
        max_concurrent_scans=100,
        timeout=1.0,
        timing_profile='normal',
        use_evasion=False,
        fast_mode=True
    )
    scanner = Scanner(config)
    try:
        yield scanner
    finally:
        await cleanup(scanner)

async def scan_service_ports(scanner, ip: str, service_type: str, service_ports: dict):
    """Scan ports for specific services"""
    print(f"\nScanning {service_type} services on {ip}...")
    
    for service, ports in service_ports.items():
        print(f"\nTesting {service} ports: {ports}")
        results = await scanner.scan_ports(ip, ports, protocol="TCP")
        if results:
            print(f"\nResults for {service}:")
            for result in results:
                print(f"Port {result.port}: {result.scan_status} ({result.service})")

async def main():
    # Handle keyboard interrupt gracefully
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, lambda: loop.stop())
    
    try:
        async with get_scanner() as scanner:
            ip = "127.0.0.1"  # Test on localhost
            
            # Test database ports
            await scan_service_ports(scanner, ip, "Database", DATABASE_PORTS)
            
            # Test web server ports
            await scan_service_ports(scanner, ip, "Web Server", WEB_PORTS)
            
            # Test mail server ports
            await scan_service_ports(scanner, ip, "Mail Server", MAIL_PORTS)
            
    except asyncio.CancelledError:
        print("\nScan cancelled by user")
    except Exception as e:
        print(f"\nError during scan: {str(e)}")
    finally:
        print("\nService scan complete")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
