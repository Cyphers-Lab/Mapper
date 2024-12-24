"""Test script for the refactored scanner"""
import asyncio
import signal
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
        max_concurrent_scans=100,  # Lower for testing
        timeout=0.5,              # Higher for reliable results
        timing_profile='normal',
        use_evasion=False,
        fast_mode=True
    )
    scanner = Scanner(config)
    try:
        yield scanner
    finally:
        await cleanup(scanner)

async def scan_ports(scanner, ip: str, ports: list, protocol: str):
    """Perform port scan and print results"""
    print(f"Testing {protocol} scan on {ip}...")
    results = await scanner.scan_ports(ip, ports, protocol=protocol)
    if results:
        print(f"\n{protocol} Results:")
        for result in results:
            print(f"Port {result.port}: {result.scan_status} ({result.service})")
    return results

async def main():
    # Handle keyboard interrupt gracefully
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, lambda: loop.stop())
    
    try:
        async with get_scanner() as scanner:
            ip = "127.0.0.1"
            test_ports = [80, 443, 3000, 8080]  # Common web ports
            
            # Run scans
            await scan_ports(scanner, ip, test_ports, "TCP")
            await scan_ports(scanner, ip, test_ports, "UDP")
            
    except asyncio.CancelledError:
        print("\nScan cancelled by user")
    except Exception as e:
        print(f"\nError during scan: {str(e)}")
    finally:
        print("\nScan complete")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
