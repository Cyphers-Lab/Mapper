"""Test script for scanning with various evasion techniques"""
import asyncio
import signal
from contextlib import asynccontextmanager
from scanner import Scanner, ScanConfig

# Different timing profiles for testing evasion effectiveness
TIMING_PROFILES = [
    'paranoid',   # Very slow, maximum stealth
    'sneaky',     # Slow scan for IDS evasion
    'polite',     # Slows down to consume less bandwidth
    'normal',     # Default timing
    'aggressive', # Faster scanning, assumes good network
    'insane'      # Assumes perfect network for max speed
]

async def cleanup(scanner):
    """Cleanup resources"""
    if hasattr(scanner, 'tcp_scanner'):
        await scanner.tcp_scanner.db.close()
    if hasattr(scanner, 'udp_scanner'):
        await scanner.udp_scanner.db.close()

@asynccontextmanager
async def get_scanner(timing_profile: str, use_evasion: bool = True):
    """Create and cleanup scanner with specific evasion settings"""
    config = ScanConfig(
        max_concurrent_scans=50,
        timeout=2.0,  # Higher timeout for evasion techniques
        timing_profile=timing_profile,
        use_evasion=use_evasion,
        fast_mode=False  # Disable fast mode for proper evasion testing
    )
    scanner = Scanner(config)
    try:
        yield scanner
    finally:
        await cleanup(scanner)

async def test_timing_profile(ip: str, ports: list, timing_profile: str):
    """Test scanning with a specific timing profile"""
    print(f"\nTesting {timing_profile} timing profile...")
    
    async with get_scanner(timing_profile) as scanner:
        print(f"Scanning {ip} with ports {ports}")
        results = await scanner.scan_ports(ip, ports, protocol="TCP")
        if results:
            print(f"\nResults for {timing_profile} profile:")
            for result in results:
                print(f"Port {result.port}: {result.scan_status} ({result.service})")
        return results

async def test_fragmentation(scanner, ip: str, ports: list):
    """Test scanning with packet fragmentation"""
    print(f"\nTesting fragmented packet scanning...")
    # Enable fragmentation in scanner configuration
    scanner.tcp_scanner.use_fragmentation = True
    
    results = await scanner.scan_ports(ip, ports, protocol="TCP")
    if results:
        print("\nResults with packet fragmentation:")
        for result in results:
            print(f"Port {result.port}: {result.scan_status} ({result.service})")
    
    # Reset fragmentation setting
    scanner.tcp_scanner.use_fragmentation = False
    return results

async def test_decoy_scanning(scanner, ip: str, ports: list):
    """Test scanning with decoy addresses"""
    print(f"\nTesting decoy scanning...")
    # Enable decoy scanning in scanner configuration
    scanner.tcp_scanner.use_decoys = True
    
    results = await scanner.scan_ports(ip, ports, protocol="TCP")
    if results:
        print("\nResults with decoy scanning:")
        for result in results:
            print(f"Port {result.port}: {result.scan_status} ({result.service})")
    
    # Reset decoy setting
    scanner.tcp_scanner.use_decoys = False
    return results

async def main():
    # Handle keyboard interrupt gracefully
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, lambda: loop.stop())
    
    try:
        ip = "127.0.0.1"  # Test on localhost
        test_ports = [22, 80, 443, 3306]  # Common ports for testing
        
        # Test different timing profiles
        for profile in TIMING_PROFILES:
            await test_timing_profile(ip, test_ports, profile)
        
        # Test additional evasion techniques with normal timing
        async with get_scanner('normal', use_evasion=True) as scanner:
            # Test fragmentation
            await test_fragmentation(scanner, ip, test_ports)
            
            # Test decoy scanning
            await test_decoy_scanning(scanner, ip, test_ports)
            
    except asyncio.CancelledError:
        print("\nScan cancelled by user")
    except Exception as e:
        print(f"\nError during scan: {str(e)}")
    finally:
        print("\nEvasion testing complete")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
