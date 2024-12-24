import asyncio
import argparse
import ipaddress
import csv
import json
import yaml
import xml.etree.ElementTree as ET
import aiosqlite
from typing import List, Optional, Dict, Any
from scanner.tcp import TCPScanner
from scanner.udp import UDPScanner
from database.db import Database
from utils.scheduler import ScanScheduler

async def export_results(db_file: str, output_file: str, format: str = 'csv'):
    """Export scan results to CSV file"""
    async with aiosqlite.connect(db_file) as db:
        cursor = await db.execute("SELECT * FROM scan_results ORDER BY ip_address, port")
        rows = await cursor.fetchall()
        if not rows:
            print("No results to export")
            return

        if not rows:
            print("No results to export")
            return

        columns = [description[0] for description in cursor.description]
        
        if format == 'csv':
            with open(output_file, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(columns)
                writer.writerows(rows)
        
        elif format == 'json':
            results = []
            for row in rows:
                result = {}
                for i, col in enumerate(columns):
                    result[col] = row[i]
                results.append(result)
            
            with open(output_file, 'w') as jsonfile:
                json.dump(results, jsonfile, indent=2)
        
        elif format == 'xml':
            root = ET.Element("ScanResults")
            for row in rows:
                result = ET.SubElement(root, "Result")
                for i, col in enumerate(columns):
                    ET.SubElement(result, col).text = str(row[i])
            
            tree = ET.ElementTree(root)
            tree.write(output_file, encoding='utf-8', xml_declaration=True)
        
        print(f"Results exported to {output_file} in {format.upper()} format")

def parse_ip_ranges(ip_input: str) -> List[str]:
    """Parse IP addresses and CIDR ranges from string format (e.g., '192.168.1.1,10.0.0.0/24')"""
    ips = set()
    for part in ip_input.split(','):
        part = part.strip()
        try:
            # Check if it's a CIDR range
            if '/' in part:
                network = ipaddress.ip_network(part, strict=False)
                ips.update(str(ip) for ip in network.hosts())
            else:
                # Validate single IP
                ipaddress.ip_address(part)
                ips.add(part)
        except ValueError as e:
            print(f"Warning: Skipping invalid IP/CIDR {part}: {str(e)}")
    return sorted(list(ips))

def parse_ports(ports_str: str) -> List[int]:
    """Parse port ranges from string format (e.g., '80,443,8000-8080')"""
    ports = set()
    for part in ports_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from YAML file"""
    try:
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading config file: {str(e)}")
        return {}

async def run_scan(args) -> None:
    # Initialize scanners
    tcp_scanner = None
    udp_scanner = None
    
    try:
        # Parse IP addresses and ports
        ips = parse_ip_ranges(args.ips)
        if not ips:
            raise ValueError("No valid IP addresses or CIDR ranges provided")
            
        ports = parse_ports(args.ports) if args.ports else None
        if ports is not None and not ports:
            raise ValueError("No valid ports specified")
            
        # Load evasion settings from config if available
        config = load_config(args.config) if hasattr(args, 'config') else {}
        evasion_config = config.get('evasion', {})
        
        # Initialize scanners with proper concurrency limit and evasion settings
        max_concurrent = max(1, min(args.concurrent, 5000))
        
        # Determine evasion settings (command line args override config file)
        use_evasion = args.evasion if hasattr(args, 'evasion') else evasion_config.get('enabled', False)
        timing_profile = args.timing_profile if hasattr(args, 'timing_profile') else evasion_config.get('timing_profile', 'normal')
        
        tcp_scanner = TCPScanner(
            max_concurrent_scans=max_concurrent,
            timeout=args.timeout,
            use_evasion=use_evasion,
            timing_profile=timing_profile
        )
        
        if args.udp:
            udp_scanner = UDPScanner(max_concurrent_scans=max_concurrent, timeout=args.timeout)
        
        print(f"Starting port scan on {len(ips)} IP address(es)...")
        print(f"Scanning {'common ports' if ports is None else f'{len(ports)} specified ports'}")
        print(f"Maximum concurrent scans: {max_concurrent}")
        print(f"Protocols: {'TCP, UDP' if args.udp else 'TCP'}")
        print(f"Evasion techniques: {'Enabled' if use_evasion else 'Disabled'}")
        if use_evasion:
            print(f"Timing profile: {timing_profile}")
        print("Results will be stored in scan_results.db\n")
        
        # Run TCP scan
        await tcp_scanner.scan_multiple_ips(ips, ports)
        
        # Run UDP scan if requested
        if udp_scanner:
            await udp_scanner.scan_multiple_ips(ips, ports)
            
        print("\nScan completed successfully!")
        
        # Export results if output file specified
        if args.output:
            await export_results(
                "scan_results.db",
                args.output,
                args.format
            )
            
    except ValueError as e:
        print(f"\nConfiguration error: {str(e)}")
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"\nError during scan: {str(e)}")
    finally:
        if tcp_scanner:
            await tcp_scanner.close()
        if udp_scanner:
            await udp_scanner.close()

async def run_scheduler(args) -> None:
    """Run the scanner in scheduled mode"""
    scheduler = ScanScheduler(args.config)
    try:
        await scheduler.start()
    except KeyboardInterrupt:
        await scheduler.stop()
        print("\nScheduler stopped by user")
    except Exception as e:
        print(f"\nScheduler error: {str(e)}")

async def main():
    parser = argparse.ArgumentParser(description='Advanced Port Scanner')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run an immediate port scan')
    scan_parser.add_argument('ips', help='IP addresses to scan (comma-separated)')
    scan_parser.add_argument('-p', '--ports', help='Ports to scan (e.g., 80,443,8000-8080)')
    scan_parser.add_argument('-c', '--concurrent', type=int, default=1000,
                        help='Maximum concurrent scans (default: 1000)')
    scan_parser.add_argument('-t', '--timeout', type=float, default=1.0,
                        help='Timeout in seconds for each port scan (default: 1.0)')
    scan_parser.add_argument('-o', '--output', type=str,
                        help='Export results to file')
    scan_parser.add_argument('-f', '--format', choices=['csv', 'json', 'xml'],
                        default='csv', help='Output format (default: csv)')
    scan_parser.add_argument('-u', '--udp', action='store_true',
                        help='Enable UDP scanning')
    scan_parser.add_argument('--evasion', action='store_true',
                        help='Enable evasion techniques')
    scan_parser.add_argument('--timing-profile', choices=['paranoid', 'sneaky', 'normal', 'aggressive'],
                        default='normal', help='Scan timing profile (default: normal)')
    scan_parser.add_argument('--config', type=str, default='scan_config.yaml',
                        help='Path to configuration file')
    
    # Schedule command
    schedule_parser = subparsers.add_parser('schedule', help='Run scheduled scans')
    schedule_parser.add_argument('-c', '--config', type=str, default='scan_config.yaml',
                            help='Path to schedule configuration file')
    
    args = parser.parse_args()
        
    if not args.command:
        parser.print_help()
        return

    if args.command == 'scan':
        await run_scan(args)
    elif args.command == 'schedule':
        await run_scheduler(args)

if __name__ == "__main__":
    asyncio.run(main())
