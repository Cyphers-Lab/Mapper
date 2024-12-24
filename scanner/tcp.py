"""TCP port scanner implementation"""
import asyncio
import socket
from typing import List, Optional
from scapy.all import IP, TCP, send, sr1
from database import Database
from .base import BaseScanner
from .models import ScanConfig, ScanResult
from .evasion import ScanEvasion

class TCPScanner(BaseScanner):
    def __init__(self, config: ScanConfig = None):
        config = config or ScanConfig()
        super().__init__(config.max_concurrent_scans, config.timeout)
        self.config = config
        self.evasion = ScanEvasion() if config.use_evasion else None
        self.db = Database()

    async def scan_port(self, ip: str, port: int, hostname: str, isp: str, os: str, mac_address: str) -> Optional[ScanResult]:
        """Scan a single port on the specified IP using evasion techniques if enabled"""
        async with self.semaphore:  # Limit concurrent scans
            try:
                port_status = "closed"
                service = "Unknown"

                if self.evasion:
                    try:
                        # Get local IP for proper response matching
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect(("8.8.8.8", 80))
                        src_ip = s.getsockname()[0]
                        s.close()
                        
                        # Create and send the real probe packet
                        syn_packet = self.evasion.craft_custom_packet(ip, port, src_ip=src_ip)
                        
                        # Send final probe and wait for response
                        response = sr1(syn_packet, timeout=self.timeout, verbose=0)
                        
                        if response and response.haslayer(TCP):
                            tcp_flags = response[TCP].flags
                            if tcp_flags & 0x12:  # SYN-ACK flags
                                port_status = "open"
                                # Send RST to close connection
                                rst_packet = IP(src=src_ip, dst=ip)/TCP(sport=syn_packet[TCP].sport, 
                                    dport=port, flags='R', seq=syn_packet[TCP].seq + 1)
                                send(rst_packet, verbose=0)
                            elif tcp_flags & 0x14:  # RST-ACK flags
                                port_status = "closed"
                            else:
                                port_status = "filtered"
                        else:
                            port_status = "filtered"
                    except (socket.error, PermissionError):
                        # Fallback to regular socket if raw socket fails
                        port_status = await self._fallback_scan(ip, port)
                else:
                    # Regular scanning without evasion
                    port_status = await self._fallback_scan(ip, port)

                # Only attempt service detection if port is open
                if port_status == "open":
                    service = self.detect_service(ip, port, self.timeout)

                # Create scan result if not filtered
                if port_status != "filtered":
                    return await ScanResult.create(
                        ip=ip,
                        port=port,
                        protocol="TCP",
                        scan_status=port_status,
                        service=service,
                        os=os,
                        hostname=hostname,
                        mac_address=mac_address
                    )
                return None

            except Exception as e:
                print(f"Error scanning {ip}:{port} - {str(e)}")
                return None

    async def scan_ports(self, ip: str, ports: List[int] = None) -> List[ScanResult]:
        """Optimized port scanning"""
        if ports is None:
            ports = list(self.get_common_ports())

        # Get basic host information first
        hostname, isp, mac_address = self.get_ip_info(ip)
        os = self.detect_os(ip)

        # Process ports in larger chunks
        chunk_size = 5000
        results = []
        
        for i in range(0, len(ports), chunk_size):
            chunk = ports[i:i + chunk_size]
            # Use connection scan only first
            tasks = [self._fallback_scan(ip, port) for port in chunk]
            chunk_statuses = await asyncio.gather(*tasks)
            
            # Create scan results for all ports
            scan_tasks = []
            for port, status in zip(chunk, chunk_statuses):
                if status != "filtered":  # Skip filtered ports
                    scan_tasks.append(
                        ScanResult.create(
                            ip=ip,
                            port=port,
                            protocol="TCP",
                            scan_status=status,
                            service="Unknown",
                            os=os,
                            hostname=hostname,
                            mac_address=mac_address
                        )
                    )
            
            if scan_tasks:
                chunk_results = await asyncio.gather(*scan_tasks)
                results.extend([r for r in chunk_results if r is not None])
                
                # Batch insert results
                try:
                    print(f"Saving batch of {len(results)} results...")
                    await self.db.insert_scan_results_batch([r.to_dict() for r in results])
                    results = []  # Clear results after successful save
                except Exception as e:
                    print(f"Error saving results batch: {str(e)}")

        return results

    async def scan_multiple_ips(self, ips: List[str], ports: List[int] = None) -> None:
        """Scan multiple IPs concurrently with optional target randomization"""
        try:
            print("Initializing database for scan...")
            await self.db.init_db()
            print(f"Starting scan of {len(ips)} IPs...")
            
            # Randomize target order if evasion is enabled
            if self.evasion:
                ips = self.evasion.randomize_targets(ips)
            
            # Process IPs sequentially to avoid database contention
            for ip in ips:
                print(f"\nScanning IP: {ip}")
                try:
                    results = await self.scan_ports(ip, ports)
                    if results:
                        print(f"Found {len(results)} open ports on {ip}")
                    else:
                        print(f"No open ports found on {ip}")
                except Exception as e:
                    print(f"Error scanning {ip}: {str(e)}")
                    continue
                
        except Exception as e:
            print(f"Error during multi-IP scan: {str(e)}")
            raise
        finally:
            print("Closing database connection...")
            await self.db.close()

    async def _fallback_scan(self, ip: str, port: int) -> str:
        """Fallback to regular socket scanning when evasion fails or is disabled"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return "open"
        except asyncio.TimeoutError:
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except Exception:
            return "error"
