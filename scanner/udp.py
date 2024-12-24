"""UDP port scanner implementation"""
import asyncio
import socket
from typing import List, Optional
from scapy.all import IP, UDP, send, sr1, ICMP
from database import Database
from .base import BaseScanner
from .models import ScanConfig, ScanResult
from .evasion import ScanEvasion

class UDPScanner(BaseScanner):
    def __init__(self, config: ScanConfig = None):
        config = config or ScanConfig()
        super().__init__(config.max_concurrent_scans, config.timeout)
        self.config = config
        self.evasion = ScanEvasion() if config.use_evasion else None
        self.db = Database()

    async def scan_port(self, ip: str, port: int, hostname: str, isp: str, os: str, mac_address: str) -> Optional[ScanResult]:
        """Scan a single UDP port"""
        async with self.semaphore:
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

                        # Create and send UDP probe packet
                        udp_packet = self.evasion.craft_custom_packet(
                            ip, port, src_ip=src_ip, protocol="UDP"
                        )
                        
                        # Send packet and wait for response
                        response = sr1(udp_packet, timeout=self.timeout, verbose=0)
                        
                        if response is None:
                            # No response could mean open or filtered
                            port_status = "open|filtered"
                        elif response.haslayer(ICMP):
                            # ICMP port unreachable means closed
                            if response[ICMP].type == 3 and response[ICMP].code == 3:
                                port_status = "closed"
                            else:
                                port_status = "filtered"
                        else:
                            # Any response is good
                            port_status = "open"
                            
                    except (socket.error, PermissionError):
                        port_status = await self._fallback_scan(ip, port)
                else:
                    port_status = await self._fallback_scan(ip, port)

                # Only attempt service detection if port might be open
                if port_status in ["open", "open|filtered"]:
                    service = self.detect_service(ip, port, self.timeout)

                # Create scan result if not filtered
                if port_status != "filtered":
                    return await ScanResult.create(
                        ip=ip,
                        port=port,
                        protocol="UDP",
                        scan_status=port_status,
                        service=service,
                        os=os,
                        hostname=hostname,
                        mac_address=mac_address
                    )
                return None

            except Exception as e:
                print(f"Error scanning UDP {ip}:{port} - {str(e)}")
                return None

    async def scan_ports(self, ip: str, ports: List[int] = None) -> List[ScanResult]:
        """Scan multiple UDP ports"""
        if ports is None:
            ports = list(self.get_common_ports())

        # Get basic host information first
        hostname, isp, mac_address = self.get_ip_info(ip)
        os = self.detect_os(ip)

        # Process ports in chunks
        chunk_size = 1000  # Smaller chunks for UDP
        results = []
        
        for i in range(0, len(ports), chunk_size):
            chunk = ports[i:i + chunk_size]
            scan_tasks = []
            
            for port in chunk:
                scan_tasks.append(
                    self.scan_port(ip, port, hostname, isp, os, mac_address)
                )
            
            if scan_tasks:
                chunk_results = await asyncio.gather(*scan_tasks)
                results.extend([r for r in chunk_results if r is not None])
                
                # Batch insert results
                try:
                    print(f"Saving batch of {len(results)} UDP results...")
                    await self.db.insert_scan_results_batch([r.to_dict() for r in results])
                    results = []  # Clear results after successful save
                except Exception as e:
                    print(f"Error saving UDP results batch: {str(e)}")

        return results

    async def scan_multiple_ips(self, ips: List[str], ports: List[int] = None) -> None:
        """Scan multiple IPs for UDP ports"""
        try:
            print("Initializing database for UDP scan...")
            await self.db.init_db()
            print(f"Starting UDP scan of {len(ips)} IPs...")
            
            # Randomize target order if evasion is enabled
            if self.evasion:
                ips = self.evasion.randomize_targets(ips)
            
            # Process IPs sequentially
            for ip in ips:
                print(f"\nScanning UDP ports on IP: {ip}")
                try:
                    results = await self.scan_ports(ip, ports)
                    if results:
                        print(f"Found {len(results)} open/filtered UDP ports on {ip}")
                    else:
                        print(f"No open UDP ports found on {ip}")
                except Exception as e:
                    print(f"Error scanning UDP ports on {ip}: {str(e)}")
                    continue
                
        except Exception as e:
            print(f"Error during multi-IP UDP scan: {str(e)}")
            raise
        finally:
            print("Closing database connection...")
            await self.db.close()

    async def _fallback_scan(self, ip: str, port: int) -> str:
        """Fallback UDP scanning using basic socket"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP datagram
            sock.sendto(b"", (ip, port))
            
            # Wait for response
            try:
                sock.recvfrom(1024)
                return "open"
            except socket.timeout:
                return "open|filtered"
            except ConnectionRefusedError:
                return "closed"
                
        except Exception:
            return "error"
        finally:
            if sock:
                sock.close()
