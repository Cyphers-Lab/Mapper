import asyncio
import socket
from typing import List, Set, Tuple, Optional
from scapy.all import sr1, IP, ICMP, ARP, Ether, srp, send, TCP
from ipwhois import IPWhois
from database.db import Database
from utils.enrichment import ServiceEnrichment
from .evasion import ScanEvasion

class TCPScanner:
    def __init__(self, max_concurrent_scans: int = 1000, timeout: float = 1.0, 
                 timing_profile: str = 'normal', use_evasion: bool = True):
        self.enrichment = ServiceEnrichment()
        self.evasion = ScanEvasion() if use_evasion else None
        
        # Get timing profile if evasion is enabled
        if use_evasion:
            timing = self.evasion.get_scan_timing_profile(timing_profile)
            self.timeout = timing['timeout']
            self.max_concurrent_scans = timing['max_parallel']
            self.min_delay = timing['min_delay']
            self.max_delay = timing['max_delay']
            self.max_retries = timing['max_retries']
        else:
            self.timeout = timeout
            self.max_concurrent_scans = max_concurrent_scans
            self.min_delay = 0
            self.max_delay = 0
            self.max_retries = 1
            
        self.semaphore = asyncio.Semaphore(self.max_concurrent_scans)
        self.db = Database()

    @staticmethod
    def detect_service(ip: str, port: int, timeout: float) -> str:
        """Attempt to grab service banner"""
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                # Try HTTP first
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode(errors='ignore').strip()
                if banner:
                    return banner.split("\n")[0][:100]  # Truncate long banners
                return "Unknown"
        except Exception:
            return "Unknown"

    @staticmethod
    def detect_os(ip: str) -> str:
        """Perform lightweight OS detection using TTL values"""
        try:
            response = sr1(IP(dst=ip) / ICMP(), timeout=2, verbose=0)
            if response and response.ttl:
                ttl = response.ttl
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                else:
                    return "Network Device"
            return "Unknown"
        except Exception:
            return "Unknown"

    @staticmethod
    def get_mac_address(ip: str) -> str:
        """Get MAC address using ARP"""
        try:
            # Create ARP request packet
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            # Send packet and get response
            result = srp(arp_request, timeout=2, verbose=False)[0]
            # Extract MAC from response if available
            return result[0][1].hwsrc if result else "Unknown"
        except Exception:
            return "Unknown"

    @staticmethod
    def get_common_ports() -> Set[int]:
        """Return a set of commonly used ports"""
        common_ports = set(range(1, 1025))  # Well-known ports
        additional_ports = {
            1433,  # MSSQL
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5900,  # VNC
            6379,  # Redis
            8080,  # HTTP Alternate
            8443,  # HTTPS Alternate
            27017, # MongoDB
        }
        return common_ports.union(additional_ports)

    @staticmethod
    def is_host_up(ip: str) -> bool:
        """Check if host is reachable using ICMP ping"""
        try:
            response = sr1(IP(dst=ip) / ICMP(), timeout=2, verbose=0)
            return response is not None
        except Exception:
            return False

    @staticmethod
    def get_ip_info(ip: str) -> Tuple[str, str, str]:
        """Gather IP information including hostname, ISP, and MAC address"""
        hostname = "Unknown"
        isp = "Unknown"
        mac_address = TCPScanner.get_mac_address(ip)

        # Get hostname using reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            pass

        # Get ISP information using WHOIS
        try:
            whois_info = IPWhois(ip).lookup_rdap()
            isp = whois_info.get("asn_description", "Unknown")
        except Exception:
            pass

        return hostname, isp, mac_address

    async def scan_port(self, ip: str, port: int, hostname: str, isp: str, os: str, mac_address: str) -> None:
        """Scan a single port on the specified IP using evasion techniques if enabled"""
        async with self.semaphore:  # Limit concurrent scans
            try:
                port_status = "closed"
                service = "Unknown"

                if self.evasion:
                    # Add random delay between scans
                    await asyncio.sleep(self.evasion.get_random_delay(self.min_delay, self.max_delay))
                    
                    try:
                        # Get local IP for proper response matching
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect(("8.8.8.8", 80))
                        src_ip = s.getsockname()[0]
                        s.close()
                        
                        # Send decoy packets first
                        decoy_ips = self.evasion.create_decoy_ips()
                        for decoy_ip in decoy_ips:
                            decoy_packet = self.evasion.craft_custom_packet(ip, port, src_ip=decoy_ip)
                            send(decoy_packet, verbose=0)
                            await asyncio.sleep(0.1)  # Small delay between decoys
                        
                        # Create and send the real probe packet
                        syn_packet = self.evasion.craft_custom_packet(ip, port, src_ip=src_ip)
                        
                        # Only fragment if packet size is large enough
                        if len(bytes(syn_packet)) > 1000:
                            fragments = self.evasion.fragment_packet(syn_packet)
                            for frag in fragments:
                                send(frag, verbose=0)
                            # Small delay after fragments
                            await asyncio.sleep(0.1)
                        
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

                # Only attempt service detection and enrichment if port is open
                if port_status == "open":
                    service = self.detect_service(ip, port, self.timeout)
                    enrichment_data = await self.enrichment.enrich_scan_result(ip, service)
                else:
                    service = "Unknown"
                    enrichment_data = {
                        "cve_data": None,
                        "geo_status": None,
                        "geo_message": None,
                        "continent": None,
                        "continent_code": None,
                        "country": None,
                        "country_code": None,
                        "region": None,
                        "region_name": None,
                        "city": None,
                        "district": None,
                        "zip_code": None,
                        "latitude": None,
                        "longitude": None,
                        "timezone": None,
                        "offset": None,
                        "currency": None,
                        "isp": None,
                        "org": None,
                        "as_number": None,
                        "as_name": None,
                        "reverse_dns": None,
                        "is_mobile": None,
                        "is_proxy": None,
                        "is_hosting": None,
                        "query_ip": None,
                        "geo_location": None
                    }

                # Only save non-filtered results
                if port_status != "filtered":
                    await self.db.insert_scan_result(
                    ip=ip,
                    port=port,
                    protocol="TCP",
                    scan_status=port_status,
                    service=service,
                    os=os,
                    hostname=hostname,
                    mac_address=mac_address,
                    cve_data=enrichment_data["cve_data"],
                    # IP-API fields
                    geo_status=enrichment_data["geo_status"],
                    geo_message=enrichment_data["geo_message"],
                    continent=enrichment_data["continent"],
                    continent_code=enrichment_data["continent_code"],
                    country=enrichment_data["country"],
                    country_code=enrichment_data["country_code"],
                    region=enrichment_data["region"],
                    region_name=enrichment_data["region_name"],
                    city=enrichment_data["city"],
                    district=enrichment_data["district"],
                    zip_code=enrichment_data["zip_code"],
                    latitude=enrichment_data["latitude"],
                    longitude=enrichment_data["longitude"],
                    timezone=enrichment_data["timezone"],
                    offset=enrichment_data["offset"],
                    currency=enrichment_data["currency"],
                    isp=enrichment_data["isp"],
                    org=enrichment_data["org"],
                    as_number=enrichment_data["as_number"],
                    as_name=enrichment_data["as_name"],
                    reverse_dns=enrichment_data["reverse_dns"],
                    is_mobile=enrichment_data["is_mobile"],
                    is_proxy=enrichment_data["is_proxy"],
                    is_hosting=enrichment_data["is_hosting"],
                    query_ip=enrichment_data["query_ip"],
                    geo_location=enrichment_data["geo_location"]
                )
            except asyncio.TimeoutError:
                port_status = "filtered"
                service = "Unknown"
                enrichment_data = {
                    "cve_data": None,
                    "geo_status": None,
                    "geo_message": None,
                    "continent": None,
                    "continent_code": None,
                    "country": None,
                    "country_code": None,
                    "region": None,
                    "region_name": None,
                    "city": None,
                    "district": None,
                    "zip_code": None,
                    "latitude": None,
                    "longitude": None,
                    "timezone": None,
                    "offset": None,
                    "currency": None,
                    "isp": None,
                    "org": None,
                    "as_number": None,
                    "as_name": None,
                    "reverse_dns": None,
                    "is_mobile": None,
                    "is_proxy": None,
                    "is_hosting": None,
                    "query_ip": None,
                    "geo_location": None
                }
                # Skip saving filtered results
                if port_status != "filtered":
                    await self.db.insert_scan_result(
                        ip=ip,
                        port=port,
                        protocol="TCP",
                        scan_status=port_status,
                        service=service,
                        os=os,
                        hostname=hostname,
                        mac_address=mac_address,
                        cve_data=enrichment_data["cve_data"],
                        geo_status=enrichment_data["geo_status"],
                        geo_message=enrichment_data["geo_message"],
                        continent=enrichment_data["continent"],
                        continent_code=enrichment_data["continent_code"],
                        country=enrichment_data["country"],
                        country_code=enrichment_data["country_code"],
                        region=enrichment_data["region"],
                        region_name=enrichment_data["region_name"],
                        city=enrichment_data["city"],
                        district=enrichment_data["district"],
                        zip_code=enrichment_data["zip_code"],
                        latitude=enrichment_data["latitude"],
                        longitude=enrichment_data["longitude"],
                        timezone=enrichment_data["timezone"],
                        offset=enrichment_data["offset"],
                        currency=enrichment_data["currency"],
                        isp=enrichment_data["isp"],
                        org=enrichment_data["org"],
                        as_number=enrichment_data["as_number"],
                        as_name=enrichment_data["as_name"],
                        reverse_dns=enrichment_data["reverse_dns"],
                        is_mobile=enrichment_data["is_mobile"],
                        is_proxy=enrichment_data["is_proxy"],
                        is_hosting=enrichment_data["is_hosting"],
                        query_ip=enrichment_data["query_ip"],
                        geo_location=enrichment_data["geo_location"]
                    )
                print(f"Port {port} is {port_status} on {ip}")
            except ConnectionRefusedError:
                port_status = "closed"
                service = "Unknown"
                enrichment_data = {
                    "cve_data": None,
                    "geo_status": None,
                    "geo_message": None,
                    "continent": None,
                    "continent_code": None,
                    "country": None,
                    "country_code": None,
                    "region": None,
                    "region_name": None,
                    "city": None,
                    "district": None,
                    "zip_code": None,
                    "latitude": None,
                    "longitude": None,
                    "timezone": None,
                    "offset": None,
                    "currency": None,
                    "isp": None,
                    "org": None,
                    "as_number": None,
                    "as_name": None,
                    "reverse_dns": None,
                    "is_mobile": None,
                    "is_proxy": None,
                    "is_hosting": None,
                    "query_ip": None,
                    "geo_location": None
                }
                # Skip saving filtered results
                if port_status != "filtered":
                    await self.db.insert_scan_result(
                        ip=ip,
                        port=port,
                        protocol="TCP",
                        scan_status=port_status,
                        service=service,
                        os=os,
                        hostname=hostname,
                        mac_address=mac_address,
                        cve_data=enrichment_data["cve_data"],
                        geo_status=enrichment_data["geo_status"],
                        geo_message=enrichment_data["geo_message"],
                        continent=enrichment_data["continent"],
                        continent_code=enrichment_data["continent_code"],
                        country=enrichment_data["country"],
                        country_code=enrichment_data["country_code"],
                        region=enrichment_data["region"],
                        region_name=enrichment_data["region_name"],
                        city=enrichment_data["city"],
                        district=enrichment_data["district"],
                        zip_code=enrichment_data["zip_code"],
                        latitude=enrichment_data["latitude"],
                        longitude=enrichment_data["longitude"],
                        timezone=enrichment_data["timezone"],
                        offset=enrichment_data["offset"],
                        currency=enrichment_data["currency"],
                        isp=enrichment_data["isp"],
                        org=enrichment_data["org"],
                        as_number=enrichment_data["as_number"],
                        as_name=enrichment_data["as_name"],
                        reverse_dns=enrichment_data["reverse_dns"],
                        is_mobile=enrichment_data["is_mobile"],
                        is_proxy=enrichment_data["is_proxy"],
                        is_hosting=enrichment_data["is_hosting"],
                        query_ip=enrichment_data["query_ip"],
                        geo_location=enrichment_data["geo_location"]
                    )
                print(f"Port {port} is {port_status} on {ip}")
            except (OSError, Exception) as e:
                port_status = f"error: {str(e)}"
                service = "Unknown"
                enrichment_data = {
                    "cve_data": None,
                    "geo_status": None,
                    "geo_message": None,
                    "continent": None,
                    "continent_code": None,
                    "country": None,
                    "country_code": None,
                    "region": None,
                    "region_name": None,
                    "city": None,
                    "district": None,
                    "zip_code": None,
                    "latitude": None,
                    "longitude": None,
                    "timezone": None,
                    "offset": None,
                    "currency": None,
                    "isp": None,
                    "org": None,
                    "as_number": None,
                    "as_name": None,
                    "reverse_dns": None,
                    "is_mobile": None,
                    "is_proxy": None,
                    "is_hosting": None,
                    "query_ip": None,
                    "geo_location": None
                }
                await self.db.insert_scan_result(
                    ip=ip,
                    port=port,
                    protocol="TCP",
                    scan_status=port_status,
                    service=service,
                    os=os,
                    hostname=hostname,
                    mac_address=mac_address,
                    cve_data=enrichment_data["cve_data"],
                    geo_status=enrichment_data["geo_status"],
                    geo_message=enrichment_data["geo_message"],
                    continent=enrichment_data["continent"],
                    continent_code=enrichment_data["continent_code"],
                    country=enrichment_data["country"],
                    country_code=enrichment_data["country_code"],
                    region=enrichment_data["region"],
                    region_name=enrichment_data["region_name"],
                    city=enrichment_data["city"],
                    district=enrichment_data["district"],
                    zip_code=enrichment_data["zip_code"],
                    latitude=enrichment_data["latitude"],
                    longitude=enrichment_data["longitude"],
                    timezone=enrichment_data["timezone"],
                    offset=enrichment_data["offset"],
                    currency=enrichment_data["currency"],
                    isp=enrichment_data["isp"],
                    org=enrichment_data["org"],
                    as_number=enrichment_data["as_number"],
                    as_name=enrichment_data["as_name"],
                    reverse_dns=enrichment_data["reverse_dns"],
                    is_mobile=enrichment_data["is_mobile"],
                    is_proxy=enrichment_data["is_proxy"],
                    is_hosting=enrichment_data["is_hosting"],
                    query_ip=enrichment_data["query_ip"],
                    geo_location=enrichment_data["geo_location"]
                )
                if isinstance(e, Exception):
                    print(f"Error scanning {ip}:{port} - {str(e)}")
                print(f"Port {port} is {port_status} on {ip}")
            finally:
                pass  # No cleanup needed

    async def scan_ports(self, ip: str, ports: List[int] = None) -> None:
        """Scan multiple ports on the specified IP"""
        # Try ICMP ping but don't abort if it fails
        if not self.is_host_up(ip):
            print(f"Note: Host {ip} did not respond to ICMP ping, continuing with scan...")

        # Gather IP information and detect OS
        hostname, isp, mac_address = self.get_ip_info(ip)
        os = self.detect_os(ip)
        print(f"Scanning {ip} ({hostname}, {isp}, MAC: {mac_address}, OS: {os})...")

        if ports is None:
            ports = self.get_common_ports()
        
        tasks = [self.scan_port(ip, port, hostname, isp, os, mac_address) for port in ports]
        await asyncio.gather(*tasks)

    async def scan_multiple_ips(self, ips: List[str], ports: List[int] = None) -> None:
        """Scan multiple IPs concurrently with optional target randomization"""
        try:
            await self.db.init_db()
            
            # Randomize target order if evasion is enabled
            if self.evasion:
                ips = self.evasion.randomize_targets(ips)
            
            tasks = [self.scan_ports(ip, ports) for ip in ips]
            await asyncio.gather(*tasks)
        except Exception as e:
            print(f"Error during multi-IP scan: {str(e)}")
            raise
        finally:
            await self.close()  # Ensure database connection is closed

    async def _fallback_scan(self, ip: str, port: int) -> str:
        """Fallback to regular socket scanning when evasion fails or is disabled"""
        try:
            for _ in range(self.max_retries):
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    return "open"
                except (asyncio.TimeoutError, ConnectionRefusedError):
                    if _ == self.max_retries - 1:
                        raise
                    continue
        except asyncio.TimeoutError:
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except Exception:
            return "error"

    async def close(self) -> None:
        """Clean up resources"""
        await self.db.close()
