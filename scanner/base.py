"""Base scanner implementation"""
import asyncio
import socket
from typing import List, Set, Optional
from scapy.all import sr1, IP, ICMP, ARP, Ether, srp
from ipwhois import IPWhois

class BaseScanner:
    def __init__(self, max_concurrent_scans: int = 50000, timeout: float = 0.1):
        self.timeout = timeout
        self.max_concurrent_scans = max_concurrent_scans
        self.semaphore = asyncio.Semaphore(self.max_concurrent_scans)

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
    def get_ip_info(ip: str) -> tuple[str, str, str]:
        """Gather IP information including hostname, ISP, and MAC address"""
        hostname = "Unknown"
        isp = "Unknown"
        mac_address = BaseScanner.get_mac_address(ip)

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

    async def scan_port(self, ip: str, port: int) -> Optional[dict]:
        """
        Scan a single port. Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement scan_port")

    async def scan_ports(self, ip: str, ports: List[int] = None) -> List[dict]:
        """
        Scan multiple ports. Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement scan_ports")

    async def scan_multiple_ips(self, ips: List[str], ports: List[int] = None) -> None:
        """
        Scan multiple IPs. Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement scan_multiple_ips")

    async def _fallback_scan(self, ip: str, port: int) -> str:
        """
        Fallback scanning method. Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement _fallback_scan")
