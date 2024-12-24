"""Scanner package initialization"""
from .models import ScanConfig, ScanResult
from .tcp import TCPScanner
from .udp import UDPScanner

class Scanner:
    """Main scanner interface that combines TCP and UDP scanning"""
    def __init__(self, config: ScanConfig = None):
        self.config = config or ScanConfig()
        self.tcp_scanner = TCPScanner(self.config)
        self.udp_scanner = UDPScanner(self.config)

    async def scan_ports(self, ip: str, ports: list = None, protocol: str = "TCP") -> list:
        """Scan ports on an IP address using specified protocol"""
        if protocol.upper() == "TCP":
            return await self.tcp_scanner.scan_ports(ip, ports)
        elif protocol.upper() == "UDP":
            return await self.udp_scanner.scan_ports(ip, ports)
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")

    async def scan_multiple_ips(self, ips: list, ports: list = None, protocol: str = "TCP") -> None:
        """Scan multiple IPs using specified protocol"""
        if protocol.upper() == "TCP":
            await self.tcp_scanner.scan_multiple_ips(ips, ports)
        elif protocol.upper() == "UDP":
            await self.udp_scanner.scan_multiple_ips(ips, ports)
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")

    async def scan_all(self, ips: list, ports: list = None) -> None:
        """Scan both TCP and UDP ports on multiple IPs"""
        print("Starting TCP scan...")
        await self.tcp_scanner.scan_multiple_ips(ips, ports)
        print("\nStarting UDP scan...")
        await self.udp_scanner.scan_multiple_ips(ips, ports)

__all__ = ['Scanner', 'ScanConfig', 'ScanResult', 'TCPScanner', 'UDPScanner']
