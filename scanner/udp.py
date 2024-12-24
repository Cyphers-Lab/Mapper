import asyncio
from scapy.all import sr1, IP, UDP, ICMP
from typing import List, Set
from database.db import Database
from utils.enrichment import ServiceEnrichment
from .tcp import TCPScanner  # Reuse TCP scanner's IP info gathering methods

class UDPScanner:
    def __init__(self, max_concurrent_scans: int = 1000, timeout: float = 2.0):
        self.max_concurrent_scans = max_concurrent_scans
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent_scans)
        self.db = Database()
        self.enrichment = ServiceEnrichment()

    @staticmethod
    def get_common_ports() -> Set[int]:
        """Return a set of commonly used UDP ports"""
        return {
            53,    # DNS
            67,    # DHCP Server
            68,    # DHCP Client
            69,    # TFTP
            123,   # NTP
            137,   # NetBIOS Name Service
            138,   # NetBIOS Datagram Service
            161,   # SNMP
            162,   # SNMP Trap
            500,   # IKE (VPN)
            514,   # Syslog
            520,   # RIP
            1194,  # OpenVPN
            1434,  # MSSQL Browser
            1900,  # UPNP
            5353,  # mDNS
            27015  # Source Engine Games
        }

    async def scan_udp_port(self, ip: str, port: int, hostname: str, isp: str, os: str, mac_address: str) -> None:
        """Scan a single UDP port"""
        async with self.semaphore:
            try:
                # Send UDP packet and wait for response
                response = sr1(
                    IP(dst=ip)/UDP(dport=port),
                    timeout=self.timeout,
                    verbose=0
                )

                # Get enrichment data regardless of port status
                enrichment_data = await self.enrichment.enrich_scan_result(ip, "UDP Service")

                if response is None:
                    # No response could mean open or filtered - skip saving filtered results
                    status = "open|filtered"
                    print(f"UDP Port {port} is {status} on {ip}")
                    # Skip saving filtered results
                elif response.haslayer(ICMP):
                    # ICMP Port Unreachable means port is closed
                    status = "closed" if response[ICMP].type == 3 and response[ICMP].code == 3 else "filtered"
                    # Only save if not filtered
                    if status != "filtered":
                        await self.db.insert_scan_result(
                        ip=ip,
                        port=port,
                        protocol="UDP",
                        scan_status=status,
                        service="Unknown",
                        os=os,
                        hostname=hostname,
                        mac_address=mac_address,
                        cve_data=None,
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
                else:
                    # Got a UDP response - port is open
                    await self.db.insert_scan_result(
                        ip=ip,
                        port=port,
                        protocol="UDP",
                        scan_status="open",
                        service="Unknown",
                        os=os,
                        hostname=hostname,
                        mac_address=mac_address,
                        cve_data=None,
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
                    print(f"UDP Port {port} is open on {ip}")

            except Exception as e:
                status = f"error: {str(e)}"
                # Only save actual errors, not filtered results
                if not "filtered" in status.lower():
                    await self.db.insert_scan_result(
                        ip=ip,
                        port=port,
                        protocol="UDP",
                        scan_status=f"error: {str(e)}",
                        service="Unknown",
                        os=os,
                        hostname=hostname,
                        mac_address=mac_address,
                        cve_data=None
                )

    async def scan_ports(self, ip: str, ports: List[int] = None) -> None:
        """Scan multiple UDP ports on the specified IP"""
        # Reuse TCP scanner's host discovery and info gathering
        if not TCPScanner.is_host_up(ip):
            print(f"Note: Host {ip} did not respond to ICMP ping, continuing with scan...")

        hostname, isp, mac_address = TCPScanner.get_ip_info(ip)
        os = TCPScanner.detect_os(ip)
        print(f"UDP Scanning {ip} ({hostname}, {isp}, MAC: {mac_address}, OS: {os})...")

        if ports is None:
            ports = self.get_common_ports()

        tasks = [
            self.scan_udp_port(ip, port, hostname, isp, os, mac_address)
            for port in ports
        ]
        await asyncio.gather(*tasks)

    async def scan_multiple_ips(self, ips: List[str], ports: List[int] = None) -> None:
        """Scan multiple IPs concurrently"""
        try:
            await self.db.init_db()
            tasks = [self.scan_ports(ip, ports) for ip in ips]
            await asyncio.gather(*tasks)
        except Exception as e:
            print(f"Error during multi-IP UDP scan: {str(e)}")
            raise
        finally:
            await self.close()

    async def close(self) -> None:
        """Clean up resources"""
        await self.db.close()
