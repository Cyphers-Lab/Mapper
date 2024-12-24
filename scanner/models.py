"""Scanner data models"""
from dataclasses import dataclass
from typing import Optional, Dict, Any
from utils.enrichment import ServiceEnrichment

@dataclass
class ScanConfig:
    """Scanner configuration"""
    max_concurrent_scans: int = 50000
    timeout: float = 0.1
    timing_profile: str = 'normal'
    use_evasion: bool = False
    fast_mode: bool = True

@dataclass
class ScanResult:
    """Port scan result"""
    ip_address: str
    port: int
    protocol: str
    scan_status: str
    service: str = "Unknown"
    os: str = "Unknown"
    hostname: str = "Unknown"
    mac_address: str = "Unknown"
    enrichment_data: Optional[Dict[str, Any]] = None

    @classmethod
    async def create(cls, ip: str, port: int, protocol: str, scan_status: str,
                    service: str = "Unknown", os: str = "Unknown",
                    hostname: str = "Unknown", mac_address: str = "Unknown") -> 'ScanResult':
        """Create a scan result with enrichment data"""
        result = cls(
            ip_address=ip,
            port=port,
            protocol=protocol,
            scan_status=scan_status,
            service=service,
            os=os,
            hostname=hostname,
            mac_address=mac_address
        )
        
        # Only enrich if port is open
        if scan_status == "open":
            enrichment = ServiceEnrichment()
            result.enrichment_data = await enrichment.enrich_scan_result(ip, service)
            
        return result

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database operations"""
        base_dict = {
            "ip_address": self.ip_address,
            "port": self.port,
            "protocol": self.protocol,
            "scan_status": self.scan_status,
            "service": self.service,
            "os": self.os,
            "hostname": self.hostname,
            "mac_address": self.mac_address
        }
        
        # Add enrichment data if available
        if self.enrichment_data:
            base_dict.update(self.enrichment_data)
            
        return base_dict
