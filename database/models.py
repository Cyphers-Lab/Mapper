from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class ScanResult:
    ip_address: str
    port: int
    protocol: str
    scan_status: str
    service: str = "Unknown"
    os: str = "Unknown"
    hostname: str = "Unknown"
    mac_address: str = "Unknown"
    cve_data: Optional[str] = None
    geo_status: str = "success"
    geo_message: Optional[str] = None
    continent: str = "Unknown"
    continent_code: str = "Unknown"
    country: str = "Unknown"
    country_code: str = "Unknown"
    region: str = "Unknown"
    region_name: str = "Unknown"
    city: str = "Unknown"
    district: str = "Unknown"
    zip_code: str = "Unknown"
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = "Unknown"
    offset: int = 0
    currency: str = "Unknown"
    isp: str = "Unknown"
    org: str = "Unknown"
    as_number: str = "Unknown"
    as_name: str = "Unknown"
    reverse_dns: str = "Unknown"
    is_mobile: bool = False
    is_proxy: bool = False
    is_hosting: bool = False
    query_ip: str = "Unknown"
    geo_location: str = "Unknown"
    timestamp: datetime = datetime.now()

    def to_dict(self) -> dict:
        """Convert to dictionary for database operations"""
        return {
            k: v if not isinstance(v, datetime) else v.isoformat()
            for k, v in self.__dict__.items()
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'ScanResult':
        """Create instance from dictionary"""
        if 'timestamp' in data and isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)
