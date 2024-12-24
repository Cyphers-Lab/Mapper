"""Geolocation data models"""
from dataclasses import dataclass
from typing import Optional

@dataclass
class GeoLocation:
    """Geolocation data for an IP address"""
    status: str = "success"
    message: Optional[str] = None
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

    def format_location(self) -> str:
        """Format location string with all available information"""
        location_parts = []
        
        # Add organization info
        if self.org != "Unknown":
            location_parts.append(self.org)
        elif self.isp != "Unknown":
            location_parts.append(self.isp)
        
        # Add location info
        location_info = []
        if self.city != "Unknown":
            location_info.append(self.city)
        if self.region_name != "Unknown":
            location_info.append(self.region_name)
        if self.country != "Unknown":
            location_info.append(self.country)
        
        if location_info:
            location_parts.append(', '.join(location_info))
        
        # Add coordinates if available
        if self.latitude != 0.0 and self.longitude != 0.0:
            location_parts.append(f"({self.latitude}, {self.longitude})")
        
        # Add proxy/hosting info if relevant
        flags = []
        if self.is_proxy:
            flags.append('proxy')
        if self.is_hosting:
            flags.append('hosting')
        if flags:
            location_parts.append(f"[{', '.join(flags)}]")
        
        return ' - '.join(location_parts) if location_parts else "Unknown"

    def to_dict(self) -> dict:
        """Convert to dictionary for database operations"""
        return {
            "geo_status": self.status,
            "geo_message": self.message,
            "continent": self.continent,
            "continent_code": self.continent_code,
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "region_name": self.region_name,
            "city": self.city,
            "district": self.district,
            "zip_code": self.zip_code,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "timezone": self.timezone,
            "offset": self.offset,
            "currency": self.currency,
            "isp": self.isp,
            "org": self.org,
            "as_number": self.as_number,
            "as_name": self.as_name,
            "reverse_dns": self.reverse_dns,
            "is_mobile": self.is_mobile,
            "is_proxy": self.is_proxy,
            "is_hosting": self.is_hosting,
            "query_ip": self.query_ip,
            "geo_location": self.format_location()
        }
