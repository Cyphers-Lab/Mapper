"""Geolocation service for IP addresses"""
import aiohttp
from typing import Dict, Optional
from .models import GeoLocation
from ..network.ip import is_private_ip

class GeoLocationService:
    def __init__(self):
        self.location_cache: Dict[str, GeoLocation] = {}

    async def get_location(self, ip: str) -> GeoLocation:
        """Get geographical location for an IP address using IP-API.com"""
        # Return cached result if available
        if ip in self.location_cache:
            return self.location_cache[ip]

        # Return default for private IPs
        if is_private_ip(ip):
            return GeoLocation(query_ip=ip)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'http://ip-api.com/json/{ip}?fields=66846719', timeout=2) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('status') == 'success':
                            location = GeoLocation(
                                status=data.get('status', 'success'),
                                message=data.get('message'),
                                continent=data.get('continent', 'Unknown'),
                                continent_code=data.get('continentCode', 'Unknown'),
                                country=data.get('country', 'Unknown'),
                                country_code=data.get('countryCode', 'Unknown'),
                                region=data.get('region', 'Unknown'),
                                region_name=data.get('regionName', 'Unknown'),
                                city=data.get('city', 'Unknown'),
                                district=data.get('district', 'Unknown'),
                                zip_code=data.get('zip', 'Unknown'),
                                latitude=float(data.get('lat', 0)),
                                longitude=float(data.get('lon', 0)),
                                timezone=data.get('timezone', 'Unknown'),
                                offset=int(data.get('offset', 0)),
                                currency=data.get('currency', 'Unknown'),
                                isp=data.get('isp', 'Unknown'),
                                org=data.get('org', 'Unknown'),
                                as_number=data.get('as', 'Unknown'),
                                as_name=data.get('asname', 'Unknown'),
                                reverse_dns=data.get('reverse', 'Unknown'),
                                is_mobile=bool(data.get('mobile', False)),
                                is_proxy=bool(data.get('proxy', False)),
                                is_hosting=bool(data.get('hosting', False)),
                                query_ip=data.get('query', ip)
                            )
                            # Cache the result
                            self.location_cache[ip] = location
                            return location
                            
            return GeoLocation(status="error", message="API request failed", query_ip=ip)
        except Exception as e:
            return GeoLocation(
                status="error",
                message=f"Geolocation error: {str(e)}",
                query_ip=ip
            )
