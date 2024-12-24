import json
import aiohttp
from typing import Dict, Optional, Tuple
from .cve_lookup import CVELookup

class ServiceEnrichment:
    def __init__(self):
        self.location_cache = {}  # Cache location results
        self.cve_lookup = CVELookup()
        # Initialize ExploitDB database
        self.cve_lookup.update_exploitdb()

    async def get_geolocation(self, ip: str) -> Optional[str]:
        """Get geographical location for an IP address using IP-API.com"""
        if ip in self.location_cache:
            return self.location_cache[ip]

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'http://ip-api.com/json/{ip}?fields=66846719') as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('status') == 'success':
                            # Format location string with all available information
                            location_parts = []
                            
                            # Add organization info
                            if data.get('org'):
                                location_parts.append(data['org'])
                            elif data.get('isp'):
                                location_parts.append(data['isp'])
                            
                            # Add location info
                            location_info = []
                            if data.get('city'):
                                location_info.append(data['city'])
                            if data.get('regionName'):
                                location_info.append(data['regionName'])
                            if data.get('country'):
                                location_info.append(data['country'])
                            
                            if location_info:
                                location_parts.append(', '.join(location_info))
                            
                            # Add coordinates if available
                            if data.get('lat') and data.get('lon'):
                                location_parts.append(f"({data['lat']}, {data['lon']})")
                            
                            # Add proxy/hosting info if relevant
                            flags = []
                            if data.get('proxy'):
                                flags.append('proxy')
                            if data.get('hosting'):
                                flags.append('hosting')
                            if flags:
                                location_parts.append(f"[{', '.join(flags)}]")
                            
                            formatted_location = ' - '.join(location_parts) if location_parts else "Unknown"
                            self.location_cache[ip] = formatted_location
                            return formatted_location
                            
            return "Unknown"
        except Exception as e:
            print(f"Geolocation error for {ip}: {str(e)}")
            return "Unknown"

    async def get_service_vulnerabilities(self, service: str, version: str = None) -> Optional[str]:
        """Query for vulnerabilities related to the service"""
        try:
            vulns = await self.cve_lookup.lookup_vulnerabilities(service, version)
            return self.cve_lookup.format_vulnerabilities(vulns)
        except Exception as e:
            print(f"Vulnerability lookup error for {service}: {str(e)}")
            return None

    def parse_service_version(self, banner: str) -> Tuple[str, Optional[str]]:
        """Extract service name and version from banner"""
        if not banner or banner == "Unknown":
            return "Unknown", None

        # Common version patterns
        patterns = [
            r"(\w+)(?:[ /-])(\d+(?:\.\d+)+)",  # Apache/2.4.41
            r"(\w+) version (\d+(?:\.\d+)+)",   # Example version 1.2.3
            r"(\w+) (\d+(?:\.\d+)+)"           # Simple name 1.2.3
        ]

        import re
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1), match.group(2)

        # Return just the service name if no version found
        words = banner.split()
        return words[0], None

    async def enrich_scan_result(self, ip: str, service_banner: str) -> Dict[str, any]:
        """Enrich scan results with geolocation and vulnerability data"""
        service, version = self.parse_service_version(service_banner)
        
        # Initialize geo data with default values
        geo_data = {
            "geo_status": "success",
            "geo_message": None,
            "continent": "Unknown",
            "continent_code": "Unknown",
            "country": "Unknown",
            "country_code": "Unknown",
            "region": "Unknown",
            "region_name": "Unknown",
            "city": "Unknown",
            "district": "Unknown",
            "zip_code": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "timezone": "Unknown",
            "offset": 0,
            "currency": "Unknown",
            "isp": "Unknown",
            "org": "Unknown",
            "as_number": "Unknown",
            "as_name": "Unknown",
            "reverse_dns": "Unknown",
            "is_mobile": False,
            "is_proxy": False,
            "is_hosting": False,
            "query_ip": "Unknown",
            "geo_location": "Unknown"
        }
        
        # Get geolocation data
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'http://ip-api.com/json/{ip}') as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('status') == 'success':
                            # Store raw data fields with default values
                            geo_data.update({
                                "geo_status": data.get('status', 'success'),
                                "geo_message": data.get('message'),
                                "continent": data.get('continent', 'Unknown'),
                                "continent_code": data.get('continentCode', 'Unknown'),
                                "country": data.get('country', 'Unknown'),
                                "country_code": data.get('countryCode', 'Unknown'),
                                "region": data.get('region', 'Unknown'),
                                "region_name": data.get('regionName', 'Unknown'),
                                "city": data.get('city', 'Unknown'),
                                "district": data.get('district', 'Unknown'),
                                "zip_code": data.get('zip', 'Unknown'),
                                "latitude": float(data.get('lat', 0)),
                                "longitude": float(data.get('lon', 0)),
                                "timezone": data.get('timezone', 'Unknown'),
                                "offset": int(data.get('offset', 0)),
                                "currency": data.get('currency', 'Unknown'),
                                "isp": data.get('isp', 'Unknown'),
                                "org": data.get('org', 'Unknown'),
                                "as_number": data.get('as', 'Unknown'),
                                "as_name": data.get('asname', 'Unknown'),
                                "reverse_dns": data.get('reverse', 'Unknown'),
                                "is_mobile": bool(data.get('mobile', False)),
                                "is_proxy": bool(data.get('proxy', False)),
                                "is_hosting": bool(data.get('hosting', False)),
                                "query_ip": data.get('query', ip)
                            })
                            
                            # Format readable location string
                            location_parts = []
                            if data.get('org'):
                                location_parts.append(data['org'])
                            elif data.get('isp'):
                                location_parts.append(data['isp'])
                            
                            location_info = []
                            if data.get('city'):
                                location_info.append(data['city'])
                            if data.get('regionName'):
                                location_info.append(data['regionName'])
                            if data.get('country'):
                                location_info.append(data['country'])
                            
                            if location_info:
                                location_parts.append(', '.join(location_info))
                            
                            if data.get('lat') and data.get('lon'):
                                location_parts.append(f"({data['lat']}, {data['lon']})")
                            
                            flags = []
                            if data.get('mobile'):
                                flags.append('mobile')
                            if data.get('proxy'):
                                flags.append('proxy')
                            if data.get('hosting'):
                                flags.append('hosting')
                            if flags:
                                location_parts.append(f"[{', '.join(flags)}]")
                            
                            geo_data["geo_location"] = ' - '.join(location_parts) if location_parts else "Unknown"
                        else:
                            geo_data["geo_status"] = "fail"
                            geo_data["geo_message"] = data.get('message', 'Unknown error')
        except Exception as e:
            print(f"Geolocation error for {ip}: {str(e)}")
        
        # Get vulnerability data
        cve_data = await self.get_service_vulnerabilities(service, version)
        
        # Return all enrichment data
        return {
            **geo_data,
            "cve_data": cve_data if cve_data else None
        }
