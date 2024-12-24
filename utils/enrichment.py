"""Service enrichment coordinator"""
from typing import Dict, Any
from .geo.service import GeoLocationService
from .vulnerabilities.service import VulnerabilityService

class ServiceEnrichment:
    def __init__(self):
        self.geo_service = GeoLocationService()
        self.vuln_service = VulnerabilityService()

    async def enrich_scan_result(self, ip: str, service_banner: str) -> Dict[str, Any]:
        """Enrich scan result with geolocation and vulnerability data"""
        # Get geolocation data
        geo_location = await self.geo_service.get_location(ip)
        result = geo_location.to_dict()
        
        # Get vulnerability data if service banner available
        if service_banner != "Unknown" and "HTTP" in service_banner:
            vulns = await self.vuln_service.lookup_vulnerabilities(service_banner)
            result["cve_data"] = self.vuln_service.format_vulnerabilities(vulns)
        else:
            result["cve_data"] = None
            
        return result
