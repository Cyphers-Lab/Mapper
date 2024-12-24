"""Vulnerability lookup service"""
import json
import aiohttp
from typing import Dict, List, Optional
from datetime import datetime
from .models import Vulnerability, ServiceVulnerabilities
from ..network.ip import parse_service_version

class VulnerabilityService:
    def __init__(self):
        self.vulnerability_cache: Dict[str, ServiceVulnerabilities] = {}
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def _get_cache_key(self, service: str, version: Optional[str] = None) -> str:
        """Generate cache key for service and version"""
        return f"{service}:{version or 'unknown'}"

    async def lookup_vulnerabilities(self, service_banner: str) -> Optional[ServiceVulnerabilities]:
        """Look up vulnerabilities for a service based on its banner"""
        if not service_banner or service_banner == "Unknown":
            return None

        # Parse service name and version from banner
        service_name, version = parse_service_version(service_banner)
        if service_name == "Unknown":
            return None

        # Check cache first
        cache_key = self._get_cache_key(service_name, version)
        if cache_key in self.vulnerability_cache:
            cached = self.vulnerability_cache[cache_key]
            # Return cached result if less than 24 hours old
            if (datetime.now() - cached.last_updated).total_seconds() < 86400:
                return cached

        try:
            # Construct search parameters
            params = {
                "keywordSearch": service_name,
                "resultsPerPage": 20,
                "isExactMatch": True
            }
            
            vulnerabilities: List[Vulnerability] = []
            
            async with aiohttp.ClientSession() as session:
                async with session.get(self.api_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for vuln in data.get('vulnerabilities', []):
                            cve = vuln.get('cve', {})
                            metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0]
                            
                            # Extract version information
                            versions = []
                            for node in cve.get('configurations', []):
                                for match in node.get('nodes', []):
                                    for cpe in match.get('cpeMatch', []):
                                        if cpe.get('vulnerable'):
                                            versions.append(cpe.get('versionStartIncluding', '*'))
                            
                            vulnerability = Vulnerability(
                                cve_id=cve.get('id', 'Unknown'),
                                description=cve.get('descriptions', [{}])[0].get('value', 'No description'),
                                severity=metrics.get('cvssData', {}).get('baseSeverity', 'UNKNOWN'),
                                cvss_score=float(metrics.get('cvssData', {}).get('baseScore', 0.0)),
                                published_date=datetime.fromisoformat(cve.get('published', '').replace('Z', '+00:00')),
                                last_modified_date=datetime.fromisoformat(cve.get('lastModified', '').replace('Z', '+00:00')),
                                references=[ref.get('url') for ref in cve.get('references', [])],
                                affected_versions=versions
                            )
                            
                            # Only include if version matches or no version specified
                            if not version or any(v in version for v in versions):
                                vulnerabilities.append(vulnerability)
            
            # Create and cache result
            result = ServiceVulnerabilities(
                service_name=service_name,
                version=version,
                vulnerabilities=vulnerabilities
            )
            self.vulnerability_cache[cache_key] = result
            return result
            
        except Exception as e:
            print(f"Error looking up vulnerabilities for {service_name}: {str(e)}")
            return None

    def format_vulnerabilities(self, vulns: Optional[ServiceVulnerabilities]) -> Optional[str]:
        """Format vulnerabilities into a string for database storage"""
        if not vulns:
            return None
        return json.dumps(vulns.to_dict())
