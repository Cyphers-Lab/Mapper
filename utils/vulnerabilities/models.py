"""Vulnerability data models"""
from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime

@dataclass
class Vulnerability:
    """CVE vulnerability information"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published_date: datetime
    last_modified_date: datetime
    references: List[str]
    affected_versions: List[str]

    def to_dict(self) -> dict:
        """Convert to dictionary format"""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "published_date": self.published_date.isoformat(),
            "last_modified_date": self.last_modified_date.isoformat(),
            "references": self.references,
            "affected_versions": self.affected_versions
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Vulnerability':
        """Create instance from dictionary"""
        return cls(
            cve_id=data["cve_id"],
            description=data["description"],
            severity=data["severity"],
            cvss_score=data["cvss_score"],
            published_date=datetime.fromisoformat(data["published_date"]),
            last_modified_date=datetime.fromisoformat(data["last_modified_date"]),
            references=data["references"],
            affected_versions=data["affected_versions"]
        )

@dataclass
class ServiceVulnerabilities:
    """Collection of vulnerabilities for a service"""
    service_name: str
    version: Optional[str]
    vulnerabilities: List[Vulnerability]
    last_updated: datetime = datetime.now()

    def format_vulnerabilities(self) -> str:
        """Format vulnerabilities into a readable string"""
        if not self.vulnerabilities:
            return None

        lines = [f"Vulnerabilities for {self.service_name} {self.version or '(version unknown)'}:"]
        
        # Sort by CVSS score descending
        sorted_vulns = sorted(
            self.vulnerabilities,
            key=lambda v: v.cvss_score,
            reverse=True
        )
        
        for vuln in sorted_vulns:
            lines.append(f"\nCVE: {vuln.cve_id}")
            lines.append(f"Severity: {vuln.severity} (CVSS: {vuln.cvss_score})")
            lines.append(f"Description: {vuln.description}")
            if vuln.affected_versions:
                lines.append(f"Affected versions: {', '.join(vuln.affected_versions)}")
            
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Convert to dictionary format"""
        return {
            "service_name": self.service_name,
            "version": self.version,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "last_updated": self.last_updated.isoformat()
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'ServiceVulnerabilities':
        """Create instance from dictionary"""
        return cls(
            service_name=data["service_name"],
            version=data["version"],
            vulnerabilities=[
                Vulnerability.from_dict(v) for v in data["vulnerabilities"]
            ],
            last_updated=datetime.fromisoformat(data["last_updated"])
        )
