import os
import json
import asyncio
import aiohttp
import requests
import git
from bs4 import BeautifulSoup
from typing import List, Dict, Optional, Tuple
from pathlib import Path

class CVELookup:
    def __init__(self):
        self.cache_dir = Path(os.path.expanduser("~/.cache/port_scanner"))
        self.exploitdb_dir = self.cache_dir / "exploitdb"
        self.cache_file = self.cache_dir / "cve_cache.json"
        self.cve_cache = {}
        self._init_cache()

    def _init_cache(self):
        """Initialize cache directory and load existing cache"""
        # Create cache directory if it doesn't exist
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing cache if available
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    self.cve_cache = json.load(f)
            except json.JSONDecodeError:
                self.cve_cache = {}

    def _save_cache(self):
        """Save current cache to file"""
        with open(self.cache_file, 'w') as f:
            json.dump(self.cve_cache, f)

    def update_exploitdb(self):
        """Clone or update ExploitDB repository"""
        try:
            if not self.exploitdb_dir.exists():
                print("Cloning ExploitDB repository...")
                git.Repo.clone_from(
                    "https://gitlab.com/exploit-database/exploitdb.git",
                    self.exploitdb_dir
                )
            else:
                print("Updating ExploitDB repository...")
                repo = git.Repo(self.exploitdb_dir)
                repo.remotes.origin.pull()
        except Exception as e:
            print(f"Warning: Failed to update ExploitDB: {str(e)}")

    def search_exploitdb(self, service: str, version: str) -> List[Dict]:
        """Search ExploitDB for vulnerabilities"""
        results = []
        try:
            files_csv = self.exploitdb_dir / "files_exploits.csv"
            if not files_csv.exists():
                return results

            with open(files_csv, 'r', encoding='utf-8') as f:
                for line in f:
                    if service.lower() in line.lower():
                        # Parse CSV line (id,file,description,date,author,platform,type,port)
                        parts = line.strip().split(',')
                        if len(parts) >= 3:
                            exploit_id = parts[0]
                            description = parts[2]
                            
                            # Check version match if provided
                            if version and version.lower() in description.lower():
                                results.append({
                                    "source": "ExploitDB",
                                    "id": exploit_id,
                                    "description": description
                                })
        except Exception as e:
            print(f"Warning: ExploitDB search error: {str(e)}")
        return results

    async def search_nvd(self, service: str, version: str) -> List[Dict]:
        """Search NVD database for vulnerabilities"""
        results = []
        cache_key = f"{service}:{version}"

        # Check cache first
        if cache_key in self.cve_cache:
            return self.cve_cache[cache_key]

        try:
            # Use NVD API
            base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
            query = f"{service} {version}" if version else service
            
            async with aiohttp.ClientSession() as session:
                async with session.get(base_url, params={"keyword": query}) as response:
                    if response.status == 200:
                        data = await response.json()
                        for item in data.get("result", {}).get("CVE_Items", []):
                            cve_data = item["cve"]
                            cve_id = cve_data["CVE_data_meta"]["ID"]
                            description = cve_data["description"]["description_data"][0]["value"]
                            
                            # Get CVSS score if available
                            impact = item.get("impact", {})
                            cvss_v3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
                            cvss_v2 = impact.get("baseMetricV2", {}).get("cvssV2", {})
                            
                            score = None
                            if cvss_v3:
                                score = cvss_v3.get("baseScore")
                            elif cvss_v2:
                                score = cvss_v2.get("baseScore")

                            results.append({
                                "source": "NVD",
                                "id": cve_id,
                                "description": description,
                                "score": score
                            })

            # Cache the results
            if results:
                self.cve_cache[cache_key] = results
                self._save_cache()

        except Exception as e:
            print(f"Warning: NVD search error: {str(e)}")

        return results

    async def lookup_vulnerabilities(self, service: str, version: Optional[str] = None) -> List[Dict]:
        """
        Look up vulnerabilities from multiple sources
        Returns a list of vulnerabilities with source, ID, description, and score (if available)
        """
        if not service or service == "Unknown":
            return []

        # Search both ExploitDB and NVD
        exploitdb_results = self.search_exploitdb(service, version)
        nvd_results = await self.search_nvd(service, version)
        
        # Combine and sort results by score (if available)
        all_results = exploitdb_results + nvd_results
        return sorted(
            all_results,
            key=lambda x: (x.get("score", 0) or 0, x["source"], x["id"]),
            reverse=True
        )

    def format_vulnerabilities(self, vulns: List[Dict]) -> Optional[str]:
        """Format vulnerability results as a JSON string"""
        if not vulns:
            return None
            
        formatted = []
        for vuln in vulns:
            entry = {
                "source": vuln["source"],
                "id": vuln["id"],
                "description": vuln["description"]
            }
            if "score" in vuln and vuln["score"] is not None:
                entry["score"] = vuln["score"]
            formatted.append(entry)
            
        return json.dumps(formatted)
