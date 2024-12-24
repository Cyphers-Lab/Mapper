"""Database CRUD operations"""
from typing import List, Optional, Dict, Any
from .connection import DatabaseConnection
from .models import ScanResult

class DatabaseOperations:
    def __init__(self, connection: DatabaseConnection):
        self.connection = connection

    async def insert_scan_results_batch(self, results: List[ScanResult]) -> None:
        """Optimized batch insert using executemany"""
        if not results:
            print("No results to insert in batch")
            return
            
        try:
            print(f"Inserting batch of {len(results)} results...")
            conn = await self.connection.get_connection()
            
            # Convert ScanResult objects to tuples for executemany
            values = []
            for result in results:
                result_dict = result.to_dict()
                values.append((
                    result_dict['ip_address'],
                    result_dict['port'],
                    result_dict['protocol'],
                    result_dict['scan_status'],
                    result_dict['service'],
                    result_dict['os'],
                    result_dict['hostname'],
                    result_dict['mac_address'],
                    result_dict['cve_data'],
                    result_dict['geo_status'],
                    result_dict['geo_message'],
                    result_dict['continent'],
                    result_dict['continent_code'],
                    result_dict['country'],
                    result_dict['country_code'],
                    result_dict['region'],
                    result_dict['region_name'],
                    result_dict['city'],
                    result_dict['district'],
                    result_dict['zip_code'],
                    result_dict['latitude'],
                    result_dict['longitude'],
                    result_dict['timezone'],
                    result_dict['offset'],
                    result_dict['currency'],
                    result_dict['isp'],
                    result_dict['org'],
                    result_dict['as_number'],
                    result_dict['as_name'],
                    result_dict['reverse_dns'],
                    1 if result_dict['is_mobile'] else 0,
                    1 if result_dict['is_proxy'] else 0,
                    1 if result_dict['is_hosting'] else 0,
                    result_dict['query_ip'],
                    result_dict['geo_location']
                ))
            
            if values:
                await conn.executemany(
                    """INSERT INTO scan_results (
                        ip_address, port, protocol, scan_status, service, os, hostname,
                        mac_address, cve_data, geo_status, geo_message, continent,
                        continent_code, country, country_code, region, region_name,
                        city, district, zip, latitude, longitude, timezone, offset,
                        currency, isp, org, as_number, as_name, reverse_dns,
                        is_mobile, is_proxy, is_hosting, query_ip, geo_location
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    values
                )
                await conn.commit()
                print(f"Successfully inserted {len(values)} results")
        except Exception as e:
            print(f"Failed to insert scan results batch: {str(e)}")
            raise

    async def insert_scan_result(self, result: ScanResult) -> None:
        """Insert a single scan result"""
        try:
            print(f"Inserting result for {result.ip_address}:{result.port} ({result.scan_status})")
            conn = await self.connection.get_connection()
            
            result_dict = result.to_dict()
            values = [
                result_dict['ip_address'],
                result_dict['port'],
                result_dict['protocol'],
                result_dict['scan_status'],
                result_dict['service'],
                result_dict['os'],
                result_dict['hostname'],
                result_dict['mac_address'],
                result_dict['cve_data'],
                result_dict['geo_status'],
                result_dict['geo_message'],
                result_dict['continent'],
                result_dict['continent_code'],
                result_dict['country'],
                result_dict['country_code'],
                result_dict['region'],
                result_dict['region_name'],
                result_dict['city'],
                result_dict['district'],
                result_dict['zip_code'],
                result_dict['latitude'],
                result_dict['longitude'],
                result_dict['timezone'],
                result_dict['offset'],
                result_dict['currency'],
                result_dict['isp'],
                result_dict['org'],
                result_dict['as_number'],
                result_dict['as_name'],
                result_dict['reverse_dns'],
                1 if result_dict['is_mobile'] else 0,
                1 if result_dict['is_proxy'] else 0,
                1 if result_dict['is_hosting'] else 0,
                result_dict['query_ip'],
                result_dict['geo_location']
            ]
            
            await conn.execute(
                """INSERT INTO scan_results (
                    ip_address, port, protocol, scan_status, service, os, hostname,
                    mac_address, cve_data, geo_status, geo_message, continent,
                    continent_code, country, country_code, region, region_name,
                    city, district, zip, latitude, longitude, timezone, offset,
                    currency, isp, org, as_number, as_name, reverse_dns,
                    is_mobile, is_proxy, is_hosting, query_ip, geo_location
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                         ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                values
            )
            await conn.commit()
        except Exception as e:
            print(f"Failed to insert scan result: {str(e)}")
            raise

    async def get_scan_results(self, ip: Optional[str] = None) -> List[ScanResult]:
        """Get scan results, optionally filtered by IP address"""
        try:
            conn = await self.connection.get_connection()
            if ip:
                cursor = await conn.execute(
                    "SELECT * FROM scan_results WHERE ip_address = ? AND scan_status != 'filtered' ORDER BY port",
                    (ip,)
                )
            else:
                cursor = await conn.execute(
                    "SELECT * FROM scan_results WHERE scan_status != 'filtered' ORDER BY ip_address, port"
                )
            
            rows = await cursor.fetchall()
            results = []
            for row in rows:
                # Convert row to dictionary
                result_dict = {}
                for idx, column in enumerate(cursor.description):
                    result_dict[column[0]] = row[idx]
                results.append(ScanResult.from_dict(result_dict))
            
            return results
        except Exception as e:
            raise Exception(f"Failed to retrieve scan results: {str(e)}")

    async def update_scan_result(self, ip: str, port: int, update_data: Dict[str, Any]) -> None:
        """Update an existing scan result with new data"""
        try:
            conn = await self.connection.get_connection()
            
            # Build SET clause dynamically from update_data
            set_clause = ", ".join([f"{key} = ?" for key in update_data.keys()])
            values = list(update_data.values())
            values.extend([ip, port])  # Add WHERE clause values
            
            await conn.execute(
                f"""UPDATE scan_results 
                    SET {set_clause}
                    WHERE ip_address = ? AND port = ?""",
                values
            )
            await conn.commit()
        except Exception as e:
            print(f"Failed to update scan result: {str(e)}")
            raise
