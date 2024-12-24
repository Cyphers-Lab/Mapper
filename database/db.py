import asyncio
import aiosqlite
from datetime import datetime

class Database:
    def __init__(self, db_file="data/scan_results.db"):
        self.db_file = db_file
        self._connection = None

    async def get_connection(self):
        """Get or create database connection with timeout"""
        try:
            if self._connection is None:
                self._connection = await asyncio.wait_for(
                    aiosqlite.connect(self.db_file),
                    timeout=5.0
                )
            return self._connection
        except asyncio.TimeoutError:
            raise Exception("Database connection timeout")
        except Exception as e:
            raise Exception(f"Database connection error: {str(e)}")

    async def init_db(self):
        """Initialize database schema"""
        try:
            conn = await self.get_connection()
            # Drop existing table to apply new schema
            await conn.execute("DROP TABLE IF EXISTS scan_results")
            # Create table with default values
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                scan_status TEXT NOT NULL,
                service TEXT DEFAULT 'Unknown',
                os TEXT DEFAULT 'Unknown',
                hostname TEXT DEFAULT 'Unknown',
                mac_address TEXT DEFAULT 'Unknown',
                cve_data TEXT DEFAULT NULL,
                
                -- IP-API fields
                geo_status TEXT DEFAULT 'success',
                geo_message TEXT DEFAULT NULL,
                continent TEXT DEFAULT 'Unknown',
                continent_code TEXT DEFAULT 'Unknown',
                country TEXT DEFAULT 'Unknown',
                country_code TEXT DEFAULT 'Unknown',
                region TEXT DEFAULT 'Unknown',
                region_name TEXT DEFAULT 'Unknown',
                city TEXT DEFAULT 'Unknown',
                district TEXT DEFAULT 'Unknown',
                zip TEXT DEFAULT 'Unknown',
                latitude REAL DEFAULT 0.0,
                longitude REAL DEFAULT 0.0,
                timezone TEXT DEFAULT 'Unknown',
                offset INTEGER DEFAULT 0,
                currency TEXT DEFAULT 'Unknown',
                isp TEXT DEFAULT 'Unknown',
                org TEXT DEFAULT 'Unknown',
                as_number TEXT DEFAULT 'Unknown',
                as_name TEXT DEFAULT 'Unknown',
                reverse_dns TEXT DEFAULT 'Unknown',
                is_mobile BOOLEAN DEFAULT 0,
                is_proxy BOOLEAN DEFAULT 0,
                is_hosting BOOLEAN DEFAULT 0,
                query_ip TEXT DEFAULT 'Unknown',
                geo_location TEXT DEFAULT 'Unknown',
                
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """)
            await conn.commit()
        except Exception as e:
            raise Exception(f"Failed to initialize database: {str(e)}")

    async def insert_scan_result(self, ip: str, port: int, protocol: str, scan_status: str, 
                               service: str = 'Unknown', os: str = 'Unknown', hostname: str = 'Unknown',
                               mac_address: str = 'Unknown', cve_data: str = None,
                               # IP-API fields
                               geo_status: str = 'success', geo_message: str = None,
                               continent: str = 'Unknown', continent_code: str = 'Unknown',
                               country: str = 'Unknown', country_code: str = 'Unknown',
                               region: str = 'Unknown', region_name: str = 'Unknown',
                               city: str = 'Unknown', district: str = 'Unknown',
                               zip_code: str = 'Unknown', latitude: float = 0.0,
                               longitude: float = 0.0, timezone: str = 'Unknown',
                               offset: int = 0, currency: str = 'Unknown',
                               isp: str = 'Unknown', org: str = 'Unknown',
                               as_number: str = 'Unknown', as_name: str = 'Unknown',
                               reverse_dns: str = 'Unknown', is_mobile: bool = False,
                               is_proxy: bool = False, is_hosting: bool = False,
                               query_ip: str = 'Unknown', geo_location: str = 'Unknown'):
        """Insert a scan result into the database. Skips results with 'closed' status."""
        # Skip closed ports
        if scan_status.lower() == 'closed':
            return
        retries = 3
        for attempt in range(retries):
            try:
                conn = await self.get_connection()
                # Convert None values to defaults
                values = [
                    ip, port, protocol, scan_status,
                    service or 'Unknown',
                    os or 'Unknown',
                    hostname or 'Unknown',
                    mac_address or 'Unknown',
                    cve_data,
                    # IP-API fields
                    geo_status or 'success',
                    geo_message,
                    continent or 'Unknown',
                    continent_code or 'Unknown',
                    country or 'Unknown',
                    country_code or 'Unknown',
                    region or 'Unknown',
                    region_name or 'Unknown',
                    city or 'Unknown',
                    district or 'Unknown',
                    zip_code or 'Unknown',
                    latitude if latitude is not None else 0.0,
                    longitude if longitude is not None else 0.0,
                    timezone or 'Unknown',
                    offset if offset is not None else 0,
                    currency or 'Unknown',
                    isp or 'Unknown',
                    org or 'Unknown',
                    as_number or 'Unknown',
                    as_name or 'Unknown',
                    reverse_dns or 'Unknown',
                    1 if is_mobile else 0,
                    1 if is_proxy else 0,
                    1 if is_hosting else 0,
                    query_ip or 'Unknown',
                    geo_location or 'Unknown'
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
                break
            except Exception as e:
                if attempt == retries - 1:  # Last attempt
                    raise Exception(f"Failed to insert scan result after {retries} attempts: {str(e)}")
                await asyncio.sleep(0.1 * (attempt + 1))  # Exponential backoff

    async def get_scan_results(self, ip: str = None):
        """Get scan results, optionally filtered by IP address"""
        try:
            conn = await self.get_connection()
            if ip:
                cursor = await conn.execute(
                    "SELECT * FROM scan_results WHERE ip_address = ? AND scan_status != 'filtered' ORDER BY port",
                    (ip,)
                )
            else:
                cursor = await conn.execute("SELECT * FROM scan_results WHERE scan_status != 'filtered' ORDER BY ip_address, port")
            return await cursor.fetchall()
        except Exception as e:
            raise Exception(f"Failed to retrieve scan results: {str(e)}")

    async def close(self):
        """Close the database connection"""
        if self._connection:
            try:
                await self._connection.close()
            except Exception as e:
                print(f"Error closing database connection: {str(e)}")
            finally:
                self._connection = None
