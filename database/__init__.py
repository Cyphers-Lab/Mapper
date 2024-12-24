"""Database package initialization"""
from .models import ScanResult
from .connection import DatabaseConnection
from .operations import DatabaseOperations

class Database:
    """Main database interface that combines connection and operations"""
    def __init__(self, db_file: str = "data/scan_results.db"):
        self.connection = DatabaseConnection(db_file)
        self.operations = DatabaseOperations(self.connection)

    async def init_db(self) -> None:
        """Initialize database schema"""
        await self.connection.init_db()

    async def insert_scan_results_batch(self, results: list) -> None:
        """Insert multiple scan results"""
        scan_results = [
            ScanResult(**result) if not isinstance(result, ScanResult) else result
            for result in results
        ]
        await self.operations.insert_scan_results_batch(scan_results)

    async def insert_scan_result(self, **kwargs) -> None:
        """Insert a single scan result"""
        scan_result = ScanResult(**kwargs)
        await self.operations.insert_scan_result(scan_result)

    async def get_scan_results(self, ip: str = None) -> list:
        """Get scan results, optionally filtered by IP"""
        return await self.operations.get_scan_results(ip)

    async def update_scan_result(self, ip: str, port: int, update_data: dict) -> None:
        """Update an existing scan result"""
        await self.operations.update_scan_result(ip, port, update_data)

    async def close(self) -> None:
        """Close database connection"""
        await self.connection.close()

# For backwards compatibility
__all__ = ['Database', 'ScanResult']
