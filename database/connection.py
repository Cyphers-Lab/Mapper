"""Database connection management"""
import asyncio
import aiosqlite
from typing import Optional
from .schema import get_all_schemas, get_indexes

class DatabaseConnection:
    def __init__(self, db_file: str = "data/scan_results.db"):
        self.db_file = db_file
        self._connection: Optional[aiosqlite.Connection] = None

    async def get_connection(self) -> aiosqlite.Connection:
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

    async def init_db(self) -> None:
        """Initialize database schema and indexes"""
        try:
            print("Initializing database...")
            conn = await self.get_connection()
            
            # Create schemas
            for schema in get_all_schemas():
                await conn.execute(schema)
            
            # Create indexes
            for index in get_indexes():
                await conn.execute(index)
                
            await conn.commit()
            print("Database initialized successfully")
        except Exception as e:
            print(f"Failed to initialize database: {str(e)}")
            raise

    async def close(self) -> None:
        """Close the database connection"""
        if self._connection:
            try:
                await self._connection.close()
            except Exception as e:
                print(f"Error closing database connection: {str(e)}")
            finally:
                self._connection = None
