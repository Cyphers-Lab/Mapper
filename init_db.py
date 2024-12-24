"""Database initialization script"""
import sqlite3
import os
from database.schema import get_all_schemas, get_indexes

def init_database():
    """Initialize the database with required tables and indexes"""
    # Ensure data directory exists
    if not os.path.exists('data'):
        os.makedirs('data')
        
    # Connect to database
    conn = sqlite3.connect('data/scan_results.db')
    cursor = conn.cursor()
    
    try:
        # Create tables
        for schema in get_all_schemas():
            cursor.execute(schema)
            
        # Create indexes
        for index in get_indexes():
            cursor.execute(index)
            
        conn.commit()
        print("Database initialized successfully")
        
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        conn.rollback()
        
    finally:
        conn.close()

if __name__ == "__main__":
    init_database()
