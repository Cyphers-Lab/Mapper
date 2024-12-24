"""Database schema definition"""

SCAN_RESULTS_SCHEMA = """
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
    is_mobile INTEGER DEFAULT 0,
    is_proxy INTEGER DEFAULT 0,
    is_hosting INTEGER DEFAULT 0,
    query_ip TEXT DEFAULT 'Unknown',
    geo_location TEXT DEFAULT 'Unknown',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
"""

def get_all_schemas() -> list[str]:
    """Return all database schema creation statements"""
    return [SCAN_RESULTS_SCHEMA]

def get_indexes() -> list[str]:
    """Return all index creation statements"""
    return [
        "CREATE INDEX IF NOT EXISTS idx_scan_results_ip ON scan_results(ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_scan_results_port ON scan_results(port)",
        "CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results(scan_status)",
        "CREATE INDEX IF NOT EXISTS idx_scan_results_timestamp ON scan_results(timestamp)"
    ]
