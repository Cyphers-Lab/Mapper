"""IP address utilities"""
from typing import Tuple

def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private"""
    try:
        parts = [int(part) for part in ip.split('.')]
        if len(parts) != 4:
            return False
            
        # Convert to 32-bit integer
        ip_int = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        
        # Check private ranges
        private_ranges = [
            (0xA000000, 0xAFFFFFF),     # 10.0.0.0/8
            (0xAC100000, 0xAC1FFFFF),   # 172.16.0.0/12
            (0xC0A80000, 0xC0A8FFFF),   # 192.168.0.0/16
            (0x7F000000, 0x7FFFFFFF),   # 127.0.0.0/8 (loopback)
            (0xA9FE0000, 0xA9FEFFFF),   # 169.254.0.0/16 (link-local)
        ]
        
        return any(start <= ip_int <= end for start, end in private_ranges)
    except:
        return False

def parse_service_version(banner: str) -> Tuple[str, str]:
    """Extract service name and version from banner"""
    if not banner or banner == "Unknown":
        return "Unknown", None

    # Common version patterns
    patterns = [
        r"(\w+)(?:[ /-])(\d+(?:\.\d+)+)",  # Apache/2.4.41
        r"(\w+) version (\d+(?:\.\d+)+)",   # Example version 1.2.3
        r"(\w+) (\d+(?:\.\d+)+)"           # Simple name 1.2.3
    ]

    import re
    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1), match.group(2)

    # Return just the service name if no version found
    words = banner.split()
    return words[0], None
