import random
import time
from typing import List, Dict, Any
from scapy.all import IP, TCP, fragment, conf
import socket
import struct

class ScanEvasion:
    def __init__(self):
        self.decoy_ttls = [64, 128, 255]  # Linux, Windows, Network Device TTLs
        conf.verb = 0  # Suppress scapy output

    def randomize_targets(self, targets: List[str]) -> List[str]:
        """Randomize the order of target IPs to avoid sequential scanning patterns"""
        shuffled = targets.copy()
        random.shuffle(shuffled)
        return shuffled

    def get_random_delay(self, min_delay: float = 0.1, max_delay: float = 2.0) -> float:
        """Generate a random delay between scans to avoid rate-based detection"""
        return random.uniform(min_delay, max_delay)

    def fragment_packet(self, packet: IP, fragsize: int = 380) -> List[IP]:
        """Fragment a packet into smaller chunks to evade IDS"""
        return fragment(packet, fragsize=fragsize)

    def create_decoy_ips(self, count: int = 3) -> List[str]:
        """Generate decoy source IPs to obscure the real scanner"""
        decoy_ips = []
        for _ in range(count):
            # Generate random IP but avoid private ranges
            while True:
                ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
                if not self._is_private_ip(ip):
                    decoy_ips.append(ip)
                    break
        return decoy_ips

    def craft_custom_packet(self, dst_ip: str, dst_port: int, src_ip: str = None) -> IP:
        """Create a custom TCP packet that mimics legitimate traffic"""
        # Get source IP if not provided
        if not src_ip:
            # Get default interface IP
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                src_ip = s.getsockname()[0]
                s.close()
            except Exception:
                src_ip = "0.0.0.0"  # Fallback
        
        # Random source port above 49152 (ephemeral ports)
        sport = random.randint(49152, 65535)
        
        # Random sequence number
        seq = random.randint(1000000000, 2000000000)
        
        # Random window size from common values
        window_sizes = [8192, 16384, 29200, 65535]
        window = random.choice(window_sizes)
        
        # Create packet with random TTL
        ttl = random.choice(self.decoy_ttls)
        
        # TCP Options to mimic common clients
        tcp_options = [
            ('MSS', 1460),
            ('SAckOK', ''),
            ('Timestamp', (int(time.time()), 0)),
            ('NOP', None),
            ('WScale', 7)
        ]

        # Create IP/TCP packet with explicit source IP
        packet = IP(src=src_ip, dst=dst_ip, ttl=ttl) / \
                TCP(sport=sport, dport=dst_port, seq=seq, window=window,
                    flags='S', options=tcp_options)
        
        # Set IP ID and TCP checksum
        packet[IP].id = random.randint(1, 65535)
        packet[TCP].chksum = None  # Will be auto-computed
        
        return packet

    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is in private ranges"""
        ip_parts = list(map(int, ip.split('.')))
        return (
            ip_parts[0] == 10 or
            (ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31) or
            (ip_parts[0] == 192 and ip_parts[1] == 168)
        )

    @staticmethod
    def get_scan_timing_profile(profile: str = 'normal') -> Dict[str, Any]:
        """Get timing parameters based on profile"""
        profiles = {
            'paranoid': {
                'min_delay': 5.0,
                'max_delay': 15.0,
                'timeout': 10.0,
                'max_retries': 1,
                'max_parallel': 1
            },
            'sneaky': {
                'min_delay': 1.0,
                'max_delay': 5.0,
                'timeout': 5.0,
                'max_retries': 2,
                'max_parallel': 3
            },
            'normal': {
                'min_delay': 0.1,
                'max_delay': 1.0,
                'timeout': 2.0,
                'max_retries': 3,
                'max_parallel': 10
            },
            'aggressive': {
                'min_delay': 0.01,
                'max_delay': 0.1,
                'timeout': 1.0,
                'max_retries': 2,
                'max_parallel': 50
            }
        }
        return profiles.get(profile, profiles['normal'])
