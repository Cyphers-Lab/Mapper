"""Scanner evasion techniques"""
import random
from typing import List
from scapy.all import IP, TCP, UDP

class ScanEvasion:
    """Implements various scan evasion techniques"""
    
    def __init__(self):
        self.source_ports = list(range(1024, 65535))
        self.tcp_flags = [
            'S',     # SYN
            'SA',    # SYN-ACK
            'F',     # FIN
            'FA',    # FIN-ACK
            'R',     # RST
            'RA',    # RST-ACK
            'P',     # PSH
            'PA'     # PSH-ACK
        ]

    def randomize_targets(self, targets: List[str]) -> List[str]:
        """Randomize target order to avoid detection"""
        shuffled = targets.copy()
        random.shuffle(shuffled)
        return shuffled

    def craft_custom_packet(self, dst_ip: str, dst_port: int, src_ip: str = None,
                          protocol: str = "TCP") -> IP:
        """Create a custom packet with randomized parameters"""
        # Randomize source port
        src_port = random.choice(self.source_ports)
        
        # Create IP layer with random ID and TTL
        ip_layer = IP(
            src=src_ip,
            dst=dst_ip,
            id=random.randint(1, 65535),
            ttl=random.randint(32, 128)
        )

        if protocol.upper() == "TCP":
            # Create TCP layer with random flags and sequence number
            tcp_layer = TCP(
                sport=src_port,
                dport=dst_port,
                flags=random.choice(self.tcp_flags),
                seq=random.randint(1, 4294967295),
                window=random.randint(1024, 65535)
            )
            return ip_layer/tcp_layer
        else:
            # Create UDP layer
            udp_layer = UDP(
                sport=src_port,
                dport=dst_port
            )
            return ip_layer/udp_layer
