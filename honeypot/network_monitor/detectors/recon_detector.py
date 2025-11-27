"""
Reconnaissance Tool Detector
Detects reconnaissance tools like Amass and BBOT based on traffic patterns
"""

from typing import Optional, Dict
from scapy.all import UDP, TCP, DNS
from .base_network_detector import BaseNetworkDetector


class ReconDetector(BaseNetworkDetector):
    """
    Detects reconnaissance activities from tools like Amass and BBOT.
    Focuses on high-rate DNS queries and aggressive mixed scanning.
    """

    def __init__(self):
        super().__init__('recon_tool')
        self.amass_thresholds = {
            'dns_rate': 20,  # DNS queries per second
            'concurrent_ips': 50  # Number of unique IPs contacted recently
        }

    def detect(self, src_ip: str, context: dict, metrics: dict, packet) -> Optional[Dict]:
        """Detect recon patterns"""
        
        # Amass Detection (DNS Enumeration)
        amass_detection = self._detect_amass(context, metrics, packet)
        if amass_detection:
            return amass_detection

        # BBOT Detection (Aggressive Mixed Scanning)
        bbot_detection = self._detect_bbot(context, metrics)
        if bbot_detection:
            return bbot_detection

        return None

    def _detect_amass(self, context: dict, metrics: dict, packet) -> Optional[Dict]:
        """
        Detect Amass based on high-frequency DNS queries.
        Amass is known for aggressive subdomain enumeration.
        """
        # Check if it's a DNS packet
        is_dns = False
        if packet.haslayer(UDP) and packet.haslayer(DNS):
            is_dns = True
        elif packet.haslayer(UDP) and packet[UDP].dport == 53:
            is_dns = True

        if not is_dns:
            return None

        # Calculate DNS specific metrics if not already present
        # Note: This relies on the main sniffer tracking packet types correctly
        # We might need to enhance the main sniffer to track DNS specifically if this isn't enough
        # For now, we use packet rate and UDP prevalence as a proxy if DNS specific tracking is missing
        
        packet_rate = metrics.get('packet_rate', 0)
        udp_count = metrics.get('packet_types', {}).get('UDP', 0)
        total_packets = metrics.get('total_packets', 0)
        
        if total_packets < 20:
            return None

        udp_ratio = udp_count / total_packets
        
        # Amass Pattern: High rate UDP/DNS traffic
        if packet_rate > self.amass_thresholds['dns_rate'] and udp_ratio > 0.8:
            return self.create_detection(
                confidence=85,
                method='high_rate_dns',
                details={
                    'tool': 'amass',
                    'packet_rate': round(packet_rate, 2),
                    'udp_ratio': round(udp_ratio, 2),
                    'activity': 'dns_enumeration'
                },
                techniques=['reconnaissance', 'dns_enumeration']
            )
            
        return None

    def _detect_bbot(self, context: dict, metrics: dict) -> Optional[Dict]:
        """
        Detect BBOT based on aggressive mixed scanning.
        BBOT often runs multiple modules (web, port scan, subdomain) simultaneously.
        """
        packet_rate = metrics.get('packet_rate', 0)
        port_diversity = metrics.get('port_diversity', 0)
        packet_types = metrics.get('packet_types', {})
        
        # BBOT is noisy
        if packet_rate < 10:
            return None
            
        # Check for mixed traffic (TCP + UDP)
        tcp_count = packet_types.get('TCP', 0)
        udp_count = packet_types.get('UDP', 0)
        
        if tcp_count == 0 or udp_count == 0:
            return None
            
        # BBOT Pattern: High rate, mixed traffic, moderate port diversity
        # It's less "pure" than Masscan (SYN only) or Amass (UDP/DNS only)
        if packet_rate > 15 and port_diversity > 20:
            return self.create_detection(
                confidence=60,
                method='aggressive_mixed_scan',
                details={
                    'tool': 'bbot',
                    'packet_rate': round(packet_rate, 2),
                    'traffic_mix': 'tcp_udp',
                    'port_diversity': port_diversity
                },
                techniques=['reconnaissance', 'active_scanning']
            )

        return None
