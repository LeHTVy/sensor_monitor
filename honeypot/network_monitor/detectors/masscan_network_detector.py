"""
Masscan Network Layer Detector
Detects Masscan - the world's fastest port scanner
"""

from typing import Optional, Dict
from scapy.all import TCP
from .base_network_detector import BaseNetworkDetector


class MasscanNetworkDetector(BaseNetworkDetector):
    """
    Detects Masscan scanning activity

    Masscan Characteristics:
    - Extremely high scan rate (1000+ packets per second)
    - Randomized source ports
    - SYN packets only
    - Custom TCP/IP stack (unusual TTL, window size)
    - Stateless scanning (doesn't track responses)
    - Can scan entire internet in 6 minutes
    """

    def __init__(self):
        super().__init__('masscan')

        # Masscan typically scans at very high rates
        self.min_rate = 100  # Minimum 100 packets/second
        self.high_rate = 500  # High confidence at 500+ pps

    def detect(self, src_ip: str, context: dict, metrics: dict, packet) -> Optional[Dict]:
        """Detect Masscan scanning patterns"""

        syn_rate = metrics.get('syn_rate', 0)
        syn_count = metrics.get('syn_packets', 0)
        packet_rate = metrics.get('packet_rate', 0)

        # Masscan requires high rate
        if syn_rate < self.min_rate and packet_rate < self.min_rate:
            return None

        confidence = 0
        details = {}

        # Detection 1: Extremely high packet rate
        rate_detection = self._detect_high_rate(syn_rate, packet_rate)
        if rate_detection:
            confidence += rate_detection['confidence']
            details.update(rate_detection['details'])

        # Detection 2: Custom TCP stack fingerprinting
        if packet.haslayer(TCP):
            stack_detection = self._detect_custom_stack(packet)
            if stack_detection:
                confidence += stack_detection['confidence']
                details.update(stack_detection['details'])

        # Detection 3: Randomized source ports
        src_port_detection = self._detect_random_src_ports(context)
        if src_port_detection:
            confidence += src_port_detection['confidence']
            details.update(src_port_detection['details'])

        # Detection 4: Pure SYN scanning pattern
        syn_detection = self._detect_pure_syn_scan(metrics)
        if syn_detection:
            confidence += syn_detection['confidence']
            details.update(syn_detection['details'])

        # Detection 5: High port diversity
        port_detection = self._detect_port_pattern(metrics)
        if port_detection:
            confidence += port_detection['confidence']
            details.update(port_detection['details'])

        if confidence >= 60:
            return self.create_detection(
                confidence=min(100, confidence),
                method='high_rate_scan',
                details=details,
                techniques=['reconnaissance', 'mass_scan', 'aggressive_scan']
            )

        return None

    def _detect_high_rate(self, syn_rate: float, packet_rate: float) -> Optional[Dict]:
        """Detect extremely high packet rates characteristic of Masscan"""
        rate = max(syn_rate, packet_rate)

        if rate < self.min_rate:
            return None

        confidence = 0
        details = {
            'packet_rate': round(rate, 2),
            'scan_type': 'mass_scan'
        }

        # Scale confidence with rate
        if rate >= 1000:
            confidence = 50
            details['rate_classification'] = 'extreme'
        elif rate >= self.high_rate:
            confidence = 40
            details['rate_classification'] = 'very_high'
        elif rate >= 200:
            confidence = 30
            details['rate_classification'] = 'high'
        elif rate >= self.min_rate:
            confidence = 20
            details['rate_classification'] = 'elevated'

        return {
            'confidence': confidence,
            'details': details
        }

    def _detect_custom_stack(self, packet) -> Optional[Dict]:
        """
        Detect Masscan's custom TCP/IP stack characteristics

        Masscan uses its own TCP/IP stack with specific characteristics:
        - TTL values (often 255 or unusual values)
        - TCP window size (often unusual)
        - TCP options (minimal or absent)
        """
        tcp = packet[TCP]
        ip = packet.getlayer('IP')

        confidence = 0
        details = {}

        # Check TTL (Masscan often uses high TTL like 255)
        if ip and ip.ttl >= 250:
            confidence += 15
            details['unusual_ttl'] = ip.ttl

        # Check TCP window size (Masscan uses specific values)
        # Common Masscan window sizes: 1024, 2048, 4096
        window = tcp.window
        if window in [1024, 2048, 4096]:
            confidence += 15
            details['suspicious_window'] = window

        # Check for minimal TCP options
        options = tcp.options
        if len(options) <= 1:  # Very few or no options
            confidence += 10
            details['minimal_tcp_options'] = len(options)

        # Check sequence number (Masscan uses specific patterns)
        # Masscan often uses custom sequence numbers
        if tcp.seq != 0 and tcp.seq % 256 == 0:
            confidence += 10
            details['custom_seq_pattern'] = True

        if confidence > 0:
            return {
                'confidence': confidence,
                'details': details
            }

        return None

    def _detect_random_src_ports(self, context: dict) -> Optional[Dict]:
        """
        Detect randomized source ports

        Masscan randomizes source ports for stateless scanning
        """
        syn_packets = list(context['syn_packets'])

        if len(syn_packets) < 10:
            return None

        # Extract source ports from recent SYN packets
        # Note: In our context we track destination ports, but in a full
        # implementation we'd track source ports too
        # For now, we check if scanning many different destination ports

        # High port diversity indicates scanning
        port_diversity = len(context['ports_scanned'])

        if port_diversity > 100:
            return {
                'confidence': 20,
                'details': {
                    'high_port_diversity': port_diversity,
                    'scanning_pattern': 'wide_range'
                }
            }

        return None

    def _detect_pure_syn_scan(self, metrics: dict) -> Optional[Dict]:
        """
        Detect pure SYN scanning (stateless)

        Masscan only sends SYN packets and doesn't complete handshakes
        """
        syn_packets = metrics.get('syn_packets', 0)
        total_packets = metrics.get('total_packets', 0)

        if total_packets == 0 or syn_packets < 10:
            return None

        # Calculate SYN ratio
        syn_ratio = syn_packets / total_packets

        # Very high SYN ratio indicates stateless scanning
        if syn_ratio > 0.95:  # >95% SYN packets
            confidence = 25
            return {
                'confidence': confidence,
                'details': {
                    'syn_ratio': round(syn_ratio, 2),
                    'stateless_scan': True,
                    'syn_packets': syn_packets
                }
            }
        elif syn_ratio > 0.85:  # >85% SYN packets
            confidence = 15
            return {
                'confidence': confidence,
                'details': {
                    'syn_ratio': round(syn_ratio, 2),
                    'mostly_syn': True
                }
            }

        return None

    def _detect_port_pattern(self, metrics: dict) -> Optional[Dict]:
        """Detect port scanning patterns typical of Masscan"""
        port_diversity = metrics.get('port_diversity', 0)
        recent_ports = metrics.get('recent_ports_count', 0)

        confidence = 0
        details = {}

        # Masscan typically scans many ports very quickly
        if port_diversity > 200:
            confidence += 20
            details['massive_port_scan'] = port_diversity
        elif port_diversity > 100:
            confidence += 15
            details['large_port_scan'] = port_diversity
        elif port_diversity > 50:
            confidence += 10
            details['wide_port_scan'] = port_diversity

        # High recent port count indicates active fast scanning
        if recent_ports > 50:
            confidence += 15
            details['recent_ports'] = recent_ports

        if confidence > 0:
            return {
                'confidence': confidence,
                'details': details
            }

        return None
