"""
Generic Network Scan Detector
Detects unknown scanning tools based on behavioral patterns
"""

from typing import Optional, Dict
from .base_network_detector import BaseNetworkDetector


class GenericScanDetector(BaseNetworkDetector):
    """
    Detects generic port scanning activity from unknown tools

    Uses heuristic scoring based on:
    - Packet rates
    - Port diversity
    - SYN ratios
    - Temporal patterns
    - Traffic anomalies
    """

    def __init__(self):
        super().__init__('unknown_scanner')

    def detect(self, src_ip: str, context: dict, metrics: dict, packet) -> Optional[Dict]:
        """Detect generic scanning patterns"""

        # Need minimum activity
        total_packets = metrics.get('total_packets', 0)
        if total_packets < 10:
            return None

        score = 0
        details = {}

        # Scoring system (max 100 points)

        # 1. Packet Rate Analysis (0-25 points)
        rate_score = self._score_packet_rate(metrics)
        score += rate_score['score']
        if rate_score['score'] > 0:
            details.update(rate_score['details'])

        # 2. Port Diversity (0-25 points)
        port_score = self._score_port_diversity(metrics)
        score += port_score['score']
        if port_score['score'] > 0:
            details.update(port_score['details'])

        # 3. SYN Packet Analysis (0-20 points)
        syn_score = self._score_syn_patterns(metrics)
        score += syn_score['score']
        if syn_score['score'] > 0:
            details.update(syn_score['details'])

        # 4. Traffic Pattern (0-15 points)
        pattern_score = self._score_traffic_pattern(context, metrics)
        score += pattern_score['score']
        if pattern_score['score'] > 0:
            details.update(pattern_score['details'])

        # 5. Temporal Analysis (0-15 points)
        temporal_score = self._score_temporal_pattern(context)
        score += temporal_score['score']
        if temporal_score['score'] > 0:
            details.update(temporal_score['details'])

        # Convert score to confidence (0-100)
        confidence = min(100, score)

        # Only report if confidence is above threshold
        if confidence >= 50:
            return self.create_detection(
                confidence=confidence,
                method='behavioral_heuristics',
                details=details,
                techniques=self._determine_techniques(details)
            )

        return None

    def _score_packet_rate(self, metrics: dict) -> Dict:
        """Score based on packet rate"""
        packet_rate = metrics.get('packet_rate', 0)
        syn_rate = metrics.get('syn_rate', 0)
        rate = max(packet_rate, syn_rate)

        score = 0
        details = {}

        if rate > 100:
            score = 25
            details['rate_level'] = 'very_high'
        elif rate > 50:
            score = 20
            details['rate_level'] = 'high'
        elif rate > 10:
            score = 15
            details['rate_level'] = 'elevated'
        elif rate > 5:
            score = 10
            details['rate_level'] = 'moderate'
        elif rate > 2:
            score = 5
            details['rate_level'] = 'suspicious'

        if score > 0:
            details['packet_rate'] = round(rate, 2)

        return {'score': score, 'details': details}

    def _score_port_diversity(self, metrics: dict) -> Dict:
        """Score based on number of different ports accessed"""
        port_diversity = metrics.get('port_diversity', 0)
        recent_ports = metrics.get('recent_ports_count', 0)

        score = 0
        details = {}

        # Total port diversity
        if port_diversity > 100:
            score += 15
            details['port_scan_scope'] = 'massive'
        elif port_diversity > 50:
            score += 12
            details['port_scan_scope'] = 'large'
        elif port_diversity > 20:
            score += 10
            details['port_scan_scope'] = 'wide'
        elif port_diversity > 10:
            score += 7
            details['port_scan_scope'] = 'moderate'
        elif port_diversity > 5:
            score += 5
            details['port_scan_scope'] = 'small'

        # Recent port activity
        if recent_ports > 20:
            score += 10
            details['recent_activity'] = 'high'
        elif recent_ports > 10:
            score += 7
            details['recent_activity'] = 'moderate'
        elif recent_ports > 5:
            score += 5
            details['recent_activity'] = 'active'

        if score > 0:
            details['ports_scanned'] = port_diversity
            details['recent_ports'] = recent_ports

        return {'score': score, 'details': details}

    def _score_syn_patterns(self, metrics: dict) -> Dict:
        """Score based on SYN packet patterns"""
        syn_packets = metrics.get('syn_packets', 0)
        total_packets = metrics.get('total_packets', 0)

        if total_packets == 0:
            return {'score': 0, 'details': {}}

        syn_ratio = syn_packets / total_packets
        score = 0
        details = {}

        # High SYN ratio indicates scanning
        if syn_ratio > 0.9:
            score = 20
            details['syn_pattern'] = 'pure_syn_scan'
        elif syn_ratio > 0.7:
            score = 15
            details['syn_pattern'] = 'high_syn_ratio'
        elif syn_ratio > 0.5:
            score = 10
            details['syn_pattern'] = 'elevated_syn'
        elif syn_ratio > 0.3:
            score = 5
            details['syn_pattern'] = 'suspicious_syn'

        if score > 0:
            details['syn_ratio'] = round(syn_ratio, 2)
            details['syn_packets'] = syn_packets

        return {'score': score, 'details': details}

    def _score_traffic_pattern(self, context: dict, metrics: dict) -> Dict:
        """Score based on overall traffic pattern"""
        score = 0
        details = {}

        # Check packet type distribution
        packet_types = metrics.get('packet_types', {})
        total = sum(packet_types.values())

        if total == 0:
            return {'score': 0, 'details': {}}

        # Analyze distribution
        tcp_ratio = packet_types.get('TCP', 0) / total
        udp_ratio = packet_types.get('UDP', 0) / total
        icmp_ratio = packet_types.get('ICMP', 0) / total

        # Pure TCP scanning
        if tcp_ratio > 0.95:
            score += 8
            details['traffic_pattern'] = 'pure_tcp'

        # Mixed scanning (TCP + UDP)
        if tcp_ratio > 0.5 and udp_ratio > 0.1:
            score += 7
            details['traffic_pattern'] = 'mixed_scan'

        # ICMP scanning (ping sweep)
        if icmp_ratio > 0.3:
            score += 10
            details['icmp_scan'] = True

        # UDP scanning
        if udp_ratio > 0.5:
            score += 7
            details['udp_scan'] = True

        return {'score': score, 'details': details}

    def _score_temporal_pattern(self, context: dict) -> Dict:
        """Score based on temporal patterns"""
        packet_times = list(context['packet_times'])

        if len(packet_times) < 10:
            return {'score': 0, 'details': {}}

        score = 0
        details = {}

        # Calculate time intervals between packets
        intervals = []
        for i in range(len(packet_times) - 1):
            interval = packet_times[i + 1] - packet_times[i]
            intervals.append(interval)

        if not intervals:
            return {'score': 0, 'details': {}}

        # Calculate statistics
        avg_interval = sum(intervals) / len(intervals)
        min_interval = min(intervals)
        max_interval = max(intervals)

        # Very consistent timing (automated tool)
        if max_interval < avg_interval * 3 and len(intervals) > 20:
            score += 10
            details['timing_pattern'] = 'consistent'

        # Very fast scanning
        if avg_interval < 0.1:  # Less than 100ms between packets
            score += 5
            details['timing_pattern'] = 'rapid'

        # Burst pattern (periods of activity)
        if self._detect_burst_pattern(intervals):
            score += 5
            details['burst_pattern'] = True

        return {'score': score, 'details': details}

    def _detect_burst_pattern(self, intervals: list) -> bool:
        """Detect burst patterns in traffic"""
        if len(intervals) < 20:
            return False

        # Look for periods of fast traffic followed by pauses
        fast_count = sum(1 for i in intervals if i < 0.5)
        slow_count = sum(1 for i in intervals if i > 2)

        # If we have both fast and slow periods, it's bursty
        return fast_count > len(intervals) * 0.3 and slow_count > len(intervals) * 0.1

    def _determine_techniques(self, details: dict) -> list:
        """Determine attack techniques from detection details"""
        techniques = ['reconnaissance', 'port_scan']

        # Add specific techniques
        if details.get('rate_level') in ['very_high', 'high']:
            techniques.append('aggressive_scan')

        if details.get('syn_pattern') == 'pure_syn_scan':
            techniques.append('stealth_scan')

        if details.get('icmp_scan'):
            techniques.append('ping_sweep')

        if details.get('udp_scan'):
            techniques.append('udp_scan')

        if details.get('port_scan_scope') in ['massive', 'large']:
            techniques.append('comprehensive_scan')

        return techniques
