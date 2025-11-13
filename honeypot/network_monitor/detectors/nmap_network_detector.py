"""
Nmap Network Layer Detector
Detects Nmap port scanning based on packet patterns
"""

import time
from typing import Optional, Dict
from scapy.all import TCP, UDP, ICMP
from .base_network_detector import BaseNetworkDetector


class NmapNetworkDetector(BaseNetworkDetector):
    """
    Detects Nmap scanning activity from network traffic patterns

    Nmap Scan Types and Detection:
    - SYN scan (-sS): High rate SYN packets, no ACK
    - TCP connect scan (-sT): Full 3-way handshake
    - UDP scan (-sU): UDP packets to many ports
    - XMAS scan (-sX): FIN+PSH+URG flags
    - NULL scan (-sN): No flags set
    - FIN scan (-sF): Only FIN flag
    - ACK scan (-sA): Only ACK flag
    - Window scan (-sW): ACK flag with window checking

    Timing Templates Detection:
    - T0 (Paranoid): Very slow, 5+ minutes between packets
    - T1 (Sneaky): Slow, ~15 seconds between packets
    - T2 (Polite): ~0.4 seconds between packets
    - T3 (Normal): Default, parallel scanning
    - T4 (Aggressive): Fast, ~10ms between packets
    - T5 (Insane): Very fast, <1ms between packets
    """

    def __init__(self):
        super().__init__('nmap')

        # Timing template thresholds (packets per second)
        self.timing_templates = {
            'T0': (0, 0.2),      # < 0.2 pps
            'T1': (0.2, 1),      # 0.2-1 pps
            'T2': (1, 3),        # 1-3 pps
            'T3': (3, 10),       # 3-10 pps (default)
            'T4': (10, 50),      # 10-50 pps
            'T5': (50, 10000)    # > 50 pps
        }

    def detect(self, src_ip: str, context: dict, metrics: dict, packet) -> Optional[Dict]:
        """Detect Nmap scanning patterns"""

        # Must have some SYN packets or unusual packets
        syn_count = metrics.get('syn_packets', 0)
        total_packets = metrics.get('total_packets', 0)

        if syn_count < 5 and total_packets < 10:
            return None

        confidence = 0
        detection_methods = []
        details = {}

        # Detection 1: SYN Scan Pattern
        syn_detection = self._detect_syn_scan(context, metrics)
        if syn_detection:
            confidence += syn_detection['confidence']
            detection_methods.append('syn_scan')
            details.update(syn_detection['details'])

        # Detection 2: Unusual TCP Flags (XMAS, NULL, FIN scans)
        flags_detection = self._detect_unusual_flags(packet, context)
        if flags_detection:
            confidence += flags_detection['confidence']
            detection_methods.append(flags_detection['method'])
            details.update(flags_detection['details'])

        # Detection 3: Port Scanning Pattern (many ports)
        port_scan_detection = self._detect_port_scan_pattern(metrics)
        if port_scan_detection:
            confidence += port_scan_detection['confidence']
            detection_methods.append('port_diversity')
            details.update(port_scan_detection['details'])

        # Detection 4: Timing Analysis
        timing_detection = self._detect_timing_pattern(metrics)
        if timing_detection:
            confidence += timing_detection['confidence']
            detection_methods.append('timing_analysis')
            details.update(timing_detection['details'])

        # Detection 5: Sequential Port Scanning
        sequential_detection = self._detect_sequential_ports(context)
        if sequential_detection:
            confidence += sequential_detection['confidence']
            detection_methods.append('sequential_ports')
            details.update(sequential_detection['details'])

        # If confidence is high enough, report detection
        if confidence >= 50:
            # Determine techniques based on detection
            techniques = self._determine_techniques(detection_methods, details)

            return self.create_detection(
                confidence=min(100, confidence),
                method='+'.join(detection_methods[:3]),  # Top 3 methods
                details=details,
                techniques=techniques
            )

        return None

    def _detect_syn_scan(self, context: dict, metrics: dict) -> Optional[Dict]:
        """Detect SYN scan pattern (-sS)"""
        syn_rate = metrics.get('syn_rate', 0)
        syn_count = metrics.get('syn_packets', 0)
        port_diversity = metrics.get('port_diversity', 0)

        if syn_count < 5:
            return None

        confidence = 0
        details = {}

        # High SYN rate indicates scanning
        if syn_rate > 5:
            confidence += 30
            details['syn_rate'] = round(syn_rate, 2)

        # Many SYN packets
        if syn_count > 20:
            confidence += 20
            details['syn_packets'] = syn_count

        # Scanning many ports with SYN
        if port_diversity > 10:
            confidence += 20
            details['ports_scanned'] = port_diversity

        # Check SYN/ACK ratio (real traffic has more ACKs)
        tcp_count = context['packet_types'].get('TCP', 0)
        if tcp_count > 0:
            syn_ratio = syn_count / tcp_count
            if syn_ratio > 0.7:  # >70% SYN packets is suspicious
                confidence += 15
                details['syn_ratio'] = round(syn_ratio, 2)

        if confidence > 0:
            return {
                'confidence': confidence,
                'details': details
            }

        return None

    def _detect_unusual_flags(self, packet, context: dict) -> Optional[Dict]:
        """
        Detect unusual TCP flag combinations used in stealth scans
        - XMAS scan: FIN+PSH+URG
        - NULL scan: No flags
        - FIN scan: Only FIN
        """
        if not packet.haslayer(TCP):
            return None

        tcp = packet[TCP]
        flags = tcp.flags

        # XMAS scan (FIN+PSH+URG)
        if flags.F and flags.P and flags.U and not (flags.S or flags.A or flags.R):
            return {
                'confidence': 70,
                'method': 'xmas_scan',
                'details': {
                    'scan_type': 'xmas_scan',
                    'tcp_flags': str(flags)
                }
            }

        # NULL scan (no flags)
        if flags == 0:
            return {
                'confidence': 65,
                'method': 'null_scan',
                'details': {
                    'scan_type': 'null_scan',
                    'tcp_flags': 'none'
                }
            }

        # FIN scan (only FIN)
        if flags.F and not (flags.S or flags.A or flags.P or flags.U or flags.R):
            return {
                'confidence': 65,
                'method': 'fin_scan',
                'details': {
                    'scan_type': 'fin_scan',
                    'tcp_flags': str(flags)
                }
            }

        # ACK scan (only ACK, used for firewall detection)
        if flags.A and not (flags.S or flags.F or flags.P or flags.U or flags.R):
            # Many ACK-only packets is suspicious
            ack_count = context['packet_types'].get('ACK', 0)
            if ack_count > 10:
                return {
                    'confidence': 50,
                    'method': 'ack_scan',
                    'details': {
                        'scan_type': 'ack_scan',
                        'tcp_flags': str(flags),
                        'ack_packets': ack_count
                    }
                }

        return None

    def _detect_port_scan_pattern(self, metrics: dict) -> Optional[Dict]:
        """Detect port scanning based on port diversity"""
        port_diversity = metrics.get('port_diversity', 0)
        recent_ports = metrics.get('recent_ports_count', 0)

        confidence = 0
        details = {}

        # Many unique ports scanned
        if port_diversity > 50:
            confidence += 25
            details['total_ports_scanned'] = port_diversity
        elif port_diversity > 20:
            confidence += 15
            details['total_ports_scanned'] = port_diversity
        elif port_diversity > 10:
            confidence += 10
            details['total_ports_scanned'] = port_diversity

        # Many ports in recent window (indicates active scanning)
        if recent_ports > 20:
            confidence += 20
            details['recent_ports_scanned'] = recent_ports
        elif recent_ports > 10:
            confidence += 10
            details['recent_ports_scanned'] = recent_ports

        if confidence > 0:
            return {
                'confidence': confidence,
                'details': details
            }

        return None

    def _detect_timing_pattern(self, metrics: dict) -> Optional[Dict]:
        """Detect Nmap timing template based on packet rate"""
        packet_rate = metrics.get('packet_rate', 0)
        syn_rate = metrics.get('syn_rate', 0)

        # Use the higher rate for detection
        rate = max(packet_rate, syn_rate)

        if rate == 0:
            return None

        # Determine timing template
        timing_template = None
        for template, (min_rate, max_rate) in self.timing_templates.items():
            if min_rate <= rate < max_rate:
                timing_template = template
                break

        if not timing_template:
            return None

        # Calculate confidence based on rate and template
        confidence = 0
        details = {
            'packet_rate': round(rate, 2),
            'timing_template': timing_template
        }

        # Aggressive timings (T4, T5) are more indicative of scanning
        if timing_template in ['T4', 'T5']:
            confidence += 25
            details['scan_speed'] = 'aggressive'
        elif timing_template == 'T3':
            confidence += 15
            details['scan_speed'] = 'normal'
        elif timing_template in ['T0', 'T1', 'T2']:
            confidence += 20
            details['scan_speed'] = 'stealth'

        return {
            'confidence': confidence,
            'details': details
        }

    def _detect_sequential_ports(self, context: dict) -> Optional[Dict]:
        """Detect sequential port scanning pattern"""
        ports = sorted(list(context['ports_scanned']))

        if len(ports) < 10:
            return None

        # Check for sequential patterns
        sequential_count = 0
        for i in range(len(ports) - 1):
            if ports[i + 1] - ports[i] == 1:
                sequential_count += 1

        # Calculate sequential ratio
        sequential_ratio = sequential_count / (len(ports) - 1) if len(ports) > 1 else 0

        # High sequential ratio indicates systematic scanning
        if sequential_ratio > 0.5:  # >50% sequential
            confidence = int(sequential_ratio * 40)
            return {
                'confidence': confidence,
                'details': {
                    'sequential_ports': sequential_count,
                    'sequential_ratio': round(sequential_ratio, 2),
                    'pattern': 'sequential_scan'
                }
            }

        # Check for common port ranges (well-known ports, registered ports, etc.)
        well_known_ports = [p for p in ports if p < 1024]
        if len(well_known_ports) > 10:
            return {
                'confidence': 15,
                'details': {
                    'well_known_ports_scanned': len(well_known_ports),
                    'pattern': 'well_known_ports'
                }
            }

        return None

    def _determine_techniques(self, methods: list, details: dict) -> list:
        """Determine MITRE ATT&CK techniques based on detection"""
        techniques = ['reconnaissance', 'port_scan']

        # Add specific technique based on scan type
        scan_type = details.get('scan_type', '')
        if scan_type in ['xmas_scan', 'null_scan', 'fin_scan', 'ack_scan']:
            techniques.append('stealth_scan')

        if details.get('scan_speed') == 'stealth':
            techniques.append('slow_scan')
        elif details.get('scan_speed') == 'aggressive':
            techniques.append('aggressive_scan')

        return techniques
