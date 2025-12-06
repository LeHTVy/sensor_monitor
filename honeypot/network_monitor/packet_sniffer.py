#!/usr/bin/env python3
"""
Network Layer Packet Sniffer for Honeypot
Captures and analyzes network traffic at packet level
Detects port scans, SYN scans, and other network-layer attacks
"""

import sys
import os
import json
import threading
import time
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
import queue

# Add parent directory to path for imports
# This adds /app/ to the path so we can import app.utils.kafka_producer
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Also add /app/app to path as fallback
app_dir = os.path.join(parent_dir, 'app')
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    from scapy.layers.inet import TCP, UDP
except ImportError:
    print("ERROR: Scapy not installed. Install with: pip install scapy")
    sys.exit(1)

# Import Kafka producer - try multiple import paths
try:
    from app.utils.kafka_producer import HoneypotKafkaProducer as KafkaProducer
except ImportError:
    try:
        from utils.kafka_producer import HoneypotKafkaProducer as KafkaProducer
    except ImportError:
        print("ERROR: Cannot import HoneypotKafkaProducer")
        print(f"sys.path: {sys.path}")
        print(f"Looking for: {os.path.join(parent_dir, 'app', 'utils', 'kafka_producer.py')}")
        sys.exit(1)

# Import network detectors
from detectors.nmap_network_detector import NmapNetworkDetector
from detectors.masscan_network_detector import MasscanNetworkDetector
from detectors.generic_scan_detector import GenericScanDetector
from detectors.web_scanner_detector import WebScannerDetector
from detectors.recon_detector import ReconDetector

# Import enhanced analyzers
from analyzers.pyshark_analyzer import PysharkAnalyzer
from analyzers.yara_analyzer import YaraAnalyzer
from analyzers.nmap_scanner import NmapScanner


class PacketSniffer:
    """
    Main packet sniffer class that captures network traffic
    and analyzes it for attack patterns
    """

    def __init__(self, interface='any', kafka_bootstrap='10.8.0.1:9093',
                 enable_pyshark=True, enable_yara=True, enable_nmap_scanner=True):
        """
        Initialize packet sniffer

        Args:
            interface: Network interface to sniff on ('any' for all interfaces, 'auto' to detect)
            kafka_bootstrap: Kafka server address for log transmission
            enable_pyshark: Enable deep packet analysis with Pyshark
            enable_yara: Enable YARA pattern matching
            enable_nmap_scanner: Enable active scanning of attackers
        """
        # Auto-detect interface if needed
        if interface == 'auto':
            self.interface = self._detect_interface()
            print(f"🔍 Auto-detected interface: {self.interface}")
        else:
            self.interface = interface

        self.kafka_producer = None
        self.kafka_bootstrap = kafka_bootstrap
        self.running = False

        # Traffic tracking per IP
        self.ip_contexts = defaultdict(lambda: {
            'syn_packets': deque(maxlen=1000),  # Track last 1000 SYN packets
            'ports_scanned': set(),              # Unique ports accessed
            'packet_times': deque(maxlen=1000),  # Timestamps for rate calculation
            'packet_types': defaultdict(int),    # Count by packet type
            'last_seen': None,
            'total_packets': 0
        })

        # Detectors
        self.detectors = [
            NmapNetworkDetector(),
            MasscanNetworkDetector(),
            GenericScanDetector(),
            WebScannerDetector(),
            ReconDetector()
        ]
        
        # Enhanced analyzers
        self.pyshark_analyzer = PysharkAnalyzer(
            interface=self.interface, 
            enabled=enable_pyshark
        ) if enable_pyshark else None
        
        self.yara_analyzer = YaraAnalyzer(
            enabled=enable_yara
        ) if enable_yara else None
        
        self.nmap_scanner = NmapScanner(
            enabled=enable_nmap_scanner,
            rate_limit=5  # Max 5 scans per minute
        ) if enable_nmap_scanner else None

        # Stats
        self.stats = {
            'packets_captured': 0,
            'attacks_detected': 0,
            'yara_matches': 0,
            'deep_analyses': 0,
            'counter_scans': 0,
            'start_time': None
        }

        # Kafka queue for async sending
        self.kafka_queue = queue.Queue(maxsize=1000)
        self.kafka_worker = None

        print(f"🌐 PacketSniffer initialized on interface: {interface}")
        print(f"   📊 Pyshark: {'enabled' if enable_pyshark else 'disabled'}")
        print(f"   🔍 YARA: {'enabled' if enable_yara else 'disabled'}")
        print(f"   🎯 Nmap Scanner: {'enabled' if enable_nmap_scanner else 'disabled'}")

    def initialize_kafka(self):
        """Initialize Kafka producer with retry logic"""
        max_retries = 5
        retry_delay = 2

        for attempt in range(max_retries):
            try:
                print(f"🔌 Connecting to Kafka at {self.kafka_bootstrap} (attempt {attempt + 1}/{max_retries})...")
                self.kafka_producer = KafkaProducer(bootstrap_servers=self.kafka_bootstrap)
                print(f"✅ Kafka producer connected successfully!")

                # Start Kafka worker thread
                self.kafka_worker = threading.Thread(target=self._kafka_worker_loop, daemon=True)
                self.kafka_worker.start()
                print("✅ Kafka worker thread started")

                return True
            except Exception as e:
                print(f"❌ Kafka connection attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    print(f"⏳ Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    print(f"❌ Failed to connect to Kafka after {max_retries} attempts")
                    return False

    def _kafka_worker_loop(self):
        """Background worker to send logs to Kafka"""
        print("🔄 Kafka worker loop started")
        while True:
            try:
                log_data = self.kafka_queue.get(timeout=1)
                if log_data is None:  # Poison pill to stop worker
                    break

                # Send to Kafka
                try:
                    self.kafka_producer.send_attack_log(log_data)
                except Exception as e:
                    print(f"❌ Failed to send log to Kafka: {e}")

            except queue.Empty:
                continue
            except Exception as e:
                print(f"❌ Kafka worker error: {e}")

    def packet_callback(self, packet):
        """
        Callback function for each captured packet
        Analyzes packet and detects attacks
        """
        try:
            # Only process IP packets
            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            self.stats['packets_captured'] += 1

            # Update IP context
            context = self.ip_contexts[src_ip]
            context['last_seen'] = datetime.now()
            context['total_packets'] += 1
            context['packet_times'].append(time.time())
            
            # Run YARA pattern matching on payload
            yara_matches = []
            if self.yara_analyzer and packet.haslayer('Raw'):
                yara_matches = self.yara_analyzer.scan_packet(packet)
                if yara_matches:
                    self.stats['yara_matches'] += len(yara_matches)
                    context.setdefault('yara_matches', []).extend(yara_matches)
            
            # Deep packet analysis for suspicious traffic
            deep_analysis = None
            if self.pyshark_analyzer and context['total_packets'] >= 5:
                deep_analysis = self.pyshark_analyzer.analyze_packet(packet)
                if deep_analysis:
                    self.stats['deep_analyses'] += 1
                    context['deep_analysis'] = deep_analysis

            # Analyze TCP packets
            if packet.haslayer(TCP):
                self._analyze_tcp_packet(packet, src_ip, context)

            # Analyze UDP packets
            elif packet.haslayer(UDP):
                self._analyze_udp_packet(packet, src_ip, context)

            # Analyze ICMP packets
            elif packet.haslayer(ICMP):
                self._analyze_icmp_packet(packet, src_ip, context)

            # Cleanup old contexts every 1000 packets
            if self.stats['packets_captured'] % 1000 == 0:
                self._cleanup_old_contexts()

        except Exception as e:
            print(f"❌ Error processing packet: {e}")

    def _analyze_tcp_packet(self, packet, src_ip: str, context: dict):
        """Analyze TCP packet for scanning patterns"""
        tcp_layer = packet[TCP]
        dst_port = tcp_layer.dport
        flags = tcp_layer.flags

        context['packet_types']['TCP'] += 1

        # Track port access
        context['ports_scanned'].add(dst_port)

        # Detect SYN packets (potential SYN scan)
        if flags.S and not flags.A:  # SYN flag set, ACK not set
            context['syn_packets'].append({
                'port': dst_port,
                'time': time.time(),
                'flags': str(flags)
            })
            context['packet_types']['SYN'] += 1

            # Run detectors if we have enough data
            if len(context['syn_packets']) >= 5:
                self._run_detectors(src_ip, context, packet)

    def _analyze_udp_packet(self, packet, src_ip: str, context: dict):
        """Analyze UDP packet for scanning patterns"""
        udp_layer = packet[UDP]
        dst_port = udp_layer.dport

        context['packet_types']['UDP'] += 1
        context['ports_scanned'].add(dst_port)

        # Run detectors for UDP scans
        if context['total_packets'] >= 10:
            self._run_detectors(src_ip, context, packet)

    def _analyze_icmp_packet(self, packet, src_ip: str, context: dict):
        """Analyze ICMP packet for ping scans"""
        context['packet_types']['ICMP'] += 1

        # Run detectors for ICMP scans
        if context['packet_types']['ICMP'] >= 5:
            self._run_detectors(src_ip, context, packet)

    def _run_detectors(self, src_ip: str, context: dict, packet):
        """Run all detectors on the traffic from this IP"""
        # Calculate current metrics
        metrics = self._calculate_metrics(context)

        # Run each detector
        best_detection = None
        best_confidence = 0

        for detector in self.detectors:
            try:
                detection = detector.detect(src_ip, context, metrics, packet)
                if detection and detection['confidence'] > best_confidence:
                    best_detection = detection
                    best_confidence = detection['confidence']
            except Exception as e:
                print(f"❌ Detector {detector.__class__.__name__} error: {e}")

        # If attack detected, log it
        if best_detection and best_confidence >= 50:
            self._log_attack(src_ip, context, best_detection, packet)

    def _calculate_metrics(self, context: dict) -> dict:
        """Calculate traffic metrics for detection"""
        # Calculate packet rate (packets per second)
        packet_rate = 0
        if len(context['packet_times']) >= 2:
            time_span = context['packet_times'][-1] - context['packet_times'][0]
            if time_span > 0:
                packet_rate = len(context['packet_times']) / time_span

        # Calculate SYN rate
        syn_rate = 0
        if len(context['syn_packets']) >= 2:
            syn_times = [p['time'] for p in context['syn_packets']]
            time_span = syn_times[-1] - syn_times[0]
            if time_span > 0:
                syn_rate = len(context['syn_packets']) / time_span

        # Calculate port diversity
        port_diversity = len(context['ports_scanned'])

        # Recent ports scanned (last 10 seconds)
        current_time = time.time()
        recent_ports = set()
        for syn_pkt in context['syn_packets']:
            if current_time - syn_pkt['time'] <= 10:
                recent_ports.add(syn_pkt['port'])

        return {
            'packet_rate': packet_rate,
            'syn_rate': syn_rate,
            'port_diversity': port_diversity,
            'recent_ports_count': len(recent_ports),
            'total_packets': context['total_packets'],
            'syn_packets': len(context['syn_packets']),
            'packet_types': dict(context['packet_types'])
        }

    def _log_attack(self, src_ip: str, context: dict, detection: dict, packet):
        """Log detected attack to Kafka"""
        self.stats['attacks_detected'] += 1

        # Get packet details
        dst_ip = packet[IP].dst if packet.haslayer(IP) else 'unknown'
        dst_port = None
        protocol = 'unknown'

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            protocol = 'TCP'
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
            protocol = 'UDP'
        elif packet.haslayer(ICMP):
            protocol = 'ICMP'

        # Check cooldown to prevent flooding
        current_time = time.time()
        last_reported = context.get('last_reported', {})
        tool_name = detection['tool']
        
        # Cooldown of 60 seconds per tool per IP
        if current_time - last_reported.get(tool_name, 0) < 60:
            return

        # Update last reported time
        if 'last_reported' not in context:
            context['last_reported'] = {}
        context['last_reported'][tool_name] = current_time

        # Create log entry
        log_entry = {
            'type': 'network_scan',
            'timestamp': datetime.now().isoformat(),
            'source': 'network_monitor',
            'ip': src_ip,  # Add 'ip' field for compatibility
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': protocol,
            'attack_tool': detection['tool'],
            'attack_tool_info': {
                'tool': detection['tool'],
                'confidence': detection['confidence'],
                'method': detection['method'],
                'details': detection.get('details', {})
            },
            'attack_technique': detection.get('techniques', ['port_scan']),
            'log_category': 'attack',
            'metrics': self._calculate_metrics(context),
            'ports_scanned': list(context['ports_scanned'])[:100],  # Limit to 100
            'total_packets': context['total_packets']
        }
        
        # Add YARA matches if present
        if context.get('yara_matches'):
            log_entry['yara_matches'] = context['yara_matches'][-10:]  # Last 10 matches
            
        # Add deep analysis results if present
        if context.get('deep_analysis'):
            log_entry['deep_analysis'] = context['deep_analysis']
        
        # Trigger counter-reconnaissance for high-confidence attacks
        if self.nmap_scanner and detection['confidence'] >= 70:
            scan_queued = self.nmap_scanner.queue_scan(
                target_ip=src_ip,
                trigger_reason=f"{detection['tool']} attack",
                confidence=detection['confidence'],
                scan_type='version' if detection['confidence'] >= 85 else 'quick'
            )
            if scan_queued:
                self.stats['counter_scans'] += 1
                print(f"🎯 Counter-scan queued for {src_ip}")

        # Add to Kafka queue (non-blocking)
        try:
            self.kafka_queue.put_nowait(log_entry)
            print(f"🚨 Attack detected: {detection['tool']} from {src_ip} ({detection['confidence']}% confidence)")
        except queue.Full:
            print(f"⚠️  Kafka queue full, dropping log for {src_ip}")

    def _cleanup_old_contexts(self):
        """Remove old IP contexts to prevent memory leak"""
        current_time = datetime.now()
        to_remove = []

        for ip, context in self.ip_contexts.items():
            if context['last_seen']:
                time_diff = (current_time - context['last_seen']).total_seconds()
                if time_diff > 3600:  # Remove after 1 hour of inactivity
                    to_remove.append(ip)

        for ip in to_remove:
            del self.ip_contexts[ip]

        if to_remove:
            print(f"🧹 Cleaned up {len(to_remove)} old IP contexts")

    def _detect_interface(self) -> str:
        """
        Detect the best network interface to use for packet capture
        Tries multiple fallback strategies for Docker/host environments
        """
        from scapy.all import get_if_list, conf

        # Get list of available interfaces
        interfaces = get_if_list()
        print(f"📡 Available interfaces: {interfaces}")

        # Priority list of interfaces to try
        priority_interfaces = [
            'eth0',    # Common in Docker
            'ens33',   # Common in VMs
            'ens18',   # Common in Proxmox VMs
            'enp0s3',  # Common in VirtualBox
            'wlan0',   # WiFi
            'wlp',     # WiFi (new naming)
        ]

        # Try priority interfaces first
        for iface in priority_interfaces:
            if iface in interfaces:
                return iface

        # Try interfaces starting with 'eth', 'en', 'wl'
        for iface in interfaces:
            if iface.startswith(('eth', 'en', 'wl')) and iface != 'lo':
                return iface

        # Fallback to first non-loopback interface
        for iface in interfaces:
            if iface not in ['lo', 'lo0', 'any']:
                return iface

        # Last resort: use default
        return conf.iface

    def start(self):
        """Start packet sniffing"""
        print(f"\n{'='*60}")
        print(f"🚀 Starting Network Monitor Service")
        print(f"{'='*60}")
        print(f"📡 Interface: {self.interface}")
        print(f"🔌 Kafka: {self.kafka_bootstrap}")
        print(f"🔍 Detectors loaded: {len(self.detectors)}")

        # Initialize Kafka
        if not self.initialize_kafka():
            print("❌ Failed to initialize Kafka. Exiting.")
            sys.exit(1)
        
        # Start enhanced analyzers
        if self.pyshark_analyzer:
            self.pyshark_analyzer.start()
            print("✅ Pyshark deep analyzer started")
            
        if self.nmap_scanner:
            self.nmap_scanner.start()
            print("✅ Nmap counter-scanner started")

        self.running = True
        self.stats['start_time'] = datetime.now()

        # Disable Scapy verbose mode
        conf.verb = 0

        print(f"\n✅ Network monitor is running...")
        print(f"🎯 Monitoring for port scans, SYN scans, and network attacks")
        print(f"🔬 Deep analysis: {'enabled' if self.pyshark_analyzer else 'disabled'}")
        print(f"🔍 YARA matching: {'enabled' if self.yara_analyzer else 'disabled'}")
        print(f"🎯 Counter-recon: {'enabled' if self.nmap_scanner else 'disabled'}")
        print(f"⚡ Press Ctrl+C to stop\n")

        try:
            # Start sniffing packets
            # filter: only capture TCP, UDP, ICMP
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                filter="tcp or udp or icmp",
                store=False  # Don't store packets in memory
            )
        except KeyboardInterrupt:
            print("\n\n⚠️  Received interrupt signal, stopping...")
            self.stop()
        except Exception as e:
            print(f"\n\n❌ Fatal error: {e}")
            self.stop()

    def stop(self):
        """Stop packet sniffing and cleanup"""
        print(f"\n{'='*60}")
        print(f"🛑 Stopping Network Monitor Service")
        print(f"{'='*60}")

        self.running = False
        
        # Stop enhanced analyzers
        if self.pyshark_analyzer:
            self.pyshark_analyzer.stop()
            print("✅ Pyshark analyzer stopped")
            
        if self.nmap_scanner:
            self.nmap_scanner.stop()
            print("✅ Nmap scanner stopped")

        # Print stats
        if self.stats['start_time']:
            runtime = (datetime.now() - self.stats['start_time']).total_seconds()
            print(f"\n📊 Statistics:")
            print(f"   Runtime: {runtime:.1f} seconds")
            print(f"   Packets captured: {self.stats['packets_captured']}")
            print(f"   Attacks detected: {self.stats['attacks_detected']}")
            print(f"   YARA matches: {self.stats['yara_matches']}")
            print(f"   Deep analyses: {self.stats['deep_analyses']}")
            print(f"   Counter-scans: {self.stats['counter_scans']}")
            print(f"   IPs tracked: {len(self.ip_contexts)}")
            
            # Print YARA stats if available
            if self.yara_analyzer:
                yara_stats = self.yara_analyzer.get_stats()
                print(f"\n🔍 YARA Stats:")
                print(f"   Scans: {yara_stats['scans']}")
                print(f"   Matches: {yara_stats['matches']}")
                print(f"   Cache hits: {yara_stats['cache_hits']}")
                
            # Print Nmap stats if available
            if self.nmap_scanner:
                nmap_stats = self.nmap_scanner.get_stats()
                print(f"\n🎯 Nmap Scanner Stats:")
                print(f"   Scans completed: {nmap_stats['scans_completed']}")
                print(f"   Scans queued: {nmap_stats['scans_queued']}")
                print(f"   Scans skipped: {nmap_stats['scans_skipped']}")

        # Stop Kafka worker
        if self.kafka_worker:
            self.kafka_queue.put(None)  # Poison pill
            self.kafka_worker.join(timeout=2)

        # Close Kafka producer
        if self.kafka_producer:
            try:
                self.kafka_producer.close()
                print("✅ Kafka producer closed")
            except Exception as e:
                print(f"⚠️  Error closing Kafka producer: {e}")

        print(f"\n✅ Network monitor stopped successfully\n")


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Network Monitor for Honeypot')
    parser.add_argument('--interface', '-i', default='any',
                        help='Network interface to monitor (default: any)')
    parser.add_argument('--kafka', '-k', default='10.8.0.1:9093',
                        help='Kafka bootstrap server (default: 10.8.0.1:9093)')
    parser.add_argument('--no-pyshark', action='store_true',
                        help='Disable Pyshark deep packet analysis')
    parser.add_argument('--no-yara', action='store_true',
                        help='Disable YARA pattern matching')
    parser.add_argument('--no-nmap', action='store_true',
                        help='Disable Nmap counter-reconnaissance')

    args = parser.parse_args()

    # Check if running as root (required for packet capture)
    if os.geteuid() != 0:
        print("⚠️  WARNING: Not running as root. Packet capture may fail.")
        print("   Try: sudo python3 packet_sniffer.py")

    # Create and start sniffer
    sniffer = PacketSniffer(
        interface=args.interface, 
        kafka_bootstrap=args.kafka,
        enable_pyshark=not args.no_pyshark,
        enable_yara=not args.no_yara,
        enable_nmap_scanner=not args.no_nmap
    )
    sniffer.start()


if __name__ == '__main__':
    main()
