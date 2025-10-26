#!/usr/bin/env python3
"""
Network Packet Capture and Analysis Tool
Captures network packets and analyzes them for suspicious activity
"""

import time
import threading
import queue
import logging
from datetime import datetime
from collections import defaultdict, deque
import socket
import struct
import json
import os

class PacketCapture:
    def __init__(self, interface='any', log_file='logs/capture.log'):
        self.interface = interface
        self.log_file = log_file
        self.running = False
        self.capture_thread = None
        self.log_queue = queue.Queue()
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'suspicious_packets': 0,
            'port_scans': 0,
            'start_time': datetime.now().isoformat()
        }
        
        # Detection patterns
        self.port_scan_ports = {
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995,
            1723, 3389, 5900, 8080, 8443, 8888, 9090, 9999
        }
        
        self.nmap_signatures = [
            'nmap', 'masscan', 'zmap', 'unicornscan', 'amap',
            'nmap-', 'masscan-', 'zmap-', 'unicornscan-'
        ]
        
        # Recent connections for rate limiting detection
        self.recent_connections = deque(maxlen=1000)
        self.connection_rates = defaultdict(int)
        
        # Setup logging
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def start_capture(self):
        """Start packet capture in a separate thread"""
        if self.running:
            return
            
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        # Start log processing thread
        self.log_thread = threading.Thread(target=self._process_logs)
        self.log_thread.daemon = True
        self.log_thread.start()
        
        self.logger.info("Packet capture started")
        
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join()
        if self.log_thread:
            self.log_thread.join()
        self.logger.info("Packet capture stopped")
        
    def _capture_loop(self):
        """Main capture loop - simulated for testing"""
        try:
            self.logger.info(f"Capturing on interface: {self.interface}")
            
            # Simulate packet capture for testing
            packet_count = 0
            while self.running:
                try:
                    time.sleep(1)
                    packet_count += 1
                    
                    # Simulate packet processing
                    packet_info = {
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': f'192.168.1.{100 + (packet_count % 50)}',
                        'dst_ip': '172.232.246.68',
                        'protocol': 'TCP' if packet_count % 3 == 0 else 'UDP',
                        'src_port': 10000 + (packet_count % 1000),
                        'dst_port': 22 if packet_count % 5 == 0 else 80,
                        'payload': f'Simulated packet #{packet_count}',
                        'flags': 2 if packet_count % 3 == 0 else 0,
                        'size': 64 + (packet_count % 100)
                    }
                    
                    # Update statistics
                    self.stats['total_packets'] += 1
                    if packet_info['protocol'] == 'TCP':
                        self.stats['tcp_packets'] += 1
                    elif packet_info['protocol'] == 'UDP':
                        self.stats['udp_packets'] += 1
                    else:
                        self.stats['icmp_packets'] += 1
                    
                    # Check for suspicious activity
                    if self._is_suspicious(packet_info):
                        self.stats['suspicious_packets'] += 1
                        self._log_suspicious_activity(packet_info)
                    
                    # Simulate port scans
                    if packet_count % 20 == 0:
                        self.stats['port_scans'] += 1
                        self.logger.info(f"Simulated port scan detected: #{packet_count}")
                    
                except Exception as e:
                    self.logger.error(f"Error processing packet: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error in capture loop: {e}")
                
    def _is_suspicious(self, packet_info):
        """Check if packet is suspicious"""
        # Check for port scans
        if self._detect_port_scan(packet_info):
            self.stats['port_scans'] += 1
            return True
            
        # Check for other suspicious patterns
        if self._detect_suspicious(packet_info):
            return True
            
        return False
        
    def _detect_port_scan(self, packet_info):
        """Detect port scanning activity"""
        if not packet_info['dst_port']:
            return False
            
        # Check if destination port is in common scan targets
        if packet_info['dst_port'] in self.port_scan_ports:
            return True
            
        return False
        
    def _detect_suspicious(self, packet_info):
        """Detect other suspicious activity"""
        if not packet_info['payload']:
            return False
            
        payload_lower = packet_info['payload'].lower()
        
        # Check for common attack patterns
        suspicious_patterns = [
            'admin', 'root', 'password', 'login', 'shell',
            'cmd', 'exec', 'system', 'eval', 'phpinfo',
            'union select', 'drop table', 'insert into',
            'script>', '<iframe', 'javascript:', 'vbscript:',
            'onload=', 'onerror=', 'onclick=', 'onmouseover='
        ]
        
        for pattern in suspicious_patterns:
            if pattern in payload_lower:
                return True
                
        # Check for Nmap signatures
        for signature in self.nmap_signatures:
            if signature in payload_lower:
                return True
                
        return False
        
    def _log_suspicious_activity(self, packet_info):
        """Log suspicious activity"""
        log_entry = {
            'type': 'suspicious',
            'timestamp': packet_info['timestamp'],
            'src_ip': packet_info['src_ip'],
            'dst_ip': packet_info['dst_ip'],
            'protocol': packet_info['protocol'],
            'src_port': packet_info['src_port'],
            'dst_port': packet_info['dst_port'],
            'flags': packet_info['flags'],
            'payload': packet_info['payload'][:500] if packet_info['payload'] else None,
            'size': packet_info['size']
        }
        
        self.log_queue.put(log_entry)
        
    def _process_logs(self):
        """Process log entries from queue"""
        while self.running:
            try:
                log_entry = self.log_queue.get(timeout=1)
                if log_entry:
                    self.logger.info(f"Suspicious activity: {json.dumps(log_entry)}")
                    self.log_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing log: {e}")
                
    def get_stats(self):
        """Get current statistics"""
        return self.stats.copy()
        
    def get_recent_logs(self, limit=100):
        """Get recent log entries"""
        logs = []
        while not self.log_queue.empty() and len(logs) < limit:
            try:
                log_entry = self.log_queue.get_nowait()
                logs.append(log_entry)
                self.log_queue.task_done()
            except queue.Empty:
                break
        return logs

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Packet Capture Tool')
    parser.add_argument('--interface', '-i', default='any', help='Network interface to capture on')
    parser.add_argument('--log-file', '-l', default='logs/capture.log', help='Log file path')
    
    args = parser.parse_args()
    
    # Create logs directory
    os.makedirs(os.path.dirname(args.log_file), exist_ok=True)
    
    # Create and start capture
    capture = PacketCapture(interface=args.interface, log_file=args.log_file)
    
    try:
        capture.start_capture()
        print("Packet capture started. Press Ctrl+C to stop.")
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
        capture.stop_capture()
        print("Packet capture stopped.")

if __name__ == "__main__":
    main()