#!/usr/bin/env python3
"""
Simple Network Packet Capture and Analysis Tool
For testing purposes - simplified version
"""

import time
import threading
import logging
from datetime import datetime

class PacketCapture:
    def __init__(self, interface='any', log_file='logs/capture.log'):
        self.interface = interface
        self.log_file = log_file
        self.running = False
        self.capture_thread = None
        
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
        
        self.logger.info("Packet capture started (simulated)")
        
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join()
        self.logger.info("Packet capture stopped")
        
    def _capture_loop(self):
        """Simulated capture loop for testing"""
        self.logger.info(f"Simulating packet capture on interface: {self.interface}")
        
        # Simulate some packet processing
        packet_count = 0
        while self.running:
            try:
                time.sleep(1)
                packet_count += 1
                
                # Simulate packet statistics
                self.stats['total_packets'] += 1
                if packet_count % 3 == 0:
                    self.stats['tcp_packets'] += 1
                elif packet_count % 5 == 0:
                    self.stats['udp_packets'] += 1
                else:
                    self.stats['icmp_packets'] += 1
                
                # Simulate some suspicious activity
                if packet_count % 10 == 0:
                    self.stats['suspicious_packets'] += 1
                    self.logger.info(f"Simulated suspicious packet detected: #{packet_count}")
                
                if packet_count % 20 == 0:
                    self.stats['port_scans'] += 1
                    self.logger.info(f"Simulated port scan detected: #{packet_count}")
                    
            except Exception as e:
                self.logger.error(f"Error in capture loop: {e}")
                break
                
    def get_stats(self):
        """Get current statistics"""
        return self.stats.copy()

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Packet Capture Tool')
    parser.add_argument('--interface', '-i', default='any', help='Network interface to capture on')
    parser.add_argument('--log-file', '-l', default='logs/capture.log', help='Log file path')
    
    args = parser.parse_args()
    
    # Create logs directory
    import os
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