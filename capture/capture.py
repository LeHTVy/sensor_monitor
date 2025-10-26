#!/usr/bin/env python3
"""
Packet Capture and Analysis
Captures network packets and detects attack patterns
"""

import os
import json
import time
import threading
from datetime import datetime
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
import psutil
import netaddr

class PacketCapture:
    def __init__(self, target_ip="172.232.246.68", log_dir="/app/logs"):
        self.target_ip = target_ip
        self.log_dir = log_dir
        self.packets_log = os.path.join(log_dir, "packets", "captured_packets.log")
        self.analysis_log = os.path.join(log_dir, "analysis", "attack_analysis.log")
        
        # Create directories
        os.makedirs(os.path.dirname(self.packets_log), exist_ok=True)
        os.makedirs(os.path.dirname(self.analysis_log), exist_ok=True)
        
        # Attack detection patterns
        self.nmap_signatures = [
            "nmap", "masscan", "zmap", "unicornscan"
        ]
        
        self.metasploit_signatures = [
            "meterpreter", "payload", "exploit", "msfconsole"
        ]
        
        self.telnet_signatures = [
            "telnet", "login:", "password:", "username:"
        ]
        
        self.port_scan_ports = [
            22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900
        ]
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'nmap_detections': 0,
            'telnet_detections': 0,
            'metasploit_detections': 0,
            'port_scan_detections': 0,
            'suspicious_ips': set(),
            'start_time': datetime.now().isoformat()
        }
        
        self.running = False
        self.capture_thread = None
    
    def start_capture(self):
        """Start packet capture in background thread"""
        if self.running:
            return
        
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        print(f"Packet capture started for target IP: {self.target_ip}")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join()
        print("Packet capture stopped")
    
    def _capture_loop(self):
        """Main capture loop"""
        try:
            # Capture packets targeting our IP
            sniff(
                filter=f"host {self.target_ip}",
                prn=self._process_packet,
                stop_filter=lambda x: not self.running,
                store=0
            )
        except Exception as e:
            print(f"Error in capture loop: {e}")
            self.log_error(f"Capture loop error: {str(e)}")
    
    def _process_packet(self, packet):
        """Process captured packet"""
        try:
            self.stats['total_packets'] += 1
            
            # Extract packet information
            packet_info = self._extract_packet_info(packet)
            
            # Log packet
            self._log_packet(packet_info)
            
            # Analyze for attacks
            attack_type = self._analyze_packet(packet_info)
            
            if attack_type:
                self._log_attack(packet_info, attack_type)
                
        except Exception as e:
            self.log_error(f"Error processing packet: {str(e)}")
    
    def _extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        info = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None,
            'payload': None,
            'size': len(packet)
        }
        
        # IP layer
        if IP in packet:
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['protocol'] = packet[IP].proto
        
        # TCP layer
        if TCP in packet:
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
            if packet[TCP].payload:
                info['payload'] = str(packet[TCP].payload)
        
        # UDP layer
        elif UDP in packet:
            info['src_port'] = packet[UDP].sport
            info['dst_port'] = packet[UDP].dport
            if packet[UDP].payload:
                info['payload'] = str(packet[UDP].payload)
        
        # ICMP layer
        elif ICMP in packet:
            info['protocol'] = 'ICMP'
            if packet[ICMP].payload:
                info['payload'] = str(packet[ICMP].payload)
        
        return info
    
    def _analyze_packet(self, packet_info):
        """Analyze packet for attack patterns"""
        attack_type = None
        
        # Check for Nmap signatures
        if self._detect_nmap(packet_info):
            attack_type = 'nmap_scan'
            self.stats['nmap_detections'] += 1
        
        # Check for Telnet attempts
        elif self._detect_telnet(packet_info):
            attack_type = 'telnet_attempt'
            self.stats['telnet_detections'] += 1
        
        # Check for Metasploit signatures
        elif self._detect_metasploit(packet_info):
            attack_type = 'metasploit_payload'
            self.stats['metasploit_detections'] += 1
        
        # Check for port scanning
        elif self._detect_port_scan(packet_info):
            attack_type = 'port_scan'
            self.stats['port_scan_detections'] += 1
        
        # Check for suspicious activity
        elif self._detect_suspicious(packet_info):
            attack_type = 'suspicious_activity'
        
        if attack_type and packet_info['src_ip']:
            self.stats['suspicious_ips'].add(packet_info['src_ip'])
        
        return attack_type
    
    def _detect_nmap(self, packet_info):
        """Detect Nmap scanning patterns"""
        if not packet_info['payload']:
            return False
        
        payload_lower = packet_info['payload'].lower()
        
        # Check for Nmap signatures in payload
        for signature in self.nmap_signatures:
            if signature in payload_lower:
                return True
        
        # Check for Nmap-specific TCP flags (SYN scan)
        if packet_info['protocol'] == 'TCP' and packet_info['dst_port']:
            # Look for rapid sequential port scans
            if packet_info['dst_port'] in self.port_scan_ports:
                return True
        
        return False
    
    def _detect_telnet(self, packet_info):
        """Detect Telnet connection attempts"""
        if not packet_info['payload']:
            return False
        
        payload_lower = packet_info['payload'].lower()
        
        # Check for Telnet signatures
        for signature in self.telnet_signatures:
            if signature in payload_lower:
                return True
        
        # Check for Telnet port (23)
        if packet_info['dst_port'] == 23:
            return True
        
        return False
    
    def _detect_metasploit(self, packet_info):
        """Detect Metasploit payloads"""
        if not packet_info['payload']:
            return False
        
        payload_lower = packet_info['payload'].lower()
        
        # Check for Metasploit signatures
        for signature in self.metasploit_signatures:
            if signature in payload_lower:
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
            'union select', 'drop table', 'delete from',
            'script>', '<iframe', 'javascript:', 'onload='
        ]
        
        for pattern in suspicious_patterns:
            if pattern in payload_lower:
                return True
        
        return False
    
    def _log_packet(self, packet_info):
        """Log packet information"""
        try:
            with open(self.packets_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(packet_info, ensure_ascii=False) + '\n')
        except Exception as e:
            self.log_error(f"Error logging packet: {str(e)}")
    
    def _log_attack(self, packet_info, attack_type):
        """Log attack detection"""
        try:
            attack_data = {
                'timestamp': packet_info['timestamp'],
                'attack_type': attack_type,
                'src_ip': packet_info['src_ip'],
                'dst_ip': packet_info['dst_ip'],
                'src_port': packet_info['src_port'],
                'dst_port': packet_info['dst_port'],
                'protocol': packet_info['protocol'],
                'payload': packet_info['payload'],
                'size': packet_info['size'],
                'severity': self._get_attack_severity(attack_type)
            }
            
            with open(self.analysis_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(attack_data, ensure_ascii=False) + '\n')
            
            print(f"ATTACK DETECTED: {attack_type} from {packet_info['src_ip']}")
            
        except Exception as e:
            self.log_error(f"Error logging attack: {str(e)}")
    
    def _get_attack_severity(self, attack_type):
        """Get severity level for attack type"""
        severity_map = {
            'nmap_scan': 'medium',
            'telnet_attempt': 'high',
            'metasploit_payload': 'critical',
            'port_scan': 'medium',
            'suspicious_activity': 'low'
        }
        return severity_map.get(attack_type, 'unknown')
    
    def log_error(self, error_message):
        """Log error messages"""
        try:
            error_log = os.path.join(self.log_dir, "errors.log")
            error_entry = {
                'timestamp': datetime.now().isoformat(),
                'error': error_message
            }
            
            with open(error_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(error_entry, ensure_ascii=False) + '\n')
                
        except Exception as e:
            print(f"Critical error in logger: {str(e)}")
    
    def get_stats(self):
        """Get capture statistics"""
        self.stats['suspicious_ips'] = list(self.stats['suspicious_ips'])
        self.stats['uptime'] = (datetime.now() - datetime.fromisoformat(self.stats['start_time'])).total_seconds()
        return self.stats
    
    def get_recent_attacks(self, limit=100):
        """Get recent attack logs"""
        try:
            attacks = []
            if os.path.exists(self.analysis_log):
                with open(self.analysis_log, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for line in lines[-limit:]:
                        try:
                            attacks.append(json.loads(line.strip()))
                        except json.JSONDecodeError:
                            continue
            return attacks
        except Exception as e:
            self.log_error(f"Error reading attack logs: {str(e)}")
            return []

def main():
    """Main function"""
    print("Starting Packet Capture System...")
    
    # Create capture instance
    capture = PacketCapture()
    
    try:
        # Start capture
        capture.start_capture()
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
        capture.stop_capture()
    except Exception as e:
        print(f"Error: {e}")
        capture.stop_capture()

if __name__ == "__main__":
    main()
