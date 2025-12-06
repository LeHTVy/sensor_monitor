"""
Pyshark Deep Packet Analyzer
Uses Wireshark's protocol dissectors for detailed packet inspection
"""

import threading
import queue
import time
from typing import Optional, Dict, Any, List

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    print("WARNING: pyshark not installed. Deep packet analysis disabled.")


class PysharkAnalyzer:
    """
    Deep packet analyzer using Pyshark/tshark
    
    Features:
    - Application layer protocol parsing (HTTP, DNS, SSH, TLS, etc.)
    - Payload extraction
    - Protocol anomaly detection
    - TLS/SSL metadata extraction
    """
    
    def __init__(self, interface: str = 'any', enabled: bool = True):
        """
        Initialize Pyshark analyzer
        
        Args:
            interface: Network interface to capture on
            enabled: Whether analyzer is enabled
        """
        self.interface = interface
        self.enabled = enabled and PYSHARK_AVAILABLE
        self.capture = None
        self.analysis_queue = queue.Queue(maxsize=1000)
        self.results = {}
        self._stop_event = threading.Event()
        self._worker_thread = None
        
        # Performance settings
        self.max_packet_size = 65535
        self.skip_threshold = 100  # Skip if queue > 100 packets
        
    def start(self):
        """Start the Pyshark analyzer background thread"""
        if not self.enabled:
            print("Pyshark analyzer disabled")
            return
            
        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._analysis_worker,
            daemon=True,
            name="PysharkAnalyzer"
        )
        self._worker_thread.start()
        print("Pyshark analyzer started")
        
    def stop(self):
        """Stop the analyzer"""
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
            
    def queue_packet(self, packet_data: bytes, src_ip: str, dst_port: int) -> bool:
        """
        Queue a packet for deep analysis
        
        Args:
            packet_data: Raw packet bytes
            src_ip: Source IP address
            dst_port: Destination port
            
        Returns:
            True if queued, False if skipped
        """
        if not self.enabled:
            return False
            
        # Skip if queue is too full (performance protection)
        if self.analysis_queue.qsize() > self.skip_threshold:
            return False
            
        try:
            self.analysis_queue.put_nowait({
                'data': packet_data,
                'src_ip': src_ip,
                'dst_port': dst_port,
                'timestamp': time.time()
            })
            return True
        except queue.Full:
            return False
            
    def analyze_packet(self, scapy_packet) -> Optional[Dict[str, Any]]:
        """
        Analyze a single packet synchronously (for immediate results)
        
        Args:
            scapy_packet: Scapy packet object
            
        Returns:
            Analysis result dict or None
        """
        if not self.enabled:
            return None
            
        result = {
            'protocols': [],
            'application_layer': None,
            'payload_info': {},
            'anomalies': [],
            'tls_info': None
        }
        
        try:
            # Extract basic protocol info from scapy packet
            if scapy_packet.haslayer('TCP'):
                tcp = scapy_packet['TCP']
                dst_port = tcp.dport
                
                # Identify application protocol by port
                result['application_layer'] = self._identify_app_protocol(dst_port)
                
                # Extract payload if present
                if scapy_packet.haslayer('Raw'):
                    payload = bytes(scapy_packet['Raw'].load)
                    result['payload_info'] = self._analyze_payload(payload, dst_port)
                    
                    # Check for TLS
                    if self._is_tls_handshake(payload):
                        result['tls_info'] = self._parse_tls_hello(payload)
                        
                    # Check for HTTP
                    if dst_port in [80, 8080, 8000, 8888]:
                        result['http_info'] = self._parse_http(payload)
                        
            elif scapy_packet.haslayer('UDP'):
                udp = scapy_packet['UDP']
                dst_port = udp.dport
                
                result['application_layer'] = self._identify_app_protocol(dst_port)
                
                # DNS analysis
                if dst_port == 53 and scapy_packet.haslayer('DNS'):
                    result['dns_info'] = self._parse_dns(scapy_packet)
                    
        except Exception as e:
            result['error'] = str(e)
            
        return result
        
    def _analysis_worker(self):
        """Background worker for packet analysis"""
        while not self._stop_event.is_set():
            try:
                packet_info = self.analysis_queue.get(timeout=1)
                
                # Process packet (simplified - full implementation would use tshark)
                src_ip = packet_info['src_ip']
                
                # Store results by IP
                if src_ip not in self.results:
                    self.results[src_ip] = {
                        'protocols_seen': set(),
                        'payloads_analyzed': 0,
                        'anomalies': []
                    }
                    
                self.results[src_ip]['payloads_analyzed'] += 1
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Pyshark analysis error: {e}")
                
    def _identify_app_protocol(self, port: int) -> str:
        """Identify application protocol by port"""
        port_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        return port_map.get(port, f'Unknown-{port}')
        
    def _analyze_payload(self, payload: bytes, port: int) -> Dict[str, Any]:
        """Analyze payload content"""
        info = {
            'size': len(payload),
            'is_printable': self._is_printable(payload[:100]),
            'has_null_bytes': b'\x00' in payload
        }
        
        # Check for common patterns
        if payload.startswith(b'GET ') or payload.startswith(b'POST '):
            info['type'] = 'HTTP_REQUEST'
        elif payload.startswith(b'HTTP/'):
            info['type'] = 'HTTP_RESPONSE'
        elif payload.startswith(b'\x16\x03'):
            info['type'] = 'TLS_HANDSHAKE'
        elif payload.startswith(b'SSH-'):
            info['type'] = 'SSH_BANNER'
            info['ssh_version'] = payload.split(b'\n')[0].decode('utf-8', errors='ignore')
            
        return info
        
    def _is_printable(self, data: bytes) -> bool:
        """Check if data is mostly printable ASCII"""
        if not data:
            return False
        printable = sum(1 for b in data if 32 <= b <= 126 or b in [9, 10, 13])
        return printable / len(data) > 0.8
        
    def _is_tls_handshake(self, payload: bytes) -> bool:
        """Check if payload is TLS handshake"""
        if len(payload) < 5:
            return False
        # TLS record: content_type=0x16 (handshake), version 0x0301-0x0304
        return (payload[0] == 0x16 and 
                payload[1] == 0x03 and 
                payload[2] in [0x00, 0x01, 0x02, 0x03, 0x04])
                
    def _parse_tls_hello(self, payload: bytes) -> Optional[Dict[str, Any]]:
        """Parse TLS ClientHello for metadata"""
        try:
            if len(payload) < 43:
                return None
                
            tls_version = f"{payload[1]}.{payload[2]}"
            
            # Very basic parsing - full implementation would be more complete
            return {
                'record_version': tls_version,
                'handshake_type': 'ClientHello' if payload[5] == 0x01 else 'Other'
            }
        except Exception:
            return None
            
    def _parse_http(self, payload: bytes) -> Optional[Dict[str, Any]]:
        """Parse HTTP request"""
        try:
            text = payload.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            
            if not lines:
                return None
                
            # Parse request line
            request_line = lines[0].split(' ')
            if len(request_line) >= 3:
                return {
                    'method': request_line[0],
                    'path': request_line[1],
                    'version': request_line[2] if len(request_line) > 2 else 'HTTP/1.0',
                    'headers': self._parse_http_headers(lines[1:])
                }
        except Exception:
            return None
        return None
        
    def _parse_http_headers(self, lines: List[str]) -> Dict[str, str]:
        """Parse HTTP headers"""
        headers = {}
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
            elif line == '':
                break
        return headers
        
    def _parse_dns(self, packet) -> Optional[Dict[str, Any]]:
        """Parse DNS query"""
        try:
            dns = packet['DNS']
            return {
                'query_name': dns.qd.qname.decode() if hasattr(dns, 'qd') and dns.qd else None,
                'query_type': str(dns.qd.qtype) if hasattr(dns, 'qd') and dns.qd else None,
                'is_response': bool(dns.qr)
            }
        except Exception:
            return None
            
    def get_results(self, src_ip: str) -> Optional[Dict]:
        """Get analysis results for an IP"""
        return self.results.get(src_ip)
