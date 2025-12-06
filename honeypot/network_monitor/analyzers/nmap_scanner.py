"""
Python-Nmap Active Scanner
Performs counter-reconnaissance against detected attackers
"""

import threading
import queue
import time
from typing import Optional, Dict, Any, List
from datetime import datetime

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("WARNING: python-nmap not installed. Active scanning disabled.")


class NmapScanner:
    """
    Active scanner for counter-reconnaissance against attackers
    
    Features:
    - Triggered only for high-confidence attacks
    - Service version detection
    - OS fingerprinting
    - Rate-limited to avoid overwhelming
    - Results logged for analysis
    """
    
    def __init__(self, enabled: bool = True, rate_limit: int = 5):
        """
        Initialize Nmap scanner
        
        Args:
            enabled: Whether scanner is enabled
            rate_limit: Max scans per minute
        """
        self.enabled = enabled and NMAP_AVAILABLE
        self.rate_limit = rate_limit
        self.scanner = None
        
        # Scan queue and worker
        self.scan_queue = queue.Queue(maxsize=50)
        self._stop_event = threading.Event()
        self._worker_thread = None
        
        # Track scanned IPs to avoid duplicates
        self.scanned_ips = {}  # IP -> last_scan_time
        self.scan_cooldown = 3600  # 1 hour between rescans
        
        # Results storage
        self.results = {}
        
        # Stats
        self.stats = {
            'scans_completed': 0,
            'scans_queued': 0,
            'scans_skipped': 0,
            'errors': 0
        }
        
        # Rate limiting
        self._scan_times = []
        self._rate_lock = threading.Lock()
        
        if self.enabled:
            try:
                self.scanner = nmap.PortScanner()
                print("Nmap scanner initialized")
            except nmap.PortScannerError as e:
                print(f"Nmap not found: {e}")
                self.enabled = False
                
    def start(self):
        """Start the scanner worker thread"""
        if not self.enabled:
            print("Nmap scanner disabled")
            return
            
        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._scan_worker,
            daemon=True,
            name="NmapScanner"
        )
        self._worker_thread.start()
        print("Nmap scanner worker started")
        
    def stop(self):
        """Stop the scanner"""
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=30)
            
    def queue_scan(self, target_ip: str, trigger_reason: str, 
                   confidence: int = 0, scan_type: str = 'quick') -> bool:
        """
        Queue an IP for scanning
        
        Args:
            target_ip: IP address to scan
            trigger_reason: Why scan was triggered
            confidence: Attack confidence score (0-100)
            scan_type: 'quick', 'version', or 'comprehensive'
            
        Returns:
            True if queued, False if skipped
        """
        if not self.enabled:
            return False
            
        # Skip private/local IPs
        if self._is_private_ip(target_ip):
            self.stats['scans_skipped'] += 1
            return False
            
        # Check cooldown
        if target_ip in self.scanned_ips:
            last_scan = self.scanned_ips[target_ip]
            if time.time() - last_scan < self.scan_cooldown:
                self.stats['scans_skipped'] += 1
                return False
                
        # Only scan high-confidence attacks
        if confidence < 70:
            self.stats['scans_skipped'] += 1
            return False
            
        # Check rate limit
        if not self._check_rate_limit():
            self.stats['scans_skipped'] += 1
            return False
            
        try:
            self.scan_queue.put_nowait({
                'target': target_ip,
                'reason': trigger_reason,
                'confidence': confidence,
                'scan_type': scan_type,
                'queued_at': time.time()
            })
            self.stats['scans_queued'] += 1
            return True
        except queue.Full:
            self.stats['scans_skipped'] += 1
            return False
            
    def _scan_worker(self):
        """Background worker that performs scans"""
        while not self._stop_event.is_set():
            try:
                scan_request = self.scan_queue.get(timeout=5)
                target = scan_request['target']
                scan_type = scan_request['scan_type']
                
                print(f"Scanning attacker: {target} ({scan_request['reason']})")
                
                result = self._perform_scan(target, scan_type)
                
                if result:
                    self.results[target] = result
                    self.scanned_ips[target] = time.time()
                    self.stats['scans_completed'] += 1
                    
            except queue.Empty:
                continue
            except Exception as e:
                self.stats['errors'] += 1
                print(f"Scan error: {e}")
                
    def _perform_scan(self, target: str, scan_type: str) -> Optional[Dict[str, Any]]:
        """
        Perform the actual nmap scan
        
        Args:
            target: IP to scan
            scan_type: Type of scan to perform
            
        Returns:
            Scan results
        """
        try:
            # Build scan arguments based on type
            if scan_type == 'quick':
                # Quick scan - top 100 ports
                arguments = '-sS -T4 --top-ports 100'
            elif scan_type == 'version':
                # Version detection
                arguments = '-sV -sC -T4 --top-ports 1000'
            else:
                # Comprehensive scan
                arguments = '-sV -sC -O -T4 --top-ports 1000'
                
            # Perform scan
            self.scanner.scan(hosts=target, arguments=arguments)
            
            if target not in self.scanner.all_hosts():
                return None
                
            host_info = self.scanner[target]
            
            result = {
                'ip': target,
                'scan_time': datetime.now().isoformat(),
                'scan_type': scan_type,
                'state': host_info.state(),
                'hostnames': host_info.hostnames(),
                'open_ports': [],
                'os_info': None,
                'raw_data': {}
            }
            
            # Extract open ports
            for proto in host_info.all_protocols():
                for port in host_info[proto].keys():
                    port_info = host_info[proto][port]
                    if port_info['state'] == 'open':
                        result['open_ports'].append({
                            'port': port,
                            'protocol': proto,
                            'service': port_info.get('name', 'unknown'),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        })
                        
            # Extract OS info if available
            if 'osmatch' in host_info:
                os_matches = host_info['osmatch']
                if os_matches:
                    result['os_info'] = {
                        'name': os_matches[0].get('name', 'Unknown'),
                        'accuracy': os_matches[0].get('accuracy', 0),
                        'family': os_matches[0].get('osclass', [{}])[0].get('osfamily', '')
                    }
                    
            # Store some raw data
            result['raw_data'] = {
                'protocols': list(host_info.all_protocols()),
                'total_ports_scanned': sum(len(host_info[p]) for p in host_info.all_protocols())
            }
            
            return result
            
        except nmap.PortScannerError as e:
            print(f"Nmap scan error for {target}: {e}")
            self.stats['errors'] += 1
            return None
        except Exception as e:
            print(f"Unexpected scan error for {target}: {e}")
            self.stats['errors'] += 1
            return None
            
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        parts = ip.split('.')
        if len(parts) != 4:
            return True
            
        try:
            first = int(parts[0])
            second = int(parts[1])
            
            # Private ranges
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
            if first == 0:
                return True
                
        except ValueError:
            return True
            
        return False
        
    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limit"""
        now = time.time()
        with self._rate_lock:
            # Remove old entries
            self._scan_times = [t for t in self._scan_times if now - t < 60]
            
            if len(self._scan_times) >= self.rate_limit:
                return False
                
            self._scan_times.append(now)
            return True
            
    def get_result(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get scan result for an IP"""
        return self.results.get(ip)
        
    def get_all_results(self) -> Dict[str, Any]:
        """Get all scan results"""
        return dict(self.results)
        
    def get_stats(self) -> Dict[str, int]:
        """Get scanning statistics"""
        return dict(self.stats)
        
    def scan_now(self, target: str, scan_type: str = 'quick') -> Optional[Dict[str, Any]]:
        """
        Perform a synchronous scan (blocking)
        
        Args:
            target: IP to scan
            scan_type: Type of scan
            
        Returns:
            Scan results
        """
        if not self.enabled:
            return None
            
        if self._is_private_ip(target):
            return None
            
        return self._perform_scan(target, scan_type)
