#!/usr/bin/env python3
"""
Reconnaissance Service - Black Box Security Scanning
Orchestrates nmap, amass, subfinder, and bbot scans against attacker IPs
"""

import os
import subprocess
import json
import uuid
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional
import xml.etree.ElementTree as ET
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NmapScanner:
    """Wrapper for nmap reconnaissance operations"""
    
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.results = {}
    
    def host_discovery(self, timeout: int = 1800) -> Dict:
        """Perform host discovery (ping scan)"""
        logger.info(f"[Nmap] Starting host discovery for {self.target_ip}")
        
        try:
            # Run nmap ping scan with -Pn to skip traditional ping (often blocked)
            cmd = ['nmap', '-Pn', '-sn', '-oX', '-', self.target_ip]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0:
                return {
                    'status': 'failed',
                    'error': result.stderr,
                    'output': result.stdout
                }
            
            # Parse XML output
            host_up = 'Host is up' in result.stdout or '<status state="up"' in result.stdout
            
            return {
                'status': 'completed',
                'host_up': host_up,
                'output': result.stdout,
                'raw_output': result.stdout
            }
            
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'error': f'Host discovery timed out after {timeout}s'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def port_scan(self, timeout: int = 1800) -> Dict:
        """Perform comprehensive port scan"""
        logger.info(f"[Nmap] Starting port scan for {self.target_ip}")
        
        try:
            # Run nmap with version detection
            # -Pn: Skip host discovery (treat host as up even if ping blocked)
            # -sS: SYN stealth scan
            # -sV: Service version detection
            # --top-ports 1000: Scan top 1000 most common ports (faster than -p-)
            cmd = ['nmap', '-Pn', '-sS', '-sV', '--top-ports', '1000', '-oX', '-', self.target_ip]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0:
                return {
                    'status': 'failed',
                    'error': result.stderr,
                    'output': result.stdout
                }
            
            # Parse XML output
            parsed_results = self._parse_nmap_xml(result.stdout)
            
            return {
                'status': 'completed',
                'open_ports': parsed_results.get('ports', []),
                'services': parsed_results.get('services', []),
                'os_info': parsed_results.get('os_info', {}),
                'output': result.stdout,
                'raw_xml': result.stdout
            }
            
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'error': f'Port scan timed out after {timeout}s'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def service_detection(self, ports: List[int] = None, timeout: int = 1800) -> Dict:
        """Perform detailed service version detection on specific ports"""
        logger.info(f"[Nmap] Starting service detection for {self.target_ip}")
        
        try:
            # If specific ports provided, scan only those
            port_arg = ','.join(map(str, ports)) if ports else '-p-'
            
            cmd = ['nmap', '-sV', '--version-intensity', '9', '-p', port_arg, '-oX', '-', self.target_ip]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0:
                return {
                    'status': 'failed',
                    'error': result.stderr,
                    'output': result.stdout
                }
            
            parsed_results = self._parse_nmap_xml(result.stdout)
            
            return {
                'status': 'completed',
                'services': parsed_results.get('services', []),
                'output': result.stdout
            }
            
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'error': f'Service detection timed out after {timeout}s'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def os_fingerprinting(self, timeout: int = 1800) -> Dict:
        """Perform OS fingerprinting"""
        logger.info(f"[Nmap] Starting OS fingerprinting for {self.target_ip}")
        
        try:
            # Requires root/sudo privileges
            cmd = ['nmap', '-O', '--osscan-guess', '-oX', '-', self.target_ip]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # OS detection may fail without error, check output
            parsed_results = self._parse_nmap_xml(result.stdout)
            
            return {
                'status': 'completed',
                'os_matches': parsed_results.get('os_info', {}).get('matches', []),
                'output': result.stdout
            }
            
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'error': f'OS fingerprinting timed out after {timeout}s'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict:
        """Parse nmap XML output into structured data"""
        try:
            root = ET.fromstring(xml_output)
            
            results = {
                'ports': [],
                'services': [],
                'os_info': {'matches': []}
            }
            
            # Parse ports and services
            for host in root.findall('host'):
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    state = port.find('state')
                    service = port.find('service')
                    
                    port_info = {
                        'port': int(port_id),
                        'protocol': protocol,
                        'state': state.get('state') if state is not None else 'unknown'
                    }
                    
                    if service is not None:
                        service_info = {
                            'port': int(port_id),
                            'name': service.get('name', 'unknown'),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extrainfo': service.get('extrainfo', ''),
                            'cpe': service.get('cpe', '')
                        }
                        results['services'].append(service_info)
                        port_info['service'] = service.get('name', 'unknown')
                    
                    results['ports'].append(port_info)
                
                # Parse OS detection
                for osmatch in host.findall('.//osmatch'):
                    os_info = {
                        'name': osmatch.get('name'),
                        'accuracy': osmatch.get('accuracy'),
                        'line': osmatch.get('line', '')
                    }
                    results['os_info']['matches'].append(os_info)
            
            return results
            
        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap XML: {e}")
            return {'ports': [], 'services': [], 'os_info': {'matches': []}}


class AmassScanner:
    """Wrapper for OWASP Amass subdomain enumeration"""
    
    def __init__(self, target: str):
        self.target = target
    
    def enumerate_subdomains(self, timeout: int = 1800) -> Dict:
        """Enumerate subdomains using amass in passive mode"""
        logger.info(f"[Amass] Starting passive subdomain enumeration for {self.target}")
        
        try:
            # Run amass enum with passive mode (no direct DNS queries)
            # -passive: Only use passive data sources (fastest)
            # -timeout: Limit execution time in minutes
            # -silent: Suppress informational messages
            timeout_minutes = max(1, timeout // 60)  # Convert seconds to minutes
            
            cmd = [
                'amass', 'enum',
                '-passive',                    # Passive only (no active probing)
                '-d', self.target,
                '-timeout', str(timeout_minutes),  # Timeout in minutes
                '-silent'                      # Suppress info messages
            ]
            
            logger.info(f"[Amass] Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30  # Give extra buffer beyond internal timeout
            )
            
            logger.info(f"[Amass] Completed with return code: {result.returncode}")
            
            # Parse text output (one subdomain per line in silent mode)
            subdomains = []
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and '.' in line:
                    subdomains.append(line)
            
            # Deduplicate
            subdomains = list(set(subdomains))
            
            return {
                'status': 'completed',
                'subdomains': subdomains,
                'count': len(subdomains),
                'output': result.stdout[:2000] if result.stdout else '',
                'stderr': result.stderr[:500] if result.stderr else ''
            }
            
        except subprocess.TimeoutExpired:
            logger.warning(f"[Amass] Timed out after {timeout}s")
            return {'status': 'timeout', 'error': f'Amass timed out after {timeout}s'}
        except FileNotFoundError:
            logger.error("[Amass] Not installed")
            return {'status': 'not_installed', 'error': 'Amass not found. Install from https://github.com/owasp-amass/amass'}
        except Exception as e:
            logger.error(f"[Amass] Error: {str(e)}")
            return {'status': 'error', 'error': str(e)}


class SubfinderScanner:
    """Wrapper for ProjectDiscovery Subfinder"""
    
    def __init__(self, target: str):
        self.target = target
    
    def enumerate_subdomains(self, timeout: int = 1800) -> Dict:
        """Enumerate subdomains using subfinder"""
        logger.info(f"[Subfinder] Starting subdomain enumeration for {self.target}")
        
        try:
            # Run subfinder with timeout
            # -d: Target domain
            # -silent: Show only subdomains in output
            # -timeout: Timeout in seconds for each source
            cmd = [
                'subfinder',
                '-d', self.target,
                '-silent',
                '-timeout', '30'            # 30 second timeout per source
            ]
            
            logger.info(f"[Subfinder] Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            logger.info(f"[Subfinder] Completed with return code: {result.returncode}")
            
            # Parse text output (one subdomain per line in silent mode)
            subdomains = []
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and '.' in line and not line.startswith('['):
                    subdomains.append(line)
            
            # Deduplicate
            subdomains = list(set(subdomains))
            
            return {
                'status': 'completed',
                'subdomains': subdomains,
                'count': len(subdomains),
                'output': result.stdout[:2000] if result.stdout else '',
                'stderr': result.stderr[:500] if result.stderr else ''
            }
            
        except subprocess.TimeoutExpired:
            logger.warning(f"[Subfinder] Timed out after {timeout}s")
            return {'status': 'timeout', 'error': f'Subfinder timed out after {timeout}s'}
        except FileNotFoundError:
            logger.error("[Subfinder] Not installed")
            return {'status': 'not_installed', 'error': 'Subfinder not found. Install from https://github.com/projectdiscovery/subfinder'}
        except Exception as e:
            logger.error(f"[Subfinder] Error: {str(e)}")
            return {'status': 'error', 'error': str(e)}


class BbotScanner:
    """Wrapper for BBOT (Bighuge BLS OSINT Tool)"""
    
    def __init__(self, target: str):
        self.target = target
    
    def comprehensive_scan(self, timeout: int = 300) -> Dict:
        """Run passive subdomain enumeration with bbot"""
        logger.info(f"[BBOT] Starting passive subdomain scan for {self.target}")
        
        try:
            # Use subdomain-enum preset with passive-only flag (fastest)
            # -p subdomain-enum: subdomain enumeration preset
            # -rf passive: only run passive modules (no active scanning)
            # --silent: minimal output
            # --yes: auto-confirm prompts
            cmd = [
                'bbot', '-t', self.target,
                '-p', 'subdomain-enum',    # Subdomain enumeration preset
                '-rf', 'passive',          # Passive only (fast, no active probing)
                '-o', '/tmp/bbot',
                '--silent',
                '--yes'
            ]
            
            logger.info(f"[BBOT] Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            logger.info(f"[BBOT] Completed with return code: {result.returncode}")
            
            # Parse output for subdomains from [DNS_NAME] lines
            subdomains = []
            dns_records = []
            for line in result.stdout.split('\n'):
                line = line.strip()
                # Parse lines like: [DNS_NAME]  www.example.com  crt  (tags...)
                if line.startswith('[DNS_NAME]'):
                    parts = line.split()
                    if len(parts) >= 2:
                        domain = parts[1]  # The domain is second token
                        if domain not in subdomains:
                            subdomains.append(domain)
                            dns_records.append({
                                'domain': domain,
                                'source': parts[2] if len(parts) > 2 else 'unknown',
                                'tags': line.split('(')[-1].rstrip(')') if '(' in line else ''
                            })
            
            return {
                'status': 'completed',
                'subdomains': subdomains,
                'dns_records': dns_records,
                'count': len(subdomains),
                'output': result.stdout[:2000] if result.stdout else '',
                'stderr': result.stderr[:500] if result.stderr else ''
            }
            
        except subprocess.TimeoutExpired:
            logger.warning(f"[BBOT] Timed out after {timeout}s")
            return {'status': 'timeout', 'error': f'BBOT timed out after {timeout}s'}
        except FileNotFoundError:
            logger.error("[BBOT] Not installed")
            return {'status': 'not_installed', 'error': 'BBOT not found. Install with: pip install bbot'}
        except Exception as e:
            logger.error(f"[BBOT] Error: {str(e)}")
            return {'status': 'error', 'error': str(e)}


class ReconOrchestrator:
    """Orchestrates sequential execution of reconnaissance tools"""
    
    def __init__(self, target_ip: str, elasticsearch_client=None):
        self.target_ip = target_ip
        self.recon_id = str(uuid.uuid4())
        self.es_client = elasticsearch_client
        self.results = {
            'recon_id': self.recon_id,
            'target_ip': target_ip,
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'status': 'pending',
            'tools': {}
        }
        self.current_tool = None
    
    def start_recon(self, scan_types: List[str] = None) -> str:
        """Start reconnaissance in background thread"""
        if scan_types is None:
            scan_types = ['nmap', 'amass', 'subfinder', 'bbot']
        
        self.results['scan_types'] = scan_types
        self.results['status'] = 'running'
        
        # Run in background thread
        thread = threading.Thread(target=self._run_tools_sequentially, args=(scan_types,))
        thread.daemon = True
        thread.start()
        
        return self.recon_id
    
    def _run_tools_sequentially(self, scan_types: List[str]):
        """Execute each tool sequentially"""
        logger.info(f"[Recon {self.recon_id}] Starting sequential scans for {self.target_ip}")
        
        try:
            # 1. Nmap scan
            if 'nmap' in scan_types:
                self.current_tool = 'nmap'
                self._update_progress('nmap', 'running')
                
                scanner = NmapScanner(self.target_ip)
                
                # Host discovery
                host_result = scanner.host_discovery()
                self.results['tools']['nmap'] = {'host_discovery': host_result}
                
                # ALWAYS run port scan regardless of host_up (many firewalls block ICMP)
                port_result = scanner.port_scan(timeout=1800)
                self.results['tools']['nmap']['port_scan'] = port_result
                
                # Service detection (on open ports only)
                if port_result.get('status') == 'completed':
                    open_ports = [p['port'] for p in port_result.get('open_ports', []) if p.get('state') == 'open']
                    if open_ports:
                        service_result = scanner.service_detection(open_ports[:20], timeout=1800)
                        self.results['tools']['nmap']['service_detection'] = service_result
                
                # OS fingerprinting
                os_result = scanner.os_fingerprinting(timeout=1800)
                self.results['tools']['nmap']['os_fingerprinting'] = os_result
                
                self._update_progress('nmap', 'completed')
            
            # 2. Subdomain enumeration - try to get domain from IP, use 'localhost' as fallback for demo
            domain = self._get_domain_from_ip(self.target_ip)
            if not domain:
                # Use localhost as fallback to demonstrate subdomain tools work
                domain = 'localhost'
                logger.info(f"[Recon {self.recon_id}] No domain found for {self.target_ip}, using localhost for demo")
            
            # Always run Amass
            if 'amass' in scan_types:
                self.current_tool = 'amass'
                self._update_progress('amass', 'running')
                
                scanner = AmassScanner(domain)
                amass_result = scanner.enumerate_subdomains(timeout=1800)
                self.results['tools']['amass'] = amass_result
                
                self._update_progress('amass', 'completed')
            
            # Always run Subfinder
            if 'subfinder' in scan_types:
                self.current_tool = 'subfinder'
                self._update_progress('subfinder', 'running')
                
                scanner = SubfinderScanner(domain)
                subfinder_result = scanner.enumerate_subdomains(timeout=1800)
                self.results['tools']['subfinder'] = subfinder_result
                
                self._update_progress('subfinder', 'completed')
            
            # Always run BBOT
            if 'bbot' in scan_types:
                self.current_tool = 'bbot'
                self._update_progress('bbot', 'running')
                
                scanner = BbotScanner(domain)
                bbot_result = scanner.comprehensive_scan(timeout=1800)
                self.results['tools']['bbot'] = bbot_result
                
                self._update_progress('bbot', 'completed')
            
            # Mark as complete
            self.results['status'] = 'completed'
            self.results['end_time'] = datetime.now().isoformat()
            
            # Store in Elasticsearch
            self._store_results()
            
            logger.info(f"[Recon {self.recon_id}] All scans completed")
            
        except Exception as e:
            logger.error(f"[Recon {self.recon_id}] Error: {e}")
            self.results['status'] = 'error'
            self.results['error'] = str(e)
            self.results['end_time'] = datetime.now().isoformat()
    
    def _update_progress(self, tool: str, status: str):
        """Update progress in results"""
        if 'progress' not in self.results:
            self.results['progress'] = {}
        
        self.results['progress'][tool] = {
            'status': status,
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"[Recon {self.recon_id}] {tool}: {status}")
    
    def _get_domain_from_ip(self, ip: str) -> Optional[str]:
        """Try to get domain from IP via reverse DNS"""
        try:
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            # Extract domain (remove subdomain if present)
            parts = hostname.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return hostname
        except:
            return None
    
    def _store_results(self):
        """Store reconnaissance results in Elasticsearch"""
        if self.es_client:
            try:
                index_name = f"recon-results-{datetime.now().strftime('%Y.%m')}"
                self.es_client.index(
                    index=index_name,
                    id=self.recon_id,
                    body=self.results
                )
                logger.info(f"[Recon {self.recon_id}] Results stored in Elasticsearch")
            except Exception as e:
                logger.error(f"Failed to store results in Elasticsearch: {e}")
    
    def get_status(self) -> Dict:
        """Get current status of reconnaissance"""
        return {
            'recon_id': self.recon_id,
            'status': self.results['status'],
            'current_tool': self.current_tool,
            'progress': self.results.get('progress', {}),
            'start_time': self.results['start_time'],
            'end_time': self.results.get('end_time')
        }
    
    def get_results(self) -> Dict:
        """Get full results"""
        return self.results


# Global storage for active reconnaissance jobs
active_recon_jobs = {}


def create_recon_job(target_ip: str, scan_types: List[str] = None, es_client=None) -> str:
    """Create and start a new reconnaissance job"""
    orchestrator = ReconOrchestrator(target_ip, es_client)
    recon_id = orchestrator.start_recon(scan_types)
    active_recon_jobs[recon_id] = orchestrator
    return recon_id


def get_recon_status(recon_id: str) -> Optional[Dict]:
    """Get status of a reconnaissance job"""
    if recon_id in active_recon_jobs:
        return active_recon_jobs[recon_id].get_status()
    return None


def get_recon_results(recon_id: str) -> Optional[Dict]:
    """Get full results of a reconnaissance job"""
    if recon_id in active_recon_jobs:
        return active_recon_jobs[recon_id].get_results()
    return None
