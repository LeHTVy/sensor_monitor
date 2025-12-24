"""
Web Scanner Detector
Detects web vulnerability scanners, SQL injection, brute force, and other security tools
via payload and User-Agent inspection
"""

import re
from typing import Optional, Dict
from scapy.all import TCP, Raw
from .base_network_detector import BaseNetworkDetector


class WebScannerDetector(BaseNetworkDetector):
    """
    Detects security testing tools by inspecting TCP payloads for known signatures.
    Covers: port scanners, web scanners, SQL injection, brute force, proxies, etc.
    """

    def __init__(self):
        super().__init__('web_scanner')

        # Compile regex signatures for performance
        self.signatures = {
            # === PORT SCANNERS ===
            'rustscan': [
                re.compile(rb'User-Agent:.*rustscan', re.IGNORECASE),
                re.compile(rb'RustScan', re.IGNORECASE),
            ],
            'zmap': [
                re.compile(rb'User-Agent:.*zmap', re.IGNORECASE),
                re.compile(rb'ZMap', re.IGNORECASE),
            ],
            'naabu': [
                re.compile(rb'User-Agent:.*naabu', re.IGNORECASE),
                re.compile(rb'projectdiscovery.*naabu', re.IGNORECASE),
            ],
            
            # === WEB VULNERABILITY SCANNERS ===
            'nuclei': [
                re.compile(rb'User-Agent:.*nuclei', re.IGNORECASE),
                re.compile(rb'X-Nuclei-Version', re.IGNORECASE),
                re.compile(rb'projectdiscovery', re.IGNORECASE),
            ],
            'nikto': [
                re.compile(rb'User-Agent:.*Nikto', re.IGNORECASE),
                re.compile(rb'/nikto-test', re.IGNORECASE),
            ],
            'wpscan': [
                re.compile(rb'User-Agent:.*WPScan', re.IGNORECASE),
                re.compile(rb'wpscan\.com', re.IGNORECASE),
            ],
            'joomscan': [
                re.compile(rb'User-Agent:.*JoomScan', re.IGNORECASE),
            ],
            'droopescan': [
                re.compile(rb'User-Agent:.*droopescan', re.IGNORECASE),
            ],
            'whatweb': [
                re.compile(rb'User-Agent:.*WhatWeb', re.IGNORECASE),
            ],
            'wapiti': [
                re.compile(rb'User-Agent:.*Wapiti', re.IGNORECASE),
            ],
            'skipfish': [
                re.compile(rb'User-Agent:.*skipfish', re.IGNORECASE),
            ],
            'arachni': [
                re.compile(rb'User-Agent:.*Arachni', re.IGNORECASE),
            ],
            'acunetix': [
                re.compile(rb'User-Agent:.*Acunetix', re.IGNORECASE),
                re.compile(rb'acunetix-', re.IGNORECASE),
            ],
            'nessus': [
                re.compile(rb'User-Agent:.*Nessus', re.IGNORECASE),
            ],
            'openvas': [
                re.compile(rb'User-Agent:.*OpenVAS', re.IGNORECASE),
            ],
            
            # === DIRECTORY/FILE BRUTEFORCE ===
            'gobuster': [
                re.compile(rb'User-Agent:.*gobuster', re.IGNORECASE),
            ],
            'dirbuster': [
                re.compile(rb'User-Agent:.*DirBuster', re.IGNORECASE),
            ],
            'dirb': [
                re.compile(rb'User-Agent:.*dirb', re.IGNORECASE),
            ],
            'ffuf': [
                re.compile(rb'User-Agent:.*Fuzz Faster U Fool', re.IGNORECASE),
                re.compile(rb'User-Agent:.*ffuf', re.IGNORECASE),
            ],
            'wfuzz': [
                re.compile(rb'User-Agent:.*wfuzz', re.IGNORECASE),
            ],
            'feroxbuster': [
                re.compile(rb'User-Agent:.*feroxbuster', re.IGNORECASE),
            ],
            
            # === SQL INJECTION ===
            'sqlmap': [
                re.compile(rb'User-Agent:.*sqlmap', re.IGNORECASE),
                re.compile(rb'sqlmapproject', re.IGNORECASE),
            ],
            'sql_injection': [
                re.compile(rb'UNION.*SELECT', re.IGNORECASE),
                re.compile(rb'AND\s+1=1', re.IGNORECASE),
                re.compile(rb'OR\s+1=1', re.IGNORECASE),
                re.compile(rb"'\s*OR\s*'", re.IGNORECASE),
                re.compile(rb'information_schema', re.IGNORECASE),
                re.compile(rb'WAITFOR\s+DELAY', re.IGNORECASE),
                re.compile(rb'SLEEP\s*\(', re.IGNORECASE),
                re.compile(rb'BENCHMARK\s*\(', re.IGNORECASE),
                re.compile(rb'pg_sleep', re.IGNORECASE),
                re.compile(rb'--\s*$', re.IGNORECASE),  # SQL comment
                re.compile(rb';\s*DROP\s+TABLE', re.IGNORECASE),
                re.compile(rb'xp_cmdshell', re.IGNORECASE),
            ],
            
            # === BRUTE FORCE TOOLS ===
            'hydra': [
                re.compile(rb'User-Agent:.*Hydra', re.IGNORECASE),
                re.compile(rb'hydra', re.IGNORECASE),
            ],
            'medusa': [
                re.compile(rb'User-Agent:.*Medusa', re.IGNORECASE),
            ],
            'patator': [
                re.compile(rb'User-Agent:.*Patator', re.IGNORECASE),
            ],
            'crowbar': [
                re.compile(rb'User-Agent:.*crowbar', re.IGNORECASE),
            ],
            
            # === PROXY/INTERCEPTION TOOLS ===
            'burpsuite': [
                re.compile(rb'User-Agent:.*Burp', re.IGNORECASE),
                re.compile(rb'referer:.*burp', re.IGNORECASE),
            ],
            'zaproxy': [
                re.compile(rb'User-Agent:.*ZAP', re.IGNORECASE),
                re.compile(rb'User-Agent:.*OWASP-ZAP', re.IGNORECASE),
            ],
            'mitmproxy': [
                re.compile(rb'User-Agent:.*mitmproxy', re.IGNORECASE),
            ],
            
            # === OSINT/RECON TOOLS ===
            'bbot_web': [
                re.compile(rb'User-Agent:.*bbot', re.IGNORECASE),
                re.compile(rb'X-BBOT', re.IGNORECASE),
            ],
            'httpx': [
                re.compile(rb'User-Agent:.*httpx', re.IGNORECASE),
                re.compile(rb'projectdiscovery', re.IGNORECASE),
            ],
            'subfinder': [
                re.compile(rb'User-Agent:.*subfinder', re.IGNORECASE),
            ],
            'amass_web': [
                re.compile(rb'User-Agent:.*amass', re.IGNORECASE),
            ],
            'shodan': [
                re.compile(rb'User-Agent:.*Shodan', re.IGNORECASE),
                re.compile(rb'shodan\.io', re.IGNORECASE),
            ],
            'censys': [
                re.compile(rb'User-Agent:.*Censys', re.IGNORECASE),
                re.compile(rb'censys\.io', re.IGNORECASE),
            ],
            'zgrab': [
                re.compile(rb'User-Agent:.*zgrab', re.IGNORECASE),
            ],
            
            # === EXPLOIT FRAMEWORKS ===
            'metasploit': [
                re.compile(rb'User-Agent:.*Metasploit', re.IGNORECASE),
                re.compile(rb'msf', re.IGNORECASE),
            ],
            'cobalt_strike': [
                re.compile(rb'User-Agent:.*Mozilla/5\.0.*Beacon', re.IGNORECASE),
            ],
            
            # === XSS ATTACKS ===
            'xss_attack': [
                re.compile(rb'<script>', re.IGNORECASE),
                re.compile(rb'javascript:', re.IGNORECASE),
                re.compile(rb'onerror\s*=', re.IGNORECASE),
                re.compile(rb'onload\s*=', re.IGNORECASE),
                re.compile(rb'onclick\s*=', re.IGNORECASE),
                re.compile(rb'<img[^>]+src\s*=\s*["\']?javascript', re.IGNORECASE),
            ],
            
            # === COMMAND INJECTION ===
            'cmd_injection': [
                re.compile(rb';\s*cat\s+/etc/passwd', re.IGNORECASE),
                re.compile(rb'\|\s*cat\s+/etc/passwd', re.IGNORECASE),
                re.compile(rb'`.*`', re.IGNORECASE),  # Backtick execution
                re.compile(rb'\$\(.*\)', re.IGNORECASE),  # Command substitution
                re.compile(rb'/etc/passwd', re.IGNORECASE),
                re.compile(rb'/etc/shadow', re.IGNORECASE),
                re.compile(rb'whoami', re.IGNORECASE),
                re.compile(rb'id\s*;', re.IGNORECASE),
            ],
            
            # === PATH TRAVERSAL ===
            'path_traversal': [
                re.compile(rb'\.\./', re.IGNORECASE),
                re.compile(rb'\.\.\\\\', re.IGNORECASE),
                re.compile(rb'%2e%2e%2f', re.IGNORECASE),
                re.compile(rb'%252e', re.IGNORECASE),  # Double encoding
            ],
            
            # === BOTS & CRAWLERS ===
            'crawler': [
                re.compile(rb'User-Agent:.*curl/', re.IGNORECASE),
                re.compile(rb'User-Agent:.*wget/', re.IGNORECASE),
                re.compile(rb'User-Agent:.*python-requests', re.IGNORECASE),
                re.compile(rb'User-Agent:.*python-urllib', re.IGNORECASE),
                re.compile(rb'User-Agent:.*axios', re.IGNORECASE),
                re.compile(rb'User-Agent:.*Go-http-client', re.IGNORECASE),
                re.compile(rb'User-Agent:.*libwww-perl', re.IGNORECASE),
            ],
        }
        
        # Tool categories for classification
        self.tool_categories = {
            'port_scanner': ['rustscan', 'zmap', 'naabu'],
            'vuln_scanner': ['nuclei', 'nikto', 'wpscan', 'joomscan', 'droopescan', 
                           'whatweb', 'wapiti', 'skipfish', 'arachni', 'acunetix', 
                           'nessus', 'openvas'],
            'dir_bruteforce': ['gobuster', 'dirbuster', 'dirb', 'ffuf', 'wfuzz', 'feroxbuster'],
            'sql_injection': ['sqlmap', 'sql_injection'],
            'brute_force': ['hydra', 'medusa', 'patator', 'crowbar'],
            'proxy': ['burpsuite', 'zaproxy', 'mitmproxy'],
            'osint': ['bbot_web', 'httpx', 'subfinder', 'amass_web', 'shodan', 'censys', 'zgrab'],
            'exploit': ['metasploit', 'cobalt_strike'],
            'xss': ['xss_attack'],
            'cmd_injection': ['cmd_injection'],
            'path_traversal': ['path_traversal'],
            'crawler': ['crawler'],
        }

    def detect(self, src_ip: str, context: dict, metrics: dict, packet) -> Optional[Dict]:
        """Detect web scanning patterns in TCP payloads"""
        
        # We need TCP packets with payloads
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return None

        # Get payload data
        try:
            payload = packet[Raw].load
        except Exception:
            return None

        if not payload:
            return None

        # Check against signatures - return on first match
        all_matches = []
        for tool, patterns in self.signatures.items():
            for pattern in patterns:
                if pattern.search(payload):
                    all_matches.append(tool)
                    break  # Move to next tool
        
        if all_matches:
            # Return best match (first detected)
            best_tool = all_matches[0]
            return self._create_detection_result(best_tool, payload, all_matches)

        return None

    def _create_detection_result(self, tool: str, payload: bytes, all_matches: list) -> Dict:
        """Create detection result based on matched tool"""
        
        confidence = 95  # Payload matches are high confidence
        
        # Determine specific tool name and techniques
        tool_name = tool
        techniques = ['web_scan']
        category = 'unknown'
        
        # Find category
        for cat, tools in self.tool_categories.items():
            if tool in tools:
                category = cat
                break
        
        # Add techniques based on category
        if category == 'sql_injection':
            tool_name = 'sql_injector' if tool == 'sql_injection' else tool
            techniques.extend(['sql_injection', 'exploitation'])
            confidence = 100
        elif category == 'vuln_scanner':
            techniques.append('vulnerability_scan')
        elif category == 'dir_bruteforce':
            techniques.append('directory_bruteforce')
        elif category == 'brute_force':
            techniques.extend(['brute_force', 'credential_attack'])
            confidence = 100
        elif category == 'proxy':
            techniques.append('interception')
        elif category == 'osint':
            techniques.append('reconnaissance')
        elif category == 'exploit':
            techniques.extend(['exploitation', 'post_exploitation'])
            confidence = 100
        elif category == 'xss':
            tool_name = 'xss_attacker'
            techniques.extend(['xss', 'exploitation'])
            confidence = 100
        elif category == 'cmd_injection':
            tool_name = 'cmd_injector'
            techniques.extend(['command_injection', 'exploitation'])
            confidence = 100
        elif category == 'path_traversal':
            tool_name = 'path_traversal_attack'
            techniques.extend(['path_traversal', 'exploitation'])
            confidence = 100
        elif category == 'port_scanner':
            techniques.append('port_scan')
        elif category == 'crawler':
            techniques.append('automated_crawler')
            confidence = 70  # Lower confidence for generic crawlers
        
        # Extract a snippet of the payload for details (safe decode)
        try:
            payload_snippet = payload[:200].decode('utf-8', errors='ignore')
        except:
            payload_snippet = str(payload[:200])

        details = {
            'matched_tool': tool,
            'category': category,
            'payload_snippet': payload_snippet[:100]  # Truncate for log
        }
        
        # Add all matches if multiple
        if len(all_matches) > 1:
            details['all_matches'] = all_matches[:5]

        return self.create_detection(
            confidence=confidence,
            method='payload_inspection',
            details=details,
            techniques=techniques
        )
