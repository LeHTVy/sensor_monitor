"""
Nmap Detection Module
Detects Nmap scanning activities including web and IP scanning
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class NmapDetector(ToolDetector):
    """Detect Nmap scanning tool - Enhanced for web and IP scanning"""
    
    def __init__(self):
        super().__init__('nmap')
        
        # User-Agent patterns from scanner_user_agents database
        self.ua_patterns = [
            'nmap',
            'nmap scripting engine',
            'nse',
            'mozilla/5.0 (compatible; nmap scripting engine',
            'libwww-perl',  # Nmap often uses Perl
            'libcurl',  # Nmap sometimes uses curl
            'nmap/7.',  # Nmap 7.x versions
            'nmap/8.',  # Nmap 8.x versions
            'nmap nse',
            'http-enum.nse',
            'http-vuln',
            'http-headers.nse',
        ]
        
        # Payload patterns (Nmap scan signatures and NSE scripts)
        self.payload_patterns = [
            'nmap',
            'nse',
            'script',
            'http-enum',
            'http-vuln',
            'http-headers',
            'http-methods',
            'http-shellshock',
            'http-sql-injection',
            'http-stored-xss',
            'http-csrf',
            'ssl-enum-ciphers',
            'ssl-cert',
            'http-wordpress',
            'http-joomla',
            'http-drupal',
        ]
        
        # Header patterns
        self.header_patterns = {
            'User-Agent': ['nmap', 'nse'],
        }
        
        # Common paths that nmap scans
        self.scan_paths = [
            '/',
            '/robots.txt',
            '/sitemap.xml',
            '/admin',
            '/login',
            '/test',
            '/index.html',
            '/index.php',
            '/.well-known/',
            '/favicon.ico',
        ]
        
        # HTTP methods that nmap commonly uses
        self.scan_methods = ['HEAD', 'OPTIONS', 'PROBE', 'GET']
        
        # Behavioral: Rapid sequential requests (port scanning)
        self.behavioral_patterns = {
            'rapid_requests': True,  # Multiple requests in short time
            'sequential_paths': True,  # Requests to sequential ports/paths
        }
    
    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Nmap from request - Enhanced detection for web and IP scanning"""
        user_agent = request.headers.get('User-Agent', '')
        query_string = str(request.query_string.decode())
        path = request.path
        method = request.method
        
        # Check User-Agent (high confidence)
        if self.check_user_agent(user_agent):
            return DetectionResult(
                tool=self.tool_name,
                confidence=self.get_confidence('ua'),
                method='ua',
                details={
                    'user_agent': user_agent,
                    'matched_pattern': next((p for p in self.ua_patterns if p.lower() in user_agent.lower()), None)
                }
            )
        
        # Check payload patterns
        if self.check_payload(query_string, str(request.form)):
            return DetectionResult(
                tool=self.tool_name,
                confidence=self.get_confidence('payload'),
                method='payload',
                details={
                    'query_string': query_string[:100]  # Truncate for logging
                }
            )
        
        # Check headers
        if self.check_headers(dict(request.headers)):
            return DetectionResult(
                tool=self.tool_name,
                confidence=self.get_confidence('header'),
                method='header',
                details={}
            )
        
        # Enhanced behavioral detection
        if context:
            request_rate = context.get('request_rate', 0)
            many_404s = context.get('many_404s', False)
            sequential_paths = context.get('sequential_paths', False)
            varying_params = context.get('varying_params', False)
            
            # Pattern 1: High request rate + many 404s (typical nmap web scan)
            if request_rate > 5 and many_404s:
                confidence = min(85, 60 + int(request_rate * 2))
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=confidence,
                    method='behavior',
                    details={
                        'request_rate': request_rate,
                        'many_404s': many_404s,
                        'behavior': 'high_rate_with_404s'
                    }
                )
            
            # Pattern 2: High request rate + sequential/varying paths
            if request_rate > 8:
                if sequential_paths or varying_params:
                    confidence = min(80, 55 + int(request_rate * 2))
                    return DetectionResult(
                        tool=self.tool_name,
                        confidence=confidence,
                        method='behavior',
                        details={
                            'request_rate': request_rate,
                            'sequential_paths': sequential_paths,
                            'varying_params': varying_params,
                            'behavior': 'rapid_scanning_pattern'
                        }
                    )
            
            # Pattern 3: Moderate rate but with scan characteristics
            if request_rate > 3:
                # Check if path matches common scan paths
                if any(scan_path in path.lower() for scan_path in self.scan_paths):
                    # Check if using scan methods
                    if method in self.scan_methods:
                        confidence = 70
                        return DetectionResult(
                            tool=self.tool_name,
                            confidence=confidence,
                            method='behavior',
                            details={
                                'request_rate': request_rate,
                                'method': method,
                                'path': path,
                                'behavior': 'scan_path_with_method'
                            }
                        )
        
        # Pattern 4: Missing or minimal headers (nmap often sends minimal headers)
        headers = dict(request.headers)
        header_count = len(headers)
        has_common_headers = any(h.lower() in headers for h in ['accept', 'accept-language', 'accept-encoding', 'referer'])
        
        # If very few headers and using scan methods
        if header_count < 5 and method in ['HEAD', 'OPTIONS', 'PROBE']:
            # Check if path is common scan target
            if any(scan_path in path.lower() for scan_path in self.scan_paths):
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=65,
                    method='behavior',
                    details={
                        'header_count': header_count,
                        'method': method,
                        'path': path,
                        'behavior': 'minimal_headers_scan'
                    }
                )
        
        # Pattern 5: No User-Agent or very generic User-Agent with scan behavior
        if not user_agent or user_agent.lower() in ['', '-', 'nmap']:
            if method in self.scan_methods:
                if context and context.get('request_rate', 0) > 2:
                    return DetectionResult(
                        tool=self.tool_name,
                        confidence=60,
                        method='behavior',
                        details={
                            'user_agent': user_agent or '(empty)',
                            'method': method,
                            'request_rate': context.get('request_rate', 0),
                            'behavior': 'no_ua_with_scan_method'
                        }
                    )
        
        return None

