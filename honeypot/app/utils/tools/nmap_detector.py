"""
Nmap Detection Module
Detects Nmap scanning activities
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class NmapDetector(ToolDetector):
    """Detect Nmap scanning tool"""
    
    def __init__(self):
        super().__init__('nmap')
        
        # User-Agent patterns from scanner_user_agents database
        self.ua_patterns = [
            'nmap',
            'nmap scripting engine',
            'nse',
            'libwww-perl',  # Nmap often uses Perl
        ]
        
        # Payload patterns (Nmap scan signatures)
        self.payload_patterns = [
            'nmap',
            'nse',
            'script',
        ]
        
        # Header patterns
        self.header_patterns = {
            'User-Agent': ['nmap', 'nse'],
        }
        
        # Behavioral: Rapid sequential requests (port scanning)
        self.behavioral_patterns = {
            'rapid_requests': True,  # Multiple requests in short time
            'sequential_paths': True,  # Requests to sequential ports/paths
        }
    
    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Nmap from request"""
        user_agent = request.headers.get('User-Agent', '')
        query_string = str(request.query_string.decode())
        path = request.path
        
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
        
        # Behavioral: Check for scan patterns in context
        if context and context.get('request_rate', 0) > 10:  # More than 10 requests per second
            if context.get('sequential_paths', False):
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=60,  # Lower confidence for behavioral detection
                    method='behavior',
                    details={
                        'request_rate': context.get('request_rate'),
                        'behavior': 'rapid_sequential_requests'
                    }
                )
        
        return None

