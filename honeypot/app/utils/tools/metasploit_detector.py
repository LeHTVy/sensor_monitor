"""
Metasploit Detection Module
Detects Metasploit framework activities
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class MetasploitDetector(ToolDetector):
    """Detect Metasploit framework"""
    
    def __init__(self):
        super().__init__('metasploit')
        
        # User-Agent patterns
        self.ua_patterns = [
            'metasploit',
            'msf',
            'msfconsole',
        ]
        
        # Metasploit payload patterns (reverse shell, meterpreter, etc.)
        self.payload_patterns = [
            # Meterpreter patterns
            'meterpreter',
            'msf',
            # Reverse shell patterns
            'bash -i',
            '/bin/bash',
            '/bin/sh',
            # PowerShell patterns
            'powershell',
            'iex ',
            # Common Metasploit payload signatures
            'payload',
            'exploit',
        ]
        
        # Header patterns
        self.header_patterns = {
            'User-Agent': ['metasploit', 'msf'],
        }
    
    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Metasploit from request"""
        user_agent = request.headers.get('User-Agent', '')
        query_string = str(request.query_string.decode())
        form_data = str(request.form)
        body = request.get_data(as_text=True) if hasattr(request, 'get_data') else ''
        
        # Check User-Agent
        if self.check_user_agent(user_agent):
            return DetectionResult(
                tool=self.tool_name,
                confidence=85,
                method='ua',
                details={
                    'user_agent': user_agent
                }
            )
        
        # Check payload patterns (Metasploit payloads are distinctive)
        combined_payload = f"{query_string} {form_data} {body}".lower()
        payload_matches = []
        
        for pattern in self.payload_patterns:
            if re.search(pattern, combined_payload, re.IGNORECASE):
                payload_matches.append(pattern)
        
        if payload_matches:
            confidence = min(90, 70 + len(payload_matches) * 5)
            return DetectionResult(
                tool=self.tool_name,
                confidence=confidence,
                method='payload',
                details={
                    'matched_patterns': payload_matches[:5],
                    'has_shell_pattern': any('bash' in p or 'sh' in p for p in payload_matches)
                }
            )
        
        # Check headers
        if self.check_headers(dict(request.headers)):
            return DetectionResult(
                tool=self.tool_name,
                confidence=75,
                method='header',
                details={}
            )
        
        return None

