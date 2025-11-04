"""
Burp Suite Detection Module
Detects Burp Suite proxy/scanner
"""

from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class BurpDetector(ToolDetector):
    """Detect Burp Suite"""
    
    def __init__(self):
        super().__init__('burp')
        
        # User-Agent patterns
        self.ua_patterns = [
            'burp',
            'burpsuite',
            'burp suite',
        ]
        
        # Header patterns - Burp has distinctive headers
        self.header_patterns = {
            'User-Agent': ['burp'],
            'X-Burp-Version': [],  # Any X-Burp header indicates Burp
        }
        
        # Burp often adds specific headers
        self.burp_specific_headers = [
            'x-burp-version',
            'x-burp-request',
            'x-burp-response',
        ]
    
    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Burp Suite from request"""
        user_agent = request.headers.get('User-Agent', '')
        headers = dict(request.headers)
        
        # Check User-Agent
        if self.check_user_agent(user_agent):
            return DetectionResult(
                tool=self.tool_name,
                confidence=90,  # Burp UA is distinctive
                method='ua',
                details={
                    'user_agent': user_agent
                }
            )
        
        # Check for Burp-specific headers
        for header_name in self.burp_specific_headers:
            if header_name in [k.lower() for k in headers.keys()]:
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=95,  # Burp headers are very distinctive
                    method='header',
                    details={
                        'matched_header': header_name,
                        'header_value': headers.get(header_name, '')
                    }
                )
        
        # Check header patterns
        if self.check_headers(headers):
            return DetectionResult(
                tool=self.tool_name,
                confidence=80,
                method='header',
                details={}
            )
        
        return None

