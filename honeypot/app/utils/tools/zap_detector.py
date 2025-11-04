"""
OWASP ZAP Detection Module
Detects OWASP ZAP proxy/scanner
"""

from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class ZapDetector(ToolDetector):
    """Detect OWASP ZAP"""
    
    def __init__(self):
        super().__init__('zap')
        
        # User-Agent patterns
        self.ua_patterns = [
            'zaproxy',
            'owasp zap',
            'zap',
        ]
        
        # Header patterns
        self.header_patterns = {
            'User-Agent': ['zaproxy', 'zap', 'owasp'],
        }
        
        # ZAP often includes version in UA
        self.zap_ua_patterns = [
            r'zaproxy/[\d.]+',
            r'owasp zap/[\d.]+',
        ]
    
    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect OWASP ZAP from request"""
        user_agent = request.headers.get('User-Agent', '')
        
        # Check User-Agent (high confidence)
        if self.check_user_agent(user_agent):
            return DetectionResult(
                tool=self.tool_name,
                confidence=85,  # ZAP UA is distinctive
                method='ua',
                details={
                    'user_agent': user_agent
                }
            )
        
        # Check header patterns
        if self.check_headers(dict(request.headers)):
            return DetectionResult(
                tool=self.tool_name,
                confidence=75,
                method='header',
                details={}
            )
        
        return None

