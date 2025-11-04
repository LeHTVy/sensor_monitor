"""
Nikto Detection Module
Detects Nikto web scanner
"""

from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class NiktoDetector(ToolDetector):
    """Detect Nikto scanner"""
    
    def __init__(self):
        super().__init__('nikto')
        
        # User-Agent patterns
        self.ua_patterns = [
            'nikto',
            'nikto/',
            'mozilla.*nikto',  # Sometimes Nikto uses modified UA
        ]
        
        # Nikto behavior: Multiple HEAD/GET requests to common paths
        self.path_patterns = [
            '/admin',
            '/phpmyadmin',
            '/wp-admin',
            '/.env',
            '/config',
            '/backup',
            '/test',
            '/robots.txt',
            '/sitemap.xml',
        ]
        
        # Header patterns
        self.header_patterns = {
            'User-Agent': ['nikto'],
        }
        
        # Behavioral: Nikto makes many requests in sequence
        self.behavioral_patterns = {
            'many_404s': True,  # Many 404 responses
            'rapid_requests': True,
        }
    
    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Nikto from request"""
        user_agent = request.headers.get('User-Agent', '')
        path = request.path.lower()
        method = request.method
        
        # Check User-Agent
        if self.check_user_agent(user_agent):
            return DetectionResult(
                tool=self.tool_name,
                confidence=self.get_confidence('ua'),
                method='ua',
                details={
                    'user_agent': user_agent
                }
            )
        
        # Check for Nikto scanning pattern: HEAD requests to common paths
        if method == 'HEAD' and any(common_path in path for common_path in self.path_patterns):
            return DetectionResult(
                tool=self.tool_name,
                confidence=70,
                method='pattern',
                details={
                    'method': method,
                    'path': path,
                    'pattern': 'head_request_to_common_path'
                }
            )
        
        # Behavioral: Rapid requests to scanner paths
        if context and context.get('request_rate', 0) > 5:
            if context.get('many_404s', False) and any(common_path in path for common_path in self.path_patterns):
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=65,
                    method='behavior',
                    details={
                        'request_rate': context.get('request_rate'),
                        'behavior': 'rapid_requests_many_404s'
                    }
                )
        
        return None

