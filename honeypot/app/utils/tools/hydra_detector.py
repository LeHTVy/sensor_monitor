"""
Hydra/Medusa Detection Module
Detects brute-force authentication tools
"""

from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class HydraDetector(ToolDetector):
    """Detect Hydra/Medusa brute-force tools"""
    
    def __init__(self):
        super().__init__('hydra')
        
        # User-Agent patterns
        self.ua_patterns = [
            'hydra',
            'medusa',
            'thc-hydra',
        ]
        
        # Behavioral: Many failed authentication attempts
        self.behavioral_patterns = {
            'many_failed_auths': True,
            'rapid_auth_attempts': True,
        }
        
        # Common login paths
        self.auth_paths = [
            '/login',
            '/auth',
            '/signin',
            '/admin',
            '/administrator',
            '/wp-login.php',
            '/phpmyadmin',
        ]
    
    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Hydra from request"""
        user_agent = request.headers.get('User-Agent', '')
        path = request.path.lower()
        method = request.method
        
        # Check User-Agent
        if self.check_user_agent(user_agent):
            tool_name = 'hydra' if 'hydra' in user_agent.lower() else 'medusa'
            return DetectionResult(
                tool=tool_name,
                confidence=self.get_confidence('ua'),
                method='ua',
                details={
                    'user_agent': user_agent
                }
            )
        
        # Behavioral: Many POST requests to auth endpoints with failed responses
        if context and method == 'POST':
            if any(auth_path in path for auth_path in self.auth_paths):
                if context.get('many_failed_auths', False) and context.get('request_rate', 0) > 5:
                    return DetectionResult(
                        tool=self.tool_name,
                        confidence=75,
                        method='behavior',
                        details={
                            'request_rate': context.get('request_rate'),
                            'behavior': 'rapid_failed_auth_attempts',
                            'path': path
                        }
                    )
        
        return None

