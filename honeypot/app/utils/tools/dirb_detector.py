"""
DirB/Gobuster/DirBuster Detection Module
Detects directory brute-forcing tools
"""

from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class DirbDetector(ToolDetector):
    """Detect DirB/Gobuster/DirBuster directory scanners"""
    
    def __init__(self):
        super().__init__('dirb')
        
        # User-Agent patterns
        self.ua_patterns = [
            'dirb',
            'gobuster',
            'dirbuster',
        ]
        
        # Behavioral: Many 404 responses to common wordlist paths
        self.behavioral_patterns = {
            'many_404s': True,
            'rapid_requests': True,
            'wordlist_paths': True,
        }
        
        # Common wordlist paths (these tools test common paths)
        self.common_wordlist_paths = [
            '/admin', '/administrator', '/backup', '/config', '/data',
            '/db', '/database', '/docs', '/download', '/files',
            '/images', '/inc', '/include', '/includes', '/install',
            '/logs', '/old', '/phpinfo', '/private', '/secure',
            '/src', '/sql', '/temp', '/test', '/tmp', '/uploads',
            '/www', '/wwwroot', '/.git', '/.svn', '/.env',
        ]
    
    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect DirB/Gobuster from request"""
        user_agent = request.headers.get('User-Agent', '')
        path = request.path.lower()
        
        # Check User-Agent
        if self.check_user_agent(user_agent):
            tool_name = 'dirb' if 'dirb' in user_agent.lower() else 'gobuster'
            return DetectionResult(
                tool=tool_name,
                confidence=self.get_confidence('ua'),
                method='ua',
                details={
                    'user_agent': user_agent
                }
            )
        
        # Behavioral: Many 404s to wordlist paths
        if context:
            if context.get('many_404s', False) and context.get('request_rate', 0) > 3:
                # Check if requesting common wordlist paths
                if any(wordlist_path in path for wordlist_path in self.common_wordlist_paths):
                    return DetectionResult(
                        tool=self.tool_name,
                        confidence=70,
                        method='behavior',
                        details={
                            'request_rate': context.get('request_rate'),
                            'behavior': 'many_404s_wordlist_paths',
                            'path': path
                        }
                    )
        
        return None

