"""
Gobuster Detection Module
Detects Gobuster directory/file brute force tool
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class GobusterDetector(ToolDetector):
    """Detect Gobuster brute force tool"""

    def __init__(self):
        super().__init__('gobuster')

        # User-Agent patterns
        self.ua_patterns = [
            'gobuster',
            'go-http-client',  # Golang HTTP client
        ]

        # Path patterns (wordlist-based scanning)
        self.scan_paths = [
            '/admin',
            '/login',
            '/backup',
            '/test',
            '/api',
            '/config',
            '/wp-admin',
            '/phpmyadmin',
            '/.git',
            '/.env',
            '/robots.txt',
            '/sitemap.xml',
        ]

        # Common file extensions that gobuster scans
        self.scan_extensions = [
            '.php',
            '.asp',
            '.aspx',
            '.jsp',
            '.html',
            '.htm',
            '.txt',
            '.bak',
            '.old',
            '.zip',
        ]

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Gobuster from request"""
        user_agent = request.headers.get('User-Agent', '')
        path = request.path
        method = request.method

        # Check User-Agent
        if self.check_user_agent(user_agent):
            confidence = 90 if 'gobuster' in user_agent.lower() else 75
            return DetectionResult(
                tool=self.tool_name,
                confidence=confidence,
                method='ua',
                details={
                    'user_agent': user_agent,
                    'is_golang': 'go-http-client' in user_agent.lower()
                }
            )

        # Behavioral detection
        if context:
            request_rate = context.get('request_rate', 0)
            many_404s = context.get('many_404s', False)
            sequential_paths = context.get('sequential_paths', False)

            # Pattern 1: Very high request rate (gobuster is FAST)
            if request_rate > 10 and many_404s:
                confidence = min(90, 65 + int(request_rate))
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=confidence,
                    method='behavior',
                    details={
                        'request_rate': request_rate,
                        'many_404s': many_404s,
                        'behavior': 'extremely_fast_scanning'
                    }
                )

            # Pattern 2: Sequential path scanning with high 404 rate
            if sequential_paths and many_404s and request_rate > 5:
                confidence = 75
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=confidence,
                    method='behavior',
                    details={
                        'sequential_paths': sequential_paths,
                        'many_404s': many_404s,
                        'request_rate': request_rate,
                        'behavior': 'wordlist_bruteforce'
                    }
                )

            # Pattern 3: GET requests only, no cookies, no referer
            headers = dict(request.headers)
            no_cookies = 'Cookie' not in headers
            no_referer = 'Referer' not in headers

            if method == 'GET' and no_cookies and no_referer and request_rate > 3:
                if many_404s or sequential_paths:
                    return DetectionResult(
                        tool=self.tool_name,
                        confidence=70,
                        method='behavior',
                        details={
                            'no_cookies': no_cookies,
                            'no_referer': no_referer,
                            'request_rate': request_rate,
                            'behavior': 'minimalist_scanner'
                        }
                    )

        # Pattern 4: Common scan paths + extensions
        if any(scan_path in path.lower() for scan_path in self.scan_paths):
            if any(path.endswith(ext) for ext in self.scan_extensions):
                if context and context.get('request_rate', 0) > 2:
                    return DetectionResult(
                        tool=self.tool_name,
                        confidence=65,
                        method='behavior',
                        details={
                            'path': path,
                            'behavior': 'extension_scanning'
                        }
                    )

        return None
