"""
Masscan Detection Module
Detects Masscan ultra-fast port scanner
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class MasscanDetector(ToolDetector):
    """Detect Masscan port scanner"""

    def __init__(self):
        super().__init__('masscan')

        # User-Agent patterns
        self.ua_patterns = [
            'masscan',
            'masscan/',
        ]

        # Masscan characteristics:
        # - Extremely fast (hundreds/thousands of requests per second)
        # - Randomized source ports
        # - SYN packets (but we see HTTP requests)
        # - Minimal headers
        # - Often uses custom TCP/IP stack

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Masscan from request"""
        user_agent = request.headers.get('User-Agent', '')
        method = request.method

        # Check User-Agent (very high confidence)
        if self.check_user_agent(user_agent):
            return DetectionResult(
                tool=self.tool_name,
                confidence=95,
                method='ua',
                details={
                    'user_agent': user_agent
                }
            )

        # Behavioral detection (masscan is EXTREMELY fast)
        if context:
            request_rate = context.get('request_rate', 0)
            many_404s = context.get('many_404s', False)

            # Pattern 1: Insanely high request rate (masscan can do 10M+ packets/sec)
            # Even rate-limited web requests would be very fast
            if request_rate > 20:
                confidence = min(95, 70 + int(request_rate / 2))
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=confidence,
                    method='behavior',
                    details={
                        'request_rate': request_rate,
                        'behavior': 'extreme_rate_scanning'
                    }
                )

            # Pattern 2: Minimal headers + extremely fast
            headers = dict(request.headers)
            header_count = len(headers)

            if header_count < 4 and request_rate > 15:
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=85,
                    method='behavior',
                    details={
                        'header_count': header_count,
                        'request_rate': request_rate,
                        'behavior': 'minimal_headers_extreme_speed'
                    }
                )

            # Pattern 3: No User-Agent + extreme speed
            if not user_agent and request_rate > 12:
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=80,
                    method='behavior',
                    details={
                        'no_user_agent': True,
                        'request_rate': request_rate,
                        'behavior': 'raw_scanning'
                    }
                )

        return None
