"""
Shodan Detection Module
Detects Shodan search engine crawler
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class ShodanDetector(ToolDetector):
    """Detect Shodan crawler"""

    def __init__(self):
        super().__init__('shodan')

        # User-Agent patterns
        self.ua_patterns = [
            'shodan',
            'shodanbot',
        ]

        # Shodan IP ranges (some known Shodan scanner IPs)
        # Note: These change, but can be used as additional indicators

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Shodan from request"""
        user_agent = request.headers.get('User-Agent', '')

        # Check User-Agent (very high confidence - Shodan identifies itself)
        if self.check_user_agent(user_agent):
            return DetectionResult(
                tool=self.tool_name,
                confidence=98,  # Shodan properly identifies itself
                method='ua',
                details={
                    'user_agent': user_agent,
                    'note': 'Shodan is a legitimate search engine'
                }
            )

        return None
