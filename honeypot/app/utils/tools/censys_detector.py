"""
Censys Detection Module
Detects Censys search engine crawler
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class CensysDetector(ToolDetector):
    """Detect Censys crawler"""

    def __init__(self):
        super().__init__('censys')

        # User-Agent patterns
        self.ua_patterns = [
            'censys',
            'censys scanner',
        ]

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Censys from request"""
        user_agent = request.headers.get('User-Agent', '')

        # Check User-Agent (very high confidence - Censys identifies itself)
        if self.check_user_agent(user_agent):
            return DetectionResult(
                tool=self.tool_name,
                confidence=98,  # Censys properly identifies itself
                method='ua',
                details={
                    'user_agent': user_agent,
                    'note': 'Censys is a legitimate search engine'
                }
            )

        return None
