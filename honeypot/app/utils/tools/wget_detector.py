"""
Wget Detection Module
Detects wget command-line tool (often used in automated downloads/attacks)
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class WgetDetector(ToolDetector):
    """Detect wget command-line tool"""

    def __init__(self):
        super().__init__('wget')

        # User-Agent patterns
        self.ua_patterns = [
            'wget',
            'wget/',
        ]

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect wget from request"""
        user_agent = request.headers.get('User-Agent', '')

        # Check User-Agent
        if self.check_user_agent(user_agent):
            # Wget can be legitimate or malicious
            confidence = 60

            # If wget with suspicious behavior, increase confidence
            if context:
                request_rate = context.get('request_rate', 0)
                sequential_paths = context.get('sequential_paths', False)

                if request_rate > 2 or sequential_paths:
                    confidence = 75

            return DetectionResult(
                tool=self.tool_name,
                confidence=confidence,
                method='ua',
                details={
                    'user_agent': user_agent,
                    'note': 'wget can be legitimate or malicious'
                }
            )

        return None
