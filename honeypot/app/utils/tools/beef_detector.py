"""
BeEF Detection Module
Detects BeEF (Browser Exploitation Framework)
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class BeefDetector(ToolDetector):
    """Detect BeEF framework"""

    def __init__(self):
        super().__init__('beef')

        # User-Agent patterns
        self.ua_patterns = [
            'beef',
            'beefhook',
        ]

        # BeEF-specific patterns
        self.payload_patterns = [
            r'beef',
            r'hook\.js',
            r'beefhook',
            r'/api/hook',
            r'/hook\.js',
            r'BeefBind',
        ]

        # Path patterns
        self.path_patterns = [
            '/hook.js',
            '/api/hook',
            '/beef',
        ]

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect BeEF from request"""
        user_agent = request.headers.get('User-Agent', '')
        query_string = str(request.query_string.decode())
        form_data = str(request.form)
        path = request.path
        referer = request.headers.get('Referer', '')

        # Check User-Agent
        if self.check_user_agent(user_agent):
            return DetectionResult(
                tool=self.tool_name,
                confidence=95,
                method='ua',
                details={
                    'user_agent': user_agent
                }
            )

        # Check path patterns
        if self.check_path(path):
            return DetectionResult(
                tool=self.tool_name,
                confidence=90,
                method='pattern',
                details={
                    'path': path
                }
            )

        # Check payload patterns
        combined = f"{query_string} {form_data} {referer}"
        payload_matches = []

        for pattern in self.payload_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                payload_matches.append(pattern)

        if payload_matches:
            confidence = min(95, 80 + len(payload_matches) * 5)
            return DetectionResult(
                tool=self.tool_name,
                confidence=confidence,
                method='payload',
                details={
                    'matched_patterns': payload_matches
                }
            )

        return None
