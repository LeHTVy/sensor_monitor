"""
W3af Detection Module
Detects w3af web application attack and audit framework
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class W3afDetector(ToolDetector):
    """Detect w3af framework"""

    def __init__(self):
        super().__init__('w3af')

        # User-Agent patterns
        self.ua_patterns = [
            'w3af',
            'w3af.org',
        ]

        # W3af-specific patterns
        self.payload_patterns = [
            r'w3af',
            r'w3af\.org',
        ]

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect w3af from request"""
        user_agent = request.headers.get('User-Agent', '')
        query_string = str(request.query_string.decode())
        form_data = str(request.form)

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

        # Check payload patterns
        combined_payload = f"{query_string} {form_data}"
        if self.check_payload(query_string, form_data):
            return DetectionResult(
                tool=self.tool_name,
                confidence=85,
                method='payload',
                details={
                    'query_string': query_string[:100]
                }
            )

        return None
