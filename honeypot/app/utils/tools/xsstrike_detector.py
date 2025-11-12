"""
XSStrike Detection Module
Detects XSStrike XSS detection tool
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class XSStrikeDetector(ToolDetector):
    """Detect XSStrike tool"""

    def __init__(self):
        super().__init__('xsstrike')

        # User-Agent patterns
        self.ua_patterns = [
            'xsstrike',
        ]

        # XSStrike payload patterns
        self.payload_patterns = [
            r'<[^>]*\bxsstrike\b[^>]*>',
            r'xsstrike',
            # Common XSS payloads that XSStrike uses
            r'<svg[\s/]*onload',
            r'<img[\s/]*src[\s/]*=[\s/]*["\']?javascript:',
            r'<script[\s/]*>[\s/]*alert\(',
            r'<iframe[\s/]*src[\s/]*=',
            # XSStrike-specific markers
            r'%3Cscript%3Ealert%28',
            r'%3Csvg%2Fonload',
        ]

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect XSStrike from request"""
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
        payload_matches = []

        for pattern in self.payload_patterns:
            if re.search(pattern, combined_payload, re.IGNORECASE):
                payload_matches.append(pattern)

        # Multiple XSS payloads indicate XSStrike or similar
        if len(payload_matches) >= 2:
            confidence = min(90, 70 + len(payload_matches) * 5)
            return DetectionResult(
                tool=self.tool_name,
                confidence=confidence,
                method='payload',
                details={
                    'matched_patterns': payload_matches[:5],
                    'xss_payload_count': len(payload_matches)
                }
            )

        return None
