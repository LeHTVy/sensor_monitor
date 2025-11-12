"""
Skipfish Detection Module
Detects Skipfish web application scanner
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class SkipfishDetector(ToolDetector):
    """Detect Skipfish scanner"""

    def __init__(self):
        super().__init__('skipfish')

        # User-Agent patterns
        self.ua_patterns = [
            'skipfish',
        ]

        # Skipfish-specific patterns
        self.payload_patterns = [
            r'skipfish',
            r'sf[0-9]+',  # Skipfish injection markers
        ]

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Skipfish from request"""
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

        if payload_matches:
            confidence = min(90, 75 + len(payload_matches) * 5)
            return DetectionResult(
                tool=self.tool_name,
                confidence=confidence,
                method='payload',
                details={
                    'matched_patterns': payload_matches
                }
            )

        # Behavioral detection
        if context:
            request_rate = context.get('request_rate', 0)
            many_404s = context.get('many_404s', False)
            sequential_paths = context.get('sequential_paths', False)

            # Skipfish is fast and generates many 404s
            if request_rate > 8 and many_404s and sequential_paths:
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=70,
                    method='behavior',
                    details={
                        'request_rate': request_rate,
                        'many_404s': many_404s,
                        'sequential_paths': sequential_paths,
                        'behavior': 'fast_comprehensive_scanning'
                    }
                )

        return None
