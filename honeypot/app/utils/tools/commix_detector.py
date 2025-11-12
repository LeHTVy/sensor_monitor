"""
Commix Detection Module
Detects Commix command injection exploitation tool
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class CommixDetector(ToolDetector):
    """Detect Commix command injection tool"""

    def __init__(self):
        super().__init__('commix')

        # User-Agent patterns
        self.ua_patterns = [
            'commix',
            'commix/',
        ]

        # Commix-specific payload patterns
        self.payload_patterns = [
            r'commix',
            # Time-based command injection
            r'sleep\s*\(\s*\d+\s*\)',
            r'ping\s+-[nc]\s+\d+',
            r'timeout\s+/t\s+\d+',
            # Echo-based detection
            r'echo\s+[a-zA-Z0-9]+',
            r'printf\s+',
            # Command separators
            r';\s*id\s*;',
            r';\s*whoami\s*;',
            r';\s*uname\s*;',
            r'\|\s*id\s*\|',
            r'\|\s*whoami\s*\|',
            # File-based payloads
            r'cat\s+/etc/passwd',
            r'cat\s+/etc/shadow',
            # Blind injection markers
            r'\$\{IFS\}',
            r'\$IFS\$',
        ]

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Commix from request"""
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
            # Multiple command injection patterns = very high confidence
            confidence = min(95, 80 + len(payload_matches) * 3)
            return DetectionResult(
                tool=self.tool_name,
                confidence=confidence,
                method='payload',
                details={
                    'matched_patterns': payload_matches[:5],
                    'injection_type': self._classify_injection(payload_matches)
                }
            )

        return None

    def _classify_injection(self, matches):
        """Classify the type of command injection"""
        matches_str = ' '.join(matches)

        if any(pattern in matches_str for pattern in ['sleep', 'ping', 'timeout']):
            return 'time_based'
        elif any(pattern in matches_str for pattern in ['echo', 'printf']):
            return 'echo_based'
        elif any(pattern in matches_str for pattern in ['cat', 'passwd']):
            return 'file_based'
        else:
            return 'blind'
