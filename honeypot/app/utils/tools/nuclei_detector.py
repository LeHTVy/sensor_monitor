"""
Nuclei Detection Module
Detects Nuclei vulnerability scanner
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class NucleiDetector(ToolDetector):
    """Detect Nuclei vulnerability scanner"""

    def __init__(self):
        super().__init__('nuclei')

        # User-Agent patterns
        self.ua_patterns = [
            'nuclei',
            'projectdiscovery',
        ]

        # Nuclei-specific patterns (from templates)
        self.payload_patterns = [
            r'nuclei',
            r'{{BaseURL}}',
            r'{{RootURL}}',
            r'{{Hostname}}',
            # Common nuclei test strings
            r'6d745f37652d3434',  # Nuclei interactsh ID pattern
        ]

        # Common paths that nuclei templates scan
        self.scan_paths = [
            '/.git/config',
            '/.env',
            '/.aws/credentials',
            '/api/v1',
            '/api/v2',
            '/actuator',
            '/admin',
            '/console',
            '/debug',
            '/.well-known/',
        ]

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Nuclei from request"""
        user_agent = request.headers.get('User-Agent', '')
        query_string = str(request.query_string.decode())
        form_data = str(request.form)
        path = request.path

        # Check User-Agent
        if self.check_user_agent(user_agent):
            confidence = 90 if 'nuclei' in user_agent.lower() else 80
            return DetectionResult(
                tool=self.tool_name,
                confidence=confidence,
                method='ua',
                details={
                    'user_agent': user_agent,
                    'is_projectdiscovery': 'projectdiscovery' in user_agent.lower()
                }
            )

        # Check payload patterns (nuclei template variables)
        combined_payload = f"{query_string} {form_data} {path}"
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
            sequential_paths = context.get('sequential_paths', False)

            # Pattern 1: Moderate rate with targeted paths
            if request_rate > 2 and sequential_paths:
                # Check if scanning sensitive paths
                if any(scan_path in path.lower() for scan_path in self.scan_paths):
                    return DetectionResult(
                        tool=self.tool_name,
                        confidence=70,
                        method='behavior',
                        details={
                            'request_rate': request_rate,
                            'sequential_paths': sequential_paths,
                            'path': path,
                            'behavior': 'template_based_scanning'
                        }
                    )

            # Pattern 2: Multiple unique paths (template execution)
            if sequential_paths and request_rate > 1:
                headers = dict(request.headers)
                # Nuclei often has minimal headers
                if len(headers) < 6:
                    return DetectionResult(
                        tool=self.tool_name,
                        confidence=65,
                        method='behavior',
                        details={
                            'sequential_paths': sequential_paths,
                            'header_count': len(headers),
                            'behavior': 'automated_template_scan'
                        }
                    )

        return None
