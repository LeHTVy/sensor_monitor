"""
Ffuf Detection Module
Detects Ffuf (Fuzz Faster U Fool) web fuzzer
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class FfufDetector(ToolDetector):
    """Detect Ffuf web fuzzer"""

    def __init__(self):
        super().__init__('ffuf')

        # User-Agent patterns
        self.ua_patterns = [
            'ffuf',
            'fuzz faster',
        ]

        # Ffuf characteristics:
        # - Very fast fuzzing (similar to gobuster but more flexible)
        # - Can fuzz parameters, headers, POST data
        # - Often uses FUZZ keyword in requests
        # - Supports custom wordlists

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Ffuf from request"""
        user_agent = request.headers.get('User-Agent', '')
        query_string = str(request.query_string.decode())
        form_data = str(request.form)
        path = request.path

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

        # Check for FUZZ keyword (ffuf's default placeholder)
        combined_payload = f"{query_string} {form_data} {path}".lower()
        if 'fuzz' in combined_payload:
            return DetectionResult(
                tool=self.tool_name,
                confidence=85,
                method='payload',
                details={
                    'fuzz_keyword': True,
                    'location': 'query_string' if 'fuzz' in query_string.lower() else 'form_data' if 'fuzz' in form_data.lower() else 'path'
                }
            )

        # Behavioral detection
        if context:
            request_rate = context.get('request_rate', 0)
            many_404s = context.get('many_404s', False)
            sequential_paths = context.get('sequential_paths', False)
            varying_params = context.get('varying_params', False)

            # Pattern 1: Fast fuzzing with varying parameters
            if request_rate > 8 and varying_params:
                confidence = min(85, 65 + int(request_rate * 2))
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=confidence,
                    method='behavior',
                    details={
                        'request_rate': request_rate,
                        'varying_params': varying_params,
                        'behavior': 'parameter_fuzzing'
                    }
                )

            # Pattern 2: Fast scanning with many 404s (directory fuzzing)
            if request_rate > 10 and many_404s and sequential_paths:
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=80,
                    method='behavior',
                    details={
                        'request_rate': request_rate,
                        'many_404s': many_404s,
                        'sequential_paths': sequential_paths,
                        'behavior': 'directory_fuzzing'
                    }
                )

            # Pattern 3: POST fuzzing (form data fuzzing)
            if request.method == 'POST' and varying_params and request_rate > 5:
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=75,
                    method='behavior',
                    details={
                        'method': 'POST',
                        'varying_params': varying_params,
                        'request_rate': request_rate,
                        'behavior': 'post_fuzzing'
                    }
                )

        return None
