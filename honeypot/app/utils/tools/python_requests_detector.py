"""
Python Requests Detection Module
Detects Python requests library (commonly used in custom attack scripts)
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class PythonRequestsDetector(ToolDetector):
    """Detect Python requests library"""

    def __init__(self):
        super().__init__('python-requests')

        # User-Agent patterns
        self.ua_patterns = [
            'python-requests',
            'python-urllib',
            'python/3.',
            'python/2.',
        ]

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Python requests from request"""
        user_agent = request.headers.get('User-Agent', '')

        # Check User-Agent
        if self.check_user_agent(user_agent):
            # Python requests can be legitimate or malicious (automation/scripts)
            confidence = 55

            # Check for suspicious behavior
            if context:
                request_rate = context.get('request_rate', 0)
                sequential_paths = context.get('sequential_paths', False)
                varying_params = context.get('varying_params', False)

                # If automated scanning behavior, increase confidence
                if request_rate > 3 or sequential_paths or varying_params:
                    confidence = 75

                # Very fast Python script = likely attack
                if request_rate > 10:
                    confidence = 85

            return DetectionResult(
                tool=self.tool_name,
                confidence=confidence,
                method='ua',
                details={
                    'user_agent': user_agent,
                    'note': 'Python scripts often used for automation/attacks'
                }
            )

        return None
