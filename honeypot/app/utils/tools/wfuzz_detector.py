"""
Wfuzz/FFUF Detection Module
Detects web application fuzzers
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class WfuzzDetector(ToolDetector):
    """Detect Wfuzz/FFUF fuzzing tools"""
    
    def __init__(self):
        super().__init__('wfuzz')
        
        # User-Agent patterns
        self.ua_patterns = [
            'wfuzz',
            'ffuf',
        ]
        
        # Wfuzz payload patterns (FUZZ token, etc.)
        self.payload_patterns = [
            'fuzz',
            'wfuzz',
            'ffuf',
            # Wfuzz often uses FUZZ token in parameters
            '=FUZZ',
            '=fuzz',
        ]
        
        # Behavioral: Rapid requests with varying parameters
        self.behavioral_patterns = {
            'varying_params': True,
            'rapid_requests': True,
        }
    
    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Wfuzz from request"""
        user_agent = request.headers.get('User-Agent', '')
        query_string = str(request.query_string.decode())
        form_data = str(request.form)
        
        # Check User-Agent
        if self.check_user_agent(user_agent):
            tool_name = 'wfuzz' if 'wfuzz' in user_agent.lower() else 'ffuf'
            return DetectionResult(
                tool=tool_name,
                confidence=self.get_confidence('ua'),
                method='ua',
                details={
                    'user_agent': user_agent
                }
            )
        
        # Check payload patterns (FUZZ token)
        combined_payload = f"{query_string} {form_data}".lower()
        if self.check_payload(query_string, form_data):
            return DetectionResult(
                tool=self.tool_name,
                confidence=80,
                method='payload',
                details={
                    'query_string': query_string[:200],
                    'pattern': 'fuzz_token'
                }
            )
        
        # Behavioral: Rapid requests with varying parameters
        if context and context.get('request_rate', 0) > 5:
            if context.get('varying_params', False):
                return DetectionResult(
                    tool=self.tool_name,
                    confidence=65,
                    method='behavior',
                    details={
                        'request_rate': context.get('request_rate'),
                        'behavior': 'rapid_varying_params'
                    }
                )
        
        return None

