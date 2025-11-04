"""
SQLMap Detection Module
Detects SQLMap automated SQL injection tool
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class SqlmapDetector(ToolDetector):
    """Detect SQLMap tool"""
    
    def __init__(self):
        super().__init__('sqlmap')
        
        # User-Agent patterns
        self.ua_patterns = [
            'sqlmap',
            'sqlmap/',
        ]
        
        # SQLMap payload signatures (from sqlmap repository patterns)
        self.payload_patterns = [
            # SQLMap specific patterns
            'sqlmap',
            'union.*select',
            '1=1.*--',
            '1=1.*#',
            'or 1=1',
            'or 1=1--',
            'or 1=1#',
            'admin\'--',
            'admin\'#',
            # SQLMap specific parameter names
            'sqlmapid=',
            'sqlmap=',
            # SQLMap test patterns
            'benchmark(',
            'sleep(',
            'waitfor delay',
            'pg_sleep(',
            # Boolean-based blind patterns
            'and 1=1',
            'and 1=2',
            'and true',
            'and false',
        ]
        
        # Header patterns
        self.header_patterns = {
            'User-Agent': ['sqlmap'],
        }
    
    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect SQLMap from request"""
        user_agent = request.headers.get('User-Agent', '')
        query_string = str(request.query_string.decode())
        form_data = str(request.form)
        
        # Check User-Agent (very high confidence)
        if self.check_user_agent(user_agent):
            return DetectionResult(
                tool=self.tool_name,
                confidence=95,  # SQLMap UA is very distinctive
                method='ua',
                details={
                    'user_agent': user_agent,
                    'matched_pattern': 'sqlmap'
                }
            )
        
        # Check payload patterns (high confidence - SQLMap has distinctive payloads)
        payload_matches = []
        combined_payload = f"{query_string} {form_data}".lower()
        
        for pattern in self.payload_patterns:
            if re.search(pattern, combined_payload, re.IGNORECASE):
                payload_matches.append(pattern)
        
        if payload_matches:
            # Multiple payload matches = higher confidence
            confidence = min(95, 70 + len(payload_matches) * 5)
            return DetectionResult(
                tool=self.tool_name,
                confidence=confidence,
                method='payload',
                details={
                    'matched_patterns': payload_matches[:5],  # Limit to 5 for logging
                    'query_string': query_string[:200],
                    'form_data': form_data[:200]
                }
            )
        
        # Check headers
        if self.check_headers(dict(request.headers)):
            return DetectionResult(
                tool=self.tool_name,
                confidence=75,
                method='header',
                details={}
            )
        
        return None

