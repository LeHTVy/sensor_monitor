"""
Acunetix Detection Module
Detects Acunetix web vulnerability scanner
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class AcunetixDetector(ToolDetector):
    """Detect Acunetix scanner"""

    def __init__(self):
        super().__init__('acunetix')

        # User-Agent patterns
        self.ua_patterns = [
            'acunetix',
            'acunetix-product',
            'acunetix web vulnerability scanner',
        ]

        # Acunetix-specific test patterns
        self.payload_patterns = [
            r'acunetix',
            r'acustart',
            r'acuend',
            r'acunetix_wvs',
            r'acunetix_wvs_security_test',
            r'by_wvs',
            r'acunetix-wvs-test',
            # Acunetix test markers
            r'testasp\.vulnweb\.com',
            r'testaspnet\.vulnweb\.com',
            r'testphp\.vulnweb\.com',
        ]

        # Header patterns
        self.header_patterns = {
            'User-Agent': ['acunetix'],
            'Acunetix-Aspect': ['*'],
            'Acunetix-Aspect-Password': ['*'],
            'Acunetix-Aspect-Queries': ['*'],
        }

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """Detect Acunetix from request"""
        user_agent = request.headers.get('User-Agent', '')
        query_string = str(request.query_string.decode())
        form_data = str(request.form)
        headers = dict(request.headers)

        # Check User-Agent (very high confidence)
        if self.check_user_agent(user_agent):
            return DetectionResult(
                tool=self.tool_name,
                confidence=95,
                method='ua',
                details={
                    'user_agent': user_agent
                }
            )

        # Check Acunetix-specific headers
        acunetix_headers = [h for h in headers.keys() if 'acunetix' in h.lower()]
        if acunetix_headers:
            return DetectionResult(
                tool=self.tool_name,
                confidence=98,
                method='header',
                details={
                    'acunetix_headers': acunetix_headers
                }
            )

        # Check payload patterns
        combined_payload = f"{query_string} {form_data}".lower()
        payload_matches = []

        for pattern in self.payload_patterns:
            if re.search(pattern, combined_payload, re.IGNORECASE):
                payload_matches.append(pattern)

        if payload_matches:
            confidence = min(95, 75 + len(payload_matches) * 5)
            return DetectionResult(
                tool=self.tool_name,
                confidence=confidence,
                method='payload',
                details={
                    'matched_patterns': payload_matches[:5]
                }
            )

        # Behavioral detection
        if context:
            request_rate = context.get('request_rate', 0)
            sequential_paths = context.get('sequential_paths', False)

            # Acunetix scans comprehensively but not as fast as nmap/masscan
            if request_rate > 3 and sequential_paths:
                # Check for typical web vuln scanner behavior
                if any(vuln_path in request.path.lower() for vuln_path in [
                    'xss', 'sqli', 'test', 'vuln', 'scan', 'inject'
                ]):
                    return DetectionResult(
                        tool=self.tool_name,
                        confidence=70,
                        method='behavior',
                        details={
                            'request_rate': request_rate,
                            'sequential_paths': sequential_paths,
                            'path': request.path,
                            'behavior': 'vuln_scanning'
                        }
                    )

        return None
