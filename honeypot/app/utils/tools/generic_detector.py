"""
Generic Tool Detector
Detects unknown security tools based on behavioral patterns and heuristics
"""

import re
from flask import Request
from typing import Optional, Dict
from .base import ToolDetector, DetectionResult


class GenericDetector(ToolDetector):
    """
    Generic detector for unknown tools
    Uses heuristics and behavioral analysis to identify security tools
    """

    def __init__(self):
        super().__init__('generic_scanner')

        # Suspicious User-Agent keywords
        self.suspicious_ua_keywords = [
            # Common tool indicators
            'scanner', 'scan', 'bot', 'crawler', 'exploit', 'hack', 'pentest',
            'security', 'vuln', 'test', 'audit', 'attack', 'probe', 'fuzzer',
            # Programming languages/frameworks often used in tools
            'python', 'perl', 'ruby', 'php', 'java', 'golang', 'rust',
            'http-client', 'urllib', 'requests', 'axios', 'fetch',
            # Suspicious patterns
            'automated', 'script', 'tool', 'framework', 'kit',
            # Missing common browser indicators
            'mozilla',  # (used to check if NOT present)
        ]

        # Suspicious path patterns
        self.suspicious_paths = [
            # Admin/config files
            r'/admin', r'/login', r'/phpmyadmin', r'/wp-admin', r'/wp-login',
            r'/console', r'/dashboard', r'/portal', r'/manager',
            # Config files
            r'\.env', r'\.git', r'\.svn', r'\.hg', r'config\.(php|xml|json|yml)',
            r'\.aws', r'\.ssh', r'credentials',
            # Backup files
            r'\.bak', r'\.old', r'\.backup', r'\.save', r'\.tmp',
            r'backup', r'old', r'test',
            # Common scan targets
            r'robots\.txt', r'sitemap\.xml', r'\.well-known',
            r'crossdomain\.xml', r'security\.txt',
            # API endpoints
            r'/api/', r'/v1/', r'/v2/', r'/graphql', r'/rest',
            # Shell/upload
            r'shell', r'upload', r'file', r'exec', r'cmd',
        ]

        # Suspicious payload patterns
        self.suspicious_payloads = [
            # Injection attempts
            r"['\"]?\s*(union|select|insert|delete|drop|update|exec|execute)",
            r'<script[\s/>]', r'javascript:', r'onerror=', r'onload=',
            r'\.\./', r'/etc/passwd', r'/etc/shadow',
            r';\s*(cat|ls|id|whoami|uname|pwd)', r'\|\s*(cat|ls|id)',
            # Encoding tricks
            r'%00', r'%0d%0a', r'%2e%2e', r'%252e',
            # Path traversal
            r'\.\.[\\/]', r'\.\.%2f', r'\.\.%5c',
        ]

    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """
        Detect unknown security tools based on heuristics
        """
        user_agent = request.headers.get('User-Agent', '')
        path = request.path
        query_string = str(request.query_string.decode())
        form_data = str(request.form)
        headers = dict(request.headers)

        score = 0
        indicators = []

        # 1. User-Agent analysis
        ua_score, ua_indicators = self._analyze_user_agent(user_agent, headers)
        score += ua_score
        indicators.extend(ua_indicators)

        # 2. Path analysis
        path_score, path_indicators = self._analyze_path(path)
        score += path_score
        indicators.extend(path_indicators)

        # 3. Payload analysis
        payload_score, payload_indicators = self._analyze_payload(query_string, form_data)
        score += payload_score
        indicators.extend(payload_indicators)

        # 4. Behavioral analysis
        if context:
            behavior_score, behavior_indicators = self._analyze_behavior(context, request)
            score += behavior_score
            indicators.extend(behavior_indicators)

        # Convert score to confidence (0-100)
        confidence = min(100, score)

        # Only return detection if confidence >= 50
        if confidence >= 50:
            return DetectionResult(
                tool=self.tool_name,
                confidence=confidence,
                method='heuristic',
                details={
                    'indicators': indicators,
                    'score': score,
                    'analysis': {
                        'user_agent_suspicious': ua_score > 0,
                        'path_suspicious': path_score > 0,
                        'payload_suspicious': payload_score > 0,
                        'behavior_suspicious': context and behavior_score > 0
                    }
                }
            )

        return None

    def _analyze_user_agent(self, user_agent: str, headers: Dict) -> tuple[int, list]:
        """Analyze User-Agent for suspicious patterns"""
        score = 0
        indicators = []

        ua_lower = user_agent.lower()

        # Check 1: Empty or very short User-Agent
        if not user_agent or len(user_agent) < 10:
            score += 15
            indicators.append('empty_or_short_ua')

        # Check 2: Missing common browser indicators
        browser_indicators = ['mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera']
        has_browser_indicator = any(bi in ua_lower for bi in browser_indicators)

        if not has_browser_indicator and user_agent:
            score += 10
            indicators.append('no_browser_signature')

        # Check 3: Suspicious keywords
        for keyword in self.suspicious_ua_keywords:
            if keyword in ua_lower:
                if keyword in ['scanner', 'exploit', 'hack', 'pentest', 'attack', 'vuln']:
                    score += 25
                    indicators.append(f'suspicious_keyword:{keyword}')
                elif keyword in ['python', 'perl', 'ruby', 'golang']:
                    score += 15
                    indicators.append(f'scripting_language:{keyword}')
                elif keyword in ['bot', 'crawler']:
                    score += 10
                    indicators.append(f'bot_indicator:{keyword}')

        # Check 4: Missing common headers
        common_headers = ['Accept', 'Accept-Language', 'Accept-Encoding']
        missing_headers = [h for h in common_headers if h not in headers]

        if len(missing_headers) >= 2:
            score += 10
            indicators.append(f'missing_headers:{len(missing_headers)}')

        # Check 5: Very minimal headers (< 4)
        if len(headers) < 4:
            score += 15
            indicators.append('minimal_headers')

        return score, indicators

    def _analyze_path(self, path: str) -> tuple[int, list]:
        """Analyze request path for suspicious patterns"""
        score = 0
        indicators = []

        path_lower = path.lower()

        # Check against suspicious paths
        for pattern in self.suspicious_paths:
            if re.search(pattern, path_lower, re.IGNORECASE):
                # Admin/config paths = higher score
                if any(admin in pattern for admin in ['admin', 'config', 'env', 'git', 'backup']):
                    score += 15
                    indicators.append(f'sensitive_path:{pattern[:20]}')
                else:
                    score += 8
                    indicators.append(f'suspicious_path:{pattern[:20]}')

        return score, indicators

    def _analyze_payload(self, query_string: str, form_data: str) -> tuple[int, list]:
        """Analyze payload for attack patterns"""
        score = 0
        indicators = []

        combined = f"{query_string} {form_data}".lower()

        # Check against suspicious payloads
        for pattern in self.suspicious_payloads:
            if re.search(pattern, combined, re.IGNORECASE):
                score += 20
                indicators.append(f'attack_pattern:{pattern[:30]}')

        return score, indicators

    def _analyze_behavior(self, context: Dict, request: Request) -> tuple[int, list]:
        """Analyze behavioral patterns"""
        score = 0
        indicators = []

        request_rate = context.get('request_rate', 0)
        many_404s = context.get('many_404s', False)
        sequential_paths = context.get('sequential_paths', False)
        varying_params = context.get('varying_params', False)

        # Check 1: High request rate
        if request_rate > 10:
            score += 25
            indicators.append(f'very_high_rate:{request_rate:.1f}')
        elif request_rate > 5:
            score += 15
            indicators.append(f'high_rate:{request_rate:.1f}')
        elif request_rate > 2:
            score += 8
            indicators.append(f'moderate_rate:{request_rate:.1f}')

        # Check 2: Many 404s (scanning)
        if many_404s:
            score += 15
            indicators.append('many_404s')

        # Check 3: Sequential paths (enumeration)
        if sequential_paths:
            score += 12
            indicators.append('sequential_scanning')

        # Check 4: Varying parameters (fuzzing)
        if varying_params:
            score += 12
            indicators.append('parameter_fuzzing')

        # Check 5: HTTP method anomalies
        method = request.method
        if method in ['OPTIONS', 'HEAD', 'TRACE', 'CONNECT', 'PATCH']:
            score += 10
            indicators.append(f'unusual_method:{method}')

        return score, indicators
