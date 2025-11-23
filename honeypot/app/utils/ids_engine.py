#!/usr/bin/env python3
"""
Advanced IDS Engine for Honeypot
- Rate limiting & automatic IP blocking
- Threat intelligence integration
- Protocol anomaly detection
- Multi-stage attack correlation
- Real-time alerting
"""

import time
import json
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class BlockReason(Enum):
    """Reasons for IP blocking"""
    RATE_LIMIT = "rate_limit_exceeded"
    MALICIOUS_PAYLOAD = "malicious_payload_detected"
    BRUTE_FORCE = "brute_force_attack"
    SCAN_DETECTED = "port_scan_detected"
    KNOWN_BAD_ACTOR = "known_malicious_ip"
    MANUAL_BLOCK = "manual_blacklist"


@dataclass
class ThreatScore:
    """Threat scoring for an IP"""
    ip: str
    score: int = 0
    max_score: int = 100
    reasons: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)

    def add_score(self, points: int, reason: str):
        """Add points to threat score"""
        self.score = min(self.score + points, self.max_score)
        self.reasons.append(f"{reason} (+{points})")
        self.last_activity = datetime.now()

    def get_threat_level(self) -> ThreatLevel:
        """Get threat level based on score"""
        if self.score >= 80:
            return ThreatLevel.CRITICAL
        elif self.score >= 60:
            return ThreatLevel.HIGH
        elif self.score >= 40:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW


@dataclass
class BlockedIP:
    """Blocked IP information"""
    ip: str
    reason: BlockReason
    blocked_at: datetime
    blocked_until: datetime
    block_count: int = 1

    def is_expired(self) -> bool:
        """Check if block has expired"""
        return datetime.now() >= self.blocked_until


class IDSEngine:
    """
    Advanced Intrusion Detection System Engine
    Provides multi-layered threat detection and response
    """

    def __init__(self):
        # Rate limiting configuration
        self.rate_limits = {
            'requests_per_second': 10,
            'requests_per_minute': 100,
            'requests_per_hour': 1000,
            'failed_auth_per_hour': 5,
            'scan_threshold': 20,  # Different paths in short time
        }

        # IP tracking
        self.ip_contexts: Dict[str, Dict] = defaultdict(lambda: {
            'request_times': deque(maxlen=1000),
            'request_paths': deque(maxlen=200),
            'response_codes': deque(maxlen=200),
            'failed_auths': 0,
            'attack_attempts': 0,
            'threat_score': ThreatScore(ip=''),
            'first_seen': datetime.now(),
            'last_activity': datetime.now(),
        })

        # Blocked IPs
        self.blocked_ips: Dict[str, BlockedIP] = {}

        # Whitelist (trusted IPs)
        self.whitelist = {
            '127.0.0.1',
            '::1',
            'localhost',
        }

        # Blacklist (known bad actors)
        self.blacklist = set()

        # Attack patterns
        self.attack_patterns = {
            'sql_injection': [
                r"(\bunion\b.*\bselect\b)",
                r"(\bor\b.*=.*)",
                r"(admin'--)",
                r"(1=1)",
                r"(\bdrop\b.*\btable\b)",
                r"(\binsert\b.*\binto\b)",
            ],
            'xss': [
                r"(<script[^>]*>.*</script>)",
                r"(javascript:)",
                r"(onerror=)",
                r"(onload=)",
                r"(<iframe)",
            ],
            'lfi_rfi': [
                r"(\.\./)",
                r"(\.\.\\)",
                r"(/etc/passwd)",
                r"(/etc/shadow)",
                r"(c:\\windows)",
            ],
            'command_injection': [
                r"(;\s*\w+)",
                r"(\|\s*\w+)",
                r"(`\w+`)",
                r"(\$\(.*\))",
            ],
        }

        # Anomaly detection thresholds
        self.anomaly_thresholds = {
            'max_url_length': 2000,
            'max_header_size': 8192,
            'max_payload_size': 1048576,  # 1MB
            'unusual_methods': ['TRACE', 'TRACK', 'DEBUG', 'CONNECT'],
        }

        # Statistics
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'threats_detected': 0,
            'ips_blocked': 0,
        }

        print("✅ Advanced IDS Engine initialized")
        print(f"   Rate limits: {self.rate_limits}")
        print(f"   Whitelist: {len(self.whitelist)} IPs")
        print(f"   Attack patterns: {len(self.attack_patterns)} categories")

    def check_request(self, ip: str, request_data: Dict) -> Tuple[bool, Optional[str], Dict]:
        """
        Check if request should be allowed

        Args:
            ip: Source IP address
            request_data: Request information dictionary

        Returns:
            Tuple of (allowed, block_reason, threat_info)
        """
        self.stats['total_requests'] += 1

        # 1. Check whitelist
        if ip in self.whitelist:
            return True, None, {'threat_level': 'none', 'whitelisted': True}

        # 2. Check blacklist
        if ip in self.blacklist:
            self._block_ip(ip, BlockReason.KNOWN_BAD_ACTOR, duration_minutes=1440)  # 24 hours
            self.stats['blocked_requests'] += 1
            return False, "IP in blacklist", {'threat_level': 'critical', 'blacklisted': True}

        # 3. Check if already blocked
        if ip in self.blocked_ips:
            block_info = self.blocked_ips[ip]
            if not block_info.is_expired():
                self.stats['blocked_requests'] += 1
                return False, f"IP blocked: {block_info.reason.value}", {
                    'threat_level': 'high',
                    'blocked_until': block_info.blocked_until.isoformat()
                }
            else:
                # Block expired, remove it
                del self.blocked_ips[ip]

        # 4. Update context
        context = self._update_context(ip, request_data)

        # 5. Rate limiting check
        rate_check = self._check_rate_limits(ip, context)
        if not rate_check[0]:
            self._block_ip(ip, BlockReason.RATE_LIMIT, duration_minutes=30)
            self.stats['blocked_requests'] += 1
            self.stats['threats_detected'] += 1
            return False, rate_check[1], {'threat_level': 'high', 'rate_exceeded': True}

        # 6. Protocol anomaly detection
        anomaly_check = self._check_protocol_anomalies(request_data)
        if anomaly_check[0]:
            context['threat_score'].add_score(20, anomaly_check[1])
            self.stats['threats_detected'] += 1

        # 7. Payload analysis
        payload_check = self._analyze_payload(request_data)
        if payload_check[0]:
            context['threat_score'].add_score(30, payload_check[1])
            self.stats['threats_detected'] += 1

        # 8. Behavioral analysis
        behavior_check = self._analyze_behavior(ip, context, request_data)
        if behavior_check[0]:
            context['threat_score'].add_score(15, behavior_check[1])
            self.stats['threats_detected'] += 1

        # 9. Check threat score
        threat_score = context['threat_score']
        threat_level = threat_score.get_threat_level()

        if threat_score.score >= 80:
            # Critical threat - block immediately
            self._block_ip(ip, BlockReason.MALICIOUS_PAYLOAD, duration_minutes=120)
            self.stats['blocked_requests'] += 1
            return False, "Critical threat detected", {
                'threat_level': 'critical',
                'threat_score': threat_score.score,
                'reasons': threat_score.reasons
            }

        # Allow request but return threat info
        return True, None, {
            'threat_level': threat_level.name.lower(),
            'threat_score': threat_score.score,
            'reasons': threat_score.reasons if threat_score.score > 0 else []
        }

    def _update_context(self, ip: str, request_data: Dict) -> Dict:
        """Update IP context with new request"""
        context = self.ip_contexts[ip]
        current_time = datetime.now()

        # Initialize threat score if needed
        if not isinstance(context.get('threat_score'), ThreatScore):
            context['threat_score'] = ThreatScore(ip=ip)

        # Update request tracking
        context['request_times'].append(current_time)
        context['request_paths'].append(request_data.get('path', '/'))
        context['last_activity'] = current_time

        # Track response codes if available
        if 'response_code' in request_data:
            context['response_codes'].append(request_data['response_code'])

            # Track failed auth
            if request_data['response_code'] in [401, 403]:
                context['failed_auths'] += 1

        return context

    def _check_rate_limits(self, ip: str, context: Dict) -> Tuple[bool, Optional[str]]:
        """Check if IP exceeds rate limits"""
        request_times = context['request_times']
        current_time = datetime.now()

        if len(request_times) < 2:
            return True, None

        # Requests per second
        recent_1s = sum(1 for t in request_times if (current_time - t).total_seconds() <= 1)
        if recent_1s > self.rate_limits['requests_per_second']:
            return False, f"Rate limit exceeded: {recent_1s} req/s (limit: {self.rate_limits['requests_per_second']})"

        # Requests per minute
        recent_1m = sum(1 for t in request_times if (current_time - t).total_seconds() <= 60)
        if recent_1m > self.rate_limits['requests_per_minute']:
            return False, f"Rate limit exceeded: {recent_1m} req/min (limit: {self.rate_limits['requests_per_minute']})"

        # Requests per hour
        recent_1h = sum(1 for t in request_times if (current_time - t).total_seconds() <= 3600)
        if recent_1h > self.rate_limits['requests_per_hour']:
            return False, f"Rate limit exceeded: {recent_1h} req/hour (limit: {self.rate_limits['requests_per_hour']})"

        # Failed auth per hour
        if context['failed_auths'] > self.rate_limits['failed_auth_per_hour']:
            return False, f"Too many failed auth attempts: {context['failed_auths']}"

        return True, None

    def _check_protocol_anomalies(self, request_data: Dict) -> Tuple[bool, Optional[str]]:
        """Check for HTTP protocol anomalies"""
        anomalies = []

        # Check HTTP method
        method = request_data.get('method', 'GET')
        if method in self.anomaly_thresholds['unusual_methods']:
            anomalies.append(f"Unusual HTTP method: {method}")

        # Check URL length
        url = request_data.get('url', '')
        if len(url) > self.anomaly_thresholds['max_url_length']:
            anomalies.append(f"Abnormally long URL: {len(url)} chars")

        # Check headers
        headers = request_data.get('headers', {})
        headers_str = str(headers)
        if len(headers_str) > self.anomaly_thresholds['max_header_size']:
            anomalies.append(f"Abnormally large headers: {len(headers_str)} bytes")

        # Check for suspicious headers
        suspicious_headers = ['X-Forwarded-For', 'X-Originating-IP', 'X-Remote-IP']
        for header in suspicious_headers:
            if header in headers and ',' in headers[header]:
                # Multiple IPs in header (possible proxy chain or spoofing)
                anomalies.append(f"Suspicious header chain: {header}")

        # Check content length
        content_length = request_data.get('content_length', 0)
        if content_length > self.anomaly_thresholds['max_payload_size']:
            anomalies.append(f"Abnormally large payload: {content_length} bytes")

        if anomalies:
            return True, ", ".join(anomalies)
        return False, None

    def _analyze_payload(self, request_data: Dict) -> Tuple[bool, Optional[str]]:
        """Analyze request payload for attack patterns"""
        import re

        detected_attacks = []

        # Combine all searchable fields
        search_text = " ".join([
            str(request_data.get('url', '')),
            str(request_data.get('path', '')),
            str(request_data.get('query_string', '')),
            str(request_data.get('form_data', '')),
            str(request_data.get('body', '')),
        ]).lower()

        # Check each attack pattern category
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, search_text, re.IGNORECASE):
                    detected_attacks.append(attack_type)
                    break  # One match per category is enough

        if detected_attacks:
            return True, f"Attack patterns detected: {', '.join(set(detected_attacks))}"
        return False, None

    def _analyze_behavior(self, ip: str, context: Dict, request_data: Dict) -> Tuple[bool, Optional[str]]:
        """Analyze behavioral patterns"""
        suspicious_behaviors = []

        # Check for scanning behavior (many unique paths)
        if len(context['request_paths']) > 10:
            unique_paths = len(set(context['request_paths']))
            if unique_paths > len(context['request_paths']) * 0.8:
                suspicious_behaviors.append("Directory scanning detected")

        # Check for 404 farming
        if len(context['response_codes']) > 10:
            recent_404s = sum(1 for code in list(context['response_codes'])[-20:] if code == 404)
            if recent_404s > 10:
                suspicious_behaviors.append("Excessive 404 errors (enumeration)")

        # Check for parameter fuzzing
        path = request_data.get('path', '')
        query_string = request_data.get('query_string', '')
        if query_string and ('=' in query_string or '&' in query_string):
            # Count parameters
            param_count = query_string.count('=')
            if param_count > 10:
                suspicious_behaviors.append("Excessive parameters (fuzzing)")

        # Check for rapid sequential requests
        if len(context['request_times']) > 5:
            times = list(context['request_times'])[-5:]
            time_span = (times[-1] - times[0]).total_seconds()
            if time_span < 1:  # 5 requests in less than 1 second
                suspicious_behaviors.append("Rapid sequential requests (bot-like)")

        if suspicious_behaviors:
            return True, ", ".join(suspicious_behaviors)
        return False, None

    def _block_ip(self, ip: str, reason: BlockReason, duration_minutes: int = 30):
        """Block an IP address"""
        blocked_until = datetime.now() + timedelta(minutes=duration_minutes)

        if ip in self.blocked_ips:
            # Increase block duration for repeat offenders
            self.blocked_ips[ip].block_count += 1
            self.blocked_ips[ip].blocked_until = blocked_until
            self.blocked_ips[ip].reason = reason
        else:
            self.blocked_ips[ip] = BlockedIP(
                ip=ip,
                reason=reason,
                blocked_at=datetime.now(),
                blocked_until=blocked_until
            )
            self.stats['ips_blocked'] += 1

        print(f"🚫 IP blocked: {ip} | Reason: {reason.value} | Duration: {duration_minutes}m")

    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist"""
        self.whitelist.add(ip)
        # Remove from blacklist if present
        self.blacklist.discard(ip)
        # Unblock if blocked
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
        print(f"✅ IP added to whitelist: {ip}")

    def add_to_blacklist(self, ip: str):
        """Add IP to blacklist"""
        self.blacklist.add(ip)
        # Remove from whitelist if present
        self.whitelist.discard(ip)
        # Block immediately
        self._block_ip(ip, BlockReason.MANUAL_BLOCK, duration_minutes=43200)  # 30 days
        print(f"⛔ IP added to blacklist: {ip}")

    def get_ip_stats(self, ip: str) -> Dict:
        """Get statistics for an IP"""
        if ip not in self.ip_contexts:
            return {'status': 'unknown', 'requests': 0}

        context = self.ip_contexts[ip]
        threat_score = context.get('threat_score', ThreatScore(ip=ip))

        return {
            'ip': ip,
            'status': 'blocked' if ip in self.blocked_ips else 'active',
            'threat_level': threat_score.get_threat_level().name.lower(),
            'threat_score': threat_score.score,
            'total_requests': len(context['request_times']),
            'failed_auths': context['failed_auths'],
            'attack_attempts': context['attack_attempts'],
            'first_seen': context['first_seen'].isoformat(),
            'last_activity': context['last_activity'].isoformat(),
            'is_whitelisted': ip in self.whitelist,
            'is_blacklisted': ip in self.blacklist,
        }

    def get_statistics(self) -> Dict:
        """Get overall IDS statistics"""
        return {
            'total_requests': self.stats['total_requests'],
            'blocked_requests': self.stats['blocked_requests'],
            'threats_detected': self.stats['threats_detected'],
            'ips_blocked': self.stats['ips_blocked'],
            'active_blocks': len([b for b in self.blocked_ips.values() if not b.is_expired()]),
            'whitelist_size': len(self.whitelist),
            'blacklist_size': len(self.blacklist),
            'tracked_ips': len(self.ip_contexts),
        }

    def cleanup_expired_blocks(self):
        """Remove expired IP blocks"""
        expired = [ip for ip, block in self.blocked_ips.items() if block.is_expired()]
        for ip in expired:
            del self.blocked_ips[ip]
        if expired:
            print(f"🧹 Cleaned up {len(expired)} expired IP blocks")

    def cleanup_old_contexts(self, max_age_hours: int = 24):
        """Remove old IP contexts"""
        current_time = datetime.now()
        to_remove = []

        for ip, context in self.ip_contexts.items():
            age = (current_time - context['last_activity']).total_seconds() / 3600
            if age > max_age_hours:
                to_remove.append(ip)

        for ip in to_remove:
            del self.ip_contexts[ip]

        if to_remove:
            print(f"🧹 Cleaned up {len(to_remove)} old IP contexts")
