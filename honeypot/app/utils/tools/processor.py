"""
Tool Processor
Combines all tool detectors and processes requests
"""

import re
from typing import Dict, List, Optional
from flask import Request
from datetime import datetime, timedelta
from collections import defaultdict, deque

from .base import ToolDetector, DetectionResult
from .nmap_detector import NmapDetector
from .sqlmap_detector import SqlmapDetector
from .nikto_detector import NiktoDetector
from .burp_detector import BurpDetector
from .zap_detector import ZapDetector
from .metasploit_detector import MetasploitDetector
from .dirb_detector import DirbDetector
from .hydra_detector import HydraDetector
from .wfuzz_detector import WfuzzDetector
from .cobalt_strike_detector import CobaltStrikeDetector
# New detectors (15 additional tools)
from .gobuster_detector import GobusterDetector
from .masscan_detector import MasscanDetector
from .ffuf_detector import FfufDetector
from .acunetix_detector import AcunetixDetector
from .nuclei_detector import NucleiDetector
from .commix_detector import CommixDetector
from .beef_detector import BeefDetector
from .shodan_detector import ShodanDetector
from .censys_detector import CensysDetector
from .curl_detector import CurlDetector
from .wget_detector import WgetDetector
from .python_requests_detector import PythonRequestsDetector
from .skipfish_detector import SkipfishDetector
from .w3af_detector import W3afDetector
from .xsstrike_detector import XSStrikeDetector
# Generic detector for unknown tools
from .generic_detector import GenericDetector


class ToolProcessor:
    """
    Processes requests through all tool detectors
    Maintains context for behavioral detection
    """
    
    def __init__(self):
        # Initialize all detectors (25 tools total)
        self.detectors: List[ToolDetector] = [
            # Original 10 detectors
            NmapDetector(),
            SqlmapDetector(),
            NiktoDetector(),
            BurpDetector(),
            ZapDetector(),
            MetasploitDetector(),
            DirbDetector(),
            HydraDetector(),
            WfuzzDetector(),
            CobaltStrikeDetector(),
            # New 15 detectors
            GobusterDetector(),
            MasscanDetector(),
            FfufDetector(),
            AcunetixDetector(),
            NucleiDetector(),
            CommixDetector(),
            BeefDetector(),
            ShodanDetector(),
            CensysDetector(),
            CurlDetector(),
            WgetDetector(),
            PythonRequestsDetector(),
            SkipfishDetector(),
            W3afDetector(),
            XSStrikeDetector(),
        ]

        # Add generic detector LAST (lowest priority)
        # Generic detector should only trigger if no specific tool detected
        self.generic_detector = GenericDetector()

        print(f"✅ ToolProcessor initialized with {len(self.detectors)} specific detectors + 1 generic detector")
        print(f"   Supported tools: {', '.join([d.tool_name for d in self.detectors])}")
        
        # Context tracking for behavioral detection
        self.ip_contexts: Dict[str, Dict] = defaultdict(lambda: {
            'request_times': deque(maxlen=100),  # Last 100 requests
            'request_paths': deque(maxlen=100),
            'response_codes': deque(maxlen=100),
            'failed_auths': 0,
            'last_reset': datetime.now(),
        })
        
        # Reset contexts every hour
        self.context_reset_interval = timedelta(hours=1)
    
    def process_request(self, request: Request, ip: str) -> Dict:
        """
        Process request through all detectors
        
        Args:
            request: Flask request object
            ip: Source IP address
        
        Returns:
            Detection result dictionary with tool, confidence, method, details
        """
        # Update context for this IP
        context = self._update_context(ip, request)
        
        # Run all detectors
        detections: List[DetectionResult] = []
        
        for detector in self.detectors:
            try:
                result = detector.detect(request, context)
                if result:
                    detections.append(result)
            except Exception as e:
                # Log error but continue with other detectors
                print(f"⚠️ Error in detector {detector.tool_name}: {e}")
                continue
        
        # Select best detection (highest confidence)
        if detections:
            # Sort by confidence (descending)
            detections.sort(key=lambda x: x.confidence, reverse=True)
            best_detection = detections[0]

            # If multiple detections with high confidence, combine info
            if len(detections) > 1 and detections[1].confidence >= 70:
                # Multiple high-confidence detections = very suspicious
                best_detection.confidence = min(100, best_detection.confidence + 10)
                best_detection.details['multiple_detections'] = [
                    {'tool': d.tool, 'confidence': d.confidence, 'method': d.method}
                    for d in detections[:3]  # Top 3
                ]

            return best_detection.to_dict()

        # No specific tool detected - try generic detector
        try:
            generic_result = self.generic_detector.detect(request, context)
            if generic_result:
                return generic_result.to_dict()
        except Exception as e:
            print(f"⚠️ Error in generic detector: {e}")

        # No detection found at all
        return {
            'tool': 'unknown',
            'confidence': 0,
            'method': 'none',
            'details': {}
        }
    
    def _update_context(self, ip: str, request: Request) -> Dict:
        """
        Update and return context for behavioral detection
        
        Args:
            ip: Source IP address
            request: Flask request object
        
        Returns:
            Context dictionary for behavioral detection
        """
        ctx = self.ip_contexts[ip]
        current_time = datetime.now()
        
        # Reset context if needed
        if current_time - ctx['last_reset'] > self.context_reset_interval:
            ctx['request_times'].clear()
            ctx['request_paths'].clear()
            ctx['response_codes'].clear()
            ctx['failed_auths'] = 0
            ctx['last_reset'] = current_time
        
        # Add current request to context
        ctx['request_times'].append(current_time)
        ctx['request_paths'].append(request.path)
        
        # Calculate request rate (requests per second)
        if len(ctx['request_times']) >= 2:
            time_span = (ctx['request_times'][-1] - ctx['request_times'][0]).total_seconds()
            if time_span > 0:
                request_rate = len(ctx['request_times']) / time_span
            else:
                request_rate = 0
        else:
            request_rate = 0
        
        # Check for many 404s
        many_404s = False
        if len(ctx['response_codes']) > 5:
            # Check recent response codes for 404s
            recent_codes = list(ctx['response_codes'])[-20:]
            recent_404s = sum(1 for code in recent_codes if code == 404)
            # If more than 30% are 404s, likely scanning
            if recent_404s > 5 or (len(recent_codes) > 10 and recent_404s / len(recent_codes) > 0.3):
                many_404s = True
        # Also check if we have many unique paths but few successful responses
        # (indicates scanning many paths, most returning 404)
        if len(ctx['request_paths']) > 10:
            unique_paths = len(set(ctx['request_paths']))
            if unique_paths > len(ctx['request_paths']) * 0.7 and len(ctx['response_codes']) > 0:
                # Many unique paths but few successful responses
                success_codes = sum(1 for code in ctx['response_codes'] if 200 <= code < 300)
                if success_codes < len(ctx['response_codes']) * 0.2:
                    many_404s = True
        
        # Check for sequential paths (scanning pattern)
        sequential_paths = False
        if len(ctx['request_paths']) > 5:
            recent_paths = list(ctx['request_paths'])[-15:]
            
            # Pattern 1: Many unique paths (scanning different endpoints)
            unique_paths = len(set(recent_paths))
            if unique_paths > len(recent_paths) * 0.8:  # High uniqueness
                sequential_paths = True
            
            # Pattern 2: Paths with numeric sequences (e.g., /test1, /test2, /test3)
            numeric_patterns = 0
            for path in recent_paths:
                # Check for numeric patterns in path
                if re.search(r'/\w*\d+', path) or re.search(r'\d+\.\w+', path):
                    numeric_patterns += 1
            if numeric_patterns > len(recent_paths) * 0.4:
                sequential_paths = True
            
            # Pattern 3: Common scan paths (robots.txt, sitemap.xml, etc.)
            scan_paths = ['/robots.txt', '/sitemap.xml', '/.well-known', '/favicon.ico', 
                         '/admin', '/login', '/test', '/index', '/wp-admin', '/phpmyadmin']
            scan_path_count = sum(1 for path in recent_paths if any(sp in path.lower() for sp in scan_paths))
            if scan_path_count > 3:  # Multiple scan paths
                sequential_paths = True
        
        # Check for varying parameters (fuzzing pattern)
        varying_params = False
        if len(ctx['request_paths']) > 5:
            # If paths vary but follow similar structure
            path_variations = len(set(ctx['request_paths']))
            if path_variations > len(ctx['request_paths']) * 0.7:  # High variation
                varying_params = True
        
        # Check for failed auth attempts
        if request.path.lower() in ['/login', '/auth', '/signin']:
            # Note: Would need actual response code to determine failed auth
            # For now, we'll track login attempts
            pass
        
        # Build context dictionary
        context = {
            'request_rate': request_rate,
            'many_404s': many_404s,
            'sequential_paths': sequential_paths,
            'varying_params': varying_params,
            'many_failed_auths': ctx['failed_auths'] > 10,
            'rapid_auth_attempts': ctx['failed_auths'] > 5 and request_rate > 5,
        }
        
        return context
    
    def update_response_code(self, ip: str, response_code: int):
        """
        Update response code for context tracking
        
        Args:
            ip: Source IP address
            response_code: HTTP response code
        """
        if ip in self.ip_contexts:
            ctx = self.ip_contexts[ip]
            ctx['response_codes'].append(response_code)
            
            # Track failed auth attempts
            if response_code == 401 or response_code == 403:
                ctx['failed_auths'] += 1
    
    def get_ip_statistics(self, ip: str) -> Dict:
        """
        Get statistics for an IP address
        
        Args:
            ip: Source IP address
        
        Returns:
            Statistics dictionary
        """
        if ip not in self.ip_contexts:
            return {}
        
        ctx = self.ip_contexts[ip]
        
        # Calculate current request rate
        if len(ctx['request_times']) >= 2:
            time_span = (ctx['request_times'][-1] - ctx['request_times'][0]).total_seconds()
            if time_span > 0:
                request_rate = len(ctx['request_times']) / time_span
            else:
                request_rate = 0
        else:
            request_rate = 0
        
        return {
            'total_requests': len(ctx['request_times']),
            'request_rate': request_rate,
            'unique_paths': len(set(ctx['request_paths'])),
            'failed_auths': ctx['failed_auths'],
            'recent_404s': sum(1 for code in list(ctx['response_codes'])[-20:] if code == 404),
        }

