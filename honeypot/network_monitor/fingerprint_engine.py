#!/usr/bin/env python3
"""
Fingerprint Engine for Tool Detection
Loads YAML fingerprints and matches traffic patterns against known tools
"""

import os
import yaml
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Fingerprint:
    """Represents a tool fingerprint"""
    name: str
    family: str
    description: str = ""
    repos: List[str] = field(default_factory=list)
    patterns: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0


@dataclass
class FingerprintMatch:
    """Result of fingerprint matching"""
    tool: str
    family: str
    repos: List[str]
    confidence: float
    matched_patterns: List[str]


class FingerprintEngine:
    """
    Engine to load and match fingerprints against traffic
    
    Usage:
        engine = FingerprintEngine('fingerprints/')
        matches = engine.match(context, metrics, http_data)
    """
    
    def __init__(self, fingerprints_dir: str = None):
        self.fingerprints: List[Fingerprint] = []
        
        if fingerprints_dir is None:
            # Default to fingerprints/ in same directory as this file
            fingerprints_dir = os.path.join(os.path.dirname(__file__), 'fingerprints')
        
        self._load_fingerprints(fingerprints_dir)
        logger.info(f"[FingerprintEngine] Loaded {len(self.fingerprints)} fingerprints")
    
    def _load_fingerprints(self, fingerprints_dir: str):
        """Load all YAML fingerprint files from directory"""
        if not os.path.exists(fingerprints_dir):
            logger.warning(f"[FingerprintEngine] Fingerprints directory not found: {fingerprints_dir}")
            return
        
        for filename in os.listdir(fingerprints_dir):
            if filename.endswith('.yaml') or filename.endswith('.yml'):
                filepath = os.path.join(fingerprints_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                        if data:
                            fp = Fingerprint(
                                name=data.get('name', filename),
                                family=data.get('family', 'unknown'),
                                description=data.get('description', ''),
                                repos=data.get('repos', []),
                                patterns=data.get('patterns', {}),
                                weight=data.get('weight', 1.0)
                            )
                            self.fingerprints.append(fp)
                            logger.debug(f"[FingerprintEngine] Loaded fingerprint: {fp.name}")
                except Exception as e:
                    logger.error(f"[FingerprintEngine] Error loading {filepath}: {e}")
    
    def match(self, context: dict, metrics: dict, http_data: dict = None) -> List[FingerprintMatch]:
        """
        Match traffic against all fingerprints
        
        Args:
            context: Traffic context (packet_times, ports, user_agent, paths, etc.)
            metrics: Calculated metrics (packet_rate, syn_rate, port_diversity, etc.)
            http_data: HTTP-specific data (user_agent, method, path, payload, etc.)
        
        Returns:
            List of FingerprintMatch sorted by confidence (highest first)
        """
        matches = []
        http_data = http_data or {}
        
        for fp in self.fingerprints:
            score, matched_patterns = self._calculate_match_score(fp, context, metrics, http_data)
            
            if score > 0.2:  # Minimum threshold
                matches.append(FingerprintMatch(
                    tool=fp.name,
                    family=fp.family,
                    repos=fp.repos,
                    confidence=min(1.0, score * fp.weight),
                    matched_patterns=matched_patterns
                ))
        
        # Sort by confidence descending
        matches.sort(key=lambda x: x.confidence, reverse=True)
        return matches
    
    def _calculate_match_score(self, fp: Fingerprint, context: dict, 
                               metrics: dict, http_data: dict) -> tuple:
        """Calculate how well traffic matches a fingerprint"""
        total_score = 0.0
        max_possible = 0.0
        matched_patterns = []
        
        patterns = fp.patterns
        
        # User-Agent matching (high weight)
        if 'user_agent' in patterns:
            max_possible += 0.4
            ua_score = self._match_user_agent(patterns['user_agent'], http_data, context)
            if ua_score > 0:
                total_score += ua_score * 0.4
                matched_patterns.append('user_agent')
        
        # HTTP patterns matching
        if 'http' in patterns:
            max_possible += 0.25
            http_score = self._match_http_patterns(patterns['http'], http_data, metrics)
            if http_score > 0:
                total_score += http_score * 0.25
                matched_patterns.append('http_patterns')
        
        # Payload matching (for SQL injection, XSS, etc.)
        if 'payload' in patterns:
            max_possible += 0.3
            payload_score = self._match_payload(patterns['payload'], http_data, context)
            if payload_score > 0:
                total_score += payload_score * 0.3
                matched_patterns.append('payload')
        
        # Path patterns matching
        if 'paths' in patterns:
            max_possible += 0.2
            path_score = self._match_paths(patterns['paths'], http_data, context)
            if path_score > 0:
                total_score += path_score * 0.2
                matched_patterns.append('paths')
        
        # Network patterns matching (for port scanners)
        if 'network' in patterns:
            max_possible += 0.35
            network_score = self._match_network_patterns(patterns['network'], metrics)
            if network_score > 0:
                total_score += network_score * 0.35
                matched_patterns.append('network')
        
        # TCP patterns matching
        if 'tcp' in patterns:
            max_possible += 0.25
            tcp_score = self._match_tcp_patterns(patterns['tcp'], context, metrics)
            if tcp_score > 0:
                total_score += tcp_score * 0.25
                matched_patterns.append('tcp')
        
        # Behavioral patterns matching
        if 'behavior' in patterns:
            max_possible += 0.2
            behavior_score = self._match_behavior(patterns['behavior'], context, metrics)
            if behavior_score > 0:
                total_score += behavior_score * 0.2
                matched_patterns.append('behavior')
        
        # Normalize score
        if max_possible > 0:
            normalized_score = total_score / max_possible
        else:
            normalized_score = 0.0
        
        return normalized_score, matched_patterns
    
    def _match_user_agent(self, ua_patterns: dict, http_data: dict, context: dict) -> float:
        """Match user-agent patterns"""
        user_agent = http_data.get('user_agent', '') or context.get('user_agent', '')
        if not user_agent:
            return 0.0
        
        user_agent_lower = user_agent.lower()
        
        contains = ua_patterns.get('contains', [])
        for pattern in contains:
            if pattern.lower() in user_agent_lower:
                return 1.0
        
        return 0.0
    
    def _match_http_patterns(self, http_patterns: dict, http_data: dict, metrics: dict) -> float:
        """Match HTTP-specific patterns"""
        score = 0.0
        checks = 0
        
        # Rate matching
        rate_min = http_patterns.get('rate_min')
        if rate_min is not None:
            checks += 1
            http_rate = metrics.get('packet_rate', 0)
            if http_rate >= rate_min:
                score += 1.0
        
        # Method matching
        methods = http_patterns.get('methods', [])
        if methods:
            checks += 1
            request_method = http_data.get('method', '').upper()
            if request_method in methods:
                score += 0.5
        
        return score / checks if checks > 0 else 0.0
    
    def _match_payload(self, payload_patterns: dict, http_data: dict, context: dict) -> float:
        """Match payload/body patterns (for SQL injection, etc.)"""
        # Get payload from multiple sources
        payload = ''
        if http_data:
            payload = str(http_data.get('body', '')) + str(http_data.get('path', ''))
            payload += str(http_data.get('args', ''))
        
        if context:
            payload += str(context.get('payload', ''))
        
        if not payload:
            return 0.0
        
        payload_lower = payload.lower()
        contains = payload_patterns.get('contains', [])
        matches = 0
        
        for pattern in contains:
            if pattern.lower() in payload_lower:
                matches += 1
        
        if len(contains) > 0:
            return min(1.0, matches / (len(contains) * 0.3))  # Partial matches OK
        
        return 0.0
    
    def _match_paths(self, path_patterns: dict, http_data: dict, context: dict) -> float:
        """Match path patterns"""
        path = http_data.get('path', '') or context.get('path', '')
        if not path:
            return 0.0
        
        path_lower = path.lower()
        contains = path_patterns.get('contains', [])
        matches = 0
        
        for pattern in contains:
            if pattern.lower() in path_lower:
                matches += 1
        
        if len(contains) > 0:
            return min(1.0, matches / len(contains))
        
        return 0.0
    
    def _match_network_patterns(self, network_patterns: dict, metrics: dict) -> float:
        """Match network-level patterns (for port scanners)"""
        score = 0.0
        checks = 0
        
        # PPS (packets per second) matching
        pps_min = network_patterns.get('pps_min')
        if pps_min is not None:
            checks += 1
            current_pps = metrics.get('packet_rate', 0)
            if current_pps >= pps_min:
                score += 1.0
            elif current_pps >= pps_min * 0.5:
                score += 0.5
        
        # SYN-only matching
        if network_patterns.get('syn_only'):
            checks += 1
            syn_ratio = metrics.get('syn_ratio', 0)
            if syn_ratio > 0.9:
                score += 1.0
            elif syn_ratio > 0.7:
                score += 0.5
        
        # No retries matching
        if network_patterns.get('no_retries'):
            checks += 1
            # This would need to be calculated from packet analysis
            # For now, assume high SYN ratio with no ACK means no retries
            syn_ratio = metrics.get('syn_ratio', 0)
            if syn_ratio > 0.95:
                score += 1.0
        
        return score / checks if checks > 0 else 0.0
    
    def _match_tcp_patterns(self, tcp_patterns: dict, context: dict, metrics: dict) -> float:
        """Match TCP-specific patterns"""
        score = 0.0
        checks = 0
        
        # Flag matching
        expected_flags = tcp_patterns.get('flags', [])
        if expected_flags:
            checks += 1
            # Check if traffic shows expected flag patterns
            if 'SYN' in expected_flags:
                syn_packets = metrics.get('syn_packets', 0)
                total_packets = metrics.get('total_packets', 1)
                if syn_packets / total_packets > 0.7:
                    score += 1.0
        
        return score / checks if checks > 0 else 0.0
    
    def _match_behavior(self, behavior_patterns: dict, context: dict, metrics: dict) -> float:
        """Match behavioral patterns"""
        score = 0.0
        checks = 0
        
        if behavior_patterns.get('high_request_rate'):
            checks += 1
            if metrics.get('packet_rate', 0) > 20:
                score += 1.0
        
        if behavior_patterns.get('sequential_paths'):
            checks += 1
            # Would need path history analysis
            # Approximate with port diversity
            if metrics.get('port_diversity', 0) < 5:
                score += 0.5
        
        if behavior_patterns.get('sql_injection_patterns'):
            checks += 1
            # Already handled by payload matching
            score += 0.5
        
        if behavior_patterns.get('high_rate_scanning'):
            checks += 1
            if metrics.get('packet_rate', 0) > 100:
                score += 1.0
        
        if behavior_patterns.get('extremely_high_rate'):
            checks += 1
            if metrics.get('packet_rate', 0) > 1000:
                score += 1.0
        
        return score / checks if checks > 0 else 0.0
    
    def get_similar_tools(self, family: str, exclude_tool: str = None) -> List[str]:
        """Get other tools in the same family"""
        similar = []
        for fp in self.fingerprints:
            if fp.family == family and fp.name != exclude_tool:
                similar.append(fp.name)
        return similar


# Global instance for easy import
_engine_instance = None

def get_fingerprint_engine() -> FingerprintEngine:
    """Get or create global fingerprint engine instance"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = FingerprintEngine()
    return _engine_instance
