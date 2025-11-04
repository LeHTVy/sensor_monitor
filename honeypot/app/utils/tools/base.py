"""
Base Tool Detector Class
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from flask import Request


class DetectionResult:
    """Result of tool detection"""
    def __init__(self, tool: str, confidence: int, method: str = 'unknown', details: Optional[Dict] = None):
        self.tool = tool
        self.confidence = confidence  # 0-100
        self.method = method  # 'ua', 'payload', 'behavior', 'header', 'pattern'
        self.details = details or {}
    
    def to_dict(self) -> Dict:
        return {
            'tool': self.tool,
            'confidence': self.confidence,
            'method': self.method,
            'details': self.details
        }


class ToolDetector(ABC):
    """Base class for tool detectors"""
    
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.ua_patterns: List[str] = []
        self.payload_patterns: List[str] = []
        self.header_patterns: Dict[str, List[str]] = {}
        self.path_patterns: List[str] = []
        self.behavioral_patterns: Dict = {}
    
    @abstractmethod
    def detect(self, request: Request, context: Optional[Dict] = None) -> Optional[DetectionResult]:
        """
        Detect tool from request
        
        Args:
            request: Flask request object
            context: Additional context (IP history, rate, etc.)
        
        Returns:
            DetectionResult if tool detected, None otherwise
        """
        pass
    
    def check_user_agent(self, user_agent: str) -> bool:
        """Check if User-Agent matches tool patterns"""
        if not user_agent:
            return False
        ua_lower = user_agent.lower()
        return any(pattern.lower() in ua_lower for pattern in self.ua_patterns)
    
    def check_payload(self, query_string: str, form_data: str, body: str = '') -> bool:
        """Check if payload matches tool patterns"""
        combined = ' '.join([query_string.lower(), form_data.lower(), body.lower()])
        return any(pattern.lower() in combined for pattern in self.payload_patterns)
    
    def check_headers(self, headers: Dict) -> bool:
        """Check if headers match tool patterns"""
        for header_name, patterns in self.header_patterns.items():
            header_value = headers.get(header_name, '').lower()
            if any(pattern.lower() in header_value for pattern in patterns):
                return True
        return False
    
    def check_path(self, path: str) -> bool:
        """Check if path matches tool patterns"""
        path_lower = path.lower()
        return any(pattern.lower() in path_lower for pattern in self.path_patterns)
    
    def get_confidence(self, method: str, match_count: int = 1) -> int:
        """
        Calculate confidence based on detection method
        
        Args:
            method: Detection method ('ua', 'payload', 'behavior', etc.)
            match_count: Number of matching patterns
        
        Returns:
            Confidence score 0-100
        """
        base_scores = {
            'ua': 80,  # User-Agent is strong indicator
            'payload': 90,  # Payload signatures are very reliable
            'behavior': 70,  # Behavioral patterns are moderately reliable
            'header': 75,  # Header patterns are reliable
            'pattern': 65,  # General patterns are less reliable
        }
        
        base = base_scores.get(method, 50)
        
        # Increase confidence with multiple matches
        if match_count > 1:
            base = min(100, base + (match_count - 1) * 5)
        
        return base

