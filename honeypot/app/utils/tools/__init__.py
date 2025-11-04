"""
Tool Detection Module
Detects various security tools and attack frameworks from request patterns
"""

from .base import ToolDetector, DetectionResult
from .processor import ToolProcessor

__all__ = ['ToolDetector', 'DetectionResult', 'ToolProcessor']

