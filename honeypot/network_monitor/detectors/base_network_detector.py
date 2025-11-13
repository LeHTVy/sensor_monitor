"""
Base class for network-layer tool detectors
"""

from typing import Optional, Dict, List
from abc import ABC, abstractmethod


class BaseNetworkDetector(ABC):
    """
    Abstract base class for network layer detectors
    Detects security tools based on packet patterns
    """

    def __init__(self, tool_name: str):
        self.tool_name = tool_name

    @abstractmethod
    def detect(self, src_ip: str, context: dict, metrics: dict, packet) -> Optional[Dict]:
        """
        Analyze network traffic and detect if it matches this tool

        Args:
            src_ip: Source IP address
            context: Traffic context for this IP (packet history, etc.)
            metrics: Calculated metrics (packet_rate, syn_rate, etc.)
            packet: The current packet (scapy packet object)

        Returns:
            Detection result dict if detected, None otherwise
            {
                'tool': str,
                'confidence': int (0-100),
                'method': str,
                'details': dict,
                'techniques': list
            }
        """
        pass

    def create_detection(self, confidence: int, method: str,
                        details: dict = None, techniques: list = None) -> Dict:
        """
        Helper to create standardized detection result

        Args:
            confidence: Detection confidence (0-100)
            method: Detection method used
            details: Additional detection details
            techniques: Attack techniques detected

        Returns:
            Detection result dictionary
        """
        return {
            'tool': self.tool_name,
            'confidence': min(100, max(0, confidence)),
            'method': method,
            'details': details or {},
            'techniques': techniques or ['port_scan']
        }
