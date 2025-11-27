"""
Web Scanner Detector
Detects web vulnerability scanners and SQL injection attempts via payload inspection
"""

import re
from typing import Optional, Dict
from scapy.all import TCP, Raw
from .base_network_detector import BaseNetworkDetector


class WebScannerDetector(BaseNetworkDetector):
    """
    Detects web scanners (Nuclei, Nikto, etc.) and SQL injection
    by inspecting TCP payloads for known signatures.
    """

    def __init__(self):
        super().__init__('web_scanner')

        # Compile regex signatures for performance
        self.signatures = {
            'nuclei': [
                re.compile(rb'User-Agent:.*nuclei', re.IGNORECASE),
                re.compile(rb'X-Nuclei-Version', re.IGNORECASE)
            ],
            'nikto': [
                re.compile(rb'User-Agent:.*Nikto', re.IGNORECASE),
                re.compile(rb'/nikto-test', re.IGNORECASE)
            ],
            'sql_injection': [
                re.compile(rb'UNION.*SELECT', re.IGNORECASE),
                re.compile(rb'AND\s+1=1', re.IGNORECASE),
                re.compile(rb'information_schema', re.IGNORECASE),
                re.compile(rb'WAITFOR\s+DELAY', re.IGNORECASE)
            ],
            'bbot_web': [
                re.compile(rb'User-Agent:.*bbot', re.IGNORECASE),
                re.compile(rb'X-BBOT', re.IGNORECASE)
            ],
            'gobuster': [
                re.compile(rb'User-Agent:.*gobuster', re.IGNORECASE)
            ],
            'dirbuster': [
                re.compile(rb'User-Agent:.*DirBuster', re.IGNORECASE)
            ]
        }

    def detect(self, src_ip: str, context: dict, metrics: dict, packet) -> Optional[Dict]:
        """Detect web scanning patterns in TCP payloads"""
        
        # We need TCP packets with payloads
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return None

        # Get payload data
        try:
            payload = packet[Raw].load
        except Exception:
            return None

        if not payload:
            return None

        # Check against signatures
        for tool, patterns in self.signatures.items():
            for pattern in patterns:
                if pattern.search(payload):
                    return self._create_detection_result(tool, payload)

        return None

    def _create_detection_result(self, tool: str, payload: bytes) -> Dict:
        """Create detection result based on matched tool"""
        
        confidence = 100  # Payload matches are high confidence
        
        # Determine specific tool name and techniques
        tool_name = tool
        techniques = ['web_scan']
        
        if tool == 'sql_injection':
            tool_name = 'sql_injector'
            techniques.append('sql_injection')
            techniques.append('exploitation')
        elif tool == 'nuclei':
            techniques.append('vulnerability_scan')
        elif tool == 'nikto':
            techniques.append('vulnerability_scan')
        elif tool in ['gobuster', 'dirbuster']:
            techniques.append('directory_bruteforce')
        
        # Extract a snippet of the payload for details (safe decode)
        try:
            payload_snippet = payload[:100].decode('utf-8', errors='ignore')
        except:
            payload_snippet = str(payload[:100])

        return self.create_detection(
            confidence=confidence,
            method='payload_inspection',
            details={
                'matched_tool': tool,
                'payload_snippet': payload_snippet
            },
            techniques=techniques
        )
