#!/usr/bin/env python3
"""
Enrichment Engine
Central module that enriches raw logs with tool detection, GeoIP, and OSINT data
"""

from typing import Dict
from datetime import datetime
from tool_detection import ToolDetector
from geoip_enricher import GeoIPEnricher
from osint_enricher import OSINTEnricher


class EnrichmentEngine:
    """Central enrichment pipeline for raw honeypot logs"""
    
    def __init__(self, enable_osint=True):
        """
        Initialize enrichment engine
        
        Args:
            enable_osint: Whether to enable OSINT lookups (can be slow/expensive)
        """
        self.tool_detector = ToolDetector()
        self.geoip_enricher = GeoIPEnricher()
        self.osint_enricher = OSINTEnricher() if enable_osint else None
        self.enable_osint = enable_osint
        
        print("✅ EnrichmentEngine initialized")
        print(f"   Tool Detection: ✓")
        print(f"   GeoIP: ✓")
        print(f"   OSINT: {'✓' if enable_osint else '✗ (disabled)'}")
    
    def enrich_log(self, raw_log: Dict) -> Dict:
        """
        Enrich a raw log with all available intelligence
        
        Args:
            raw_log: Raw log from honeypot
            
        Returns:
            Enriched log with tool detection, GeoIP, and OSINT data
        """
        ip = raw_log.get('ip', 'unknown')
        user_agent = raw_log.get('user_agent', '')
        path = raw_log.get('path', '')
        method = raw_log.get('method', 'GET')
        
        print(f"\n{'='*70}")
        print(f"🔍 Enriching log from {ip}")
        print(f"   Path: {path}")
        print(f"   Method: {method}")
        print(f"{'='*70}")
        
        # 1. Detect attack tool
        print("🛠️  Detecting attack tool...")
        detected_tool = self.tool_detector.detect(raw_log)
        tool_info = {
            'tool': detected_tool,
            'confidence': 95 if detected_tool != 'unknown' else 0,
            'method': 'signature_based'
        }
        
        # 2. GeoIP lookup
        print(f"🌍 Looking up GeoIP for {ip}...")
        geoip_data = self.geoip_enricher.enrich(ip)
        
        # 3. OSINT intelligence (if enabled)
        osint_data = {}
        threat_score = 0
        if self.enable_osint:
            print(f"🔎 Gathering OSINT data for {ip}...")
            osint_data = self.osint_enricher.enrich(ip)
            threat_score = self.osint_enricher.calculate_threat_score(osint_data)
        
        # 4. Detect attack techniques
        print("🎯 Detecting attack techniques...")
        # If log already has techniques (e.g. from packet_sniffer), use them
        existing_techniques = raw_log.get('attack_technique', [])
        if isinstance(existing_techniques, str):
            existing_techniques = [existing_techniques]
            
        web_techniques = self._detect_techniques(raw_log)
        
        # Merge techniques
        attack_techniques = list(set(existing_techniques + web_techniques))
        if 'unknown' in attack_techniques and len(attack_techniques) > 1:
            attack_techniques.remove('unknown')
        
        # 5. Determine threat level
        # If OSINT is disabled, use tool confidence as base for threat score
        if not self.enable_osint and threat_score == 0:
            threat_score = tool_info.get('confidence', 0)

        threat_level = self._calculate_threat_level(tool_info, attack_techniques, threat_score)
        
        # 6. Combine everything
        enriched_log = {
            **raw_log,  # Keep original data
            'attack_tool': tool_info.get('tool', 'unknown'),
            'attack_tool_info': tool_info,
            'attack_techniques': attack_techniques,
            'geoip': geoip_data,
            'osint': osint_data,
            'threat_score': threat_score,
            'threat_level': threat_level,
            'enriched_at': datetime.now().isoformat(),
            'enricher_version': '2.0.0'
        }
        
        print(f"\n📊 Enrichment Complete:")
        print(f"   Tool: {tool_info.get('tool', 'unknown')} ({tool_info.get('confidence', 0)}% confidence)")
        print(f"   Country: {geoip_data.get('country', 'Unknown')}")
        print(f"   Threat Level: {threat_level}")
        print(f"   Threat Score: {threat_score}/100")
        print(f"{'='*70}\n")
        
        return enriched_log
    
    def _detect_techniques(self, log: Dict) -> list:
        """Detect attack techniques from raw log"""
        techniques = []
        
        path = log.get('path', '').lower()
        args = str(log.get('args', {})).lower()
        form_data = str(log.get('form_data', {})).lower()
        method = log.get('method', 'GET')
        
        # SQL Injection
        sql_patterns = ['union', 'select', 'insert', 'delete', 'drop', 'or 1=1', "admin'--"]
        if any(p in args or p in form_data or p in path for p in sql_patterns):
            techniques.append('sql_injection')
        
        # XSS
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=']
        if any(p in args or p in form_data for p in xss_patterns):
            techniques.append('xss')
        
        # Path Traversal
        if '../' in path or '..\\' in path or '/etc/passwd' in path:
            techniques.append('path_traversal')
        
        # Command Injection
        cmd_patterns = [';', '|', '&', '`', '$(', 'exec', 'system']
        if any(p in args or p in form_data for p in cmd_patterns):
            techniques.append('command_injection')
        
        # File Upload
        if log.get('files'):
            techniques.append('file_upload')
        
        # Brute Force
        if path in ['/login', '/auth'] and method == 'POST':
            techniques.append('brute_force')
        
        # Reconnaissance
        recon_paths = ['/admin', '/phpmyadmin', '/wp-admin', '/.env', '/config', '/.git']
        if any(p in path for p in recon_paths):
            techniques.append('reconnaissance')
        
        return techniques if techniques else ['unknown']
    
    def _calculate_threat_level(self, tool_info: Dict, techniques: list, osint_score: int) -> str:
        """Calculate overall threat level"""
        score = 0
        
        # Tool confidence (0-40 points)
        confidence = tool_info.get('confidence', 0)
        if confidence >= 90:
            score += 40
        elif confidence >= 70:
            score += 30
        elif confidence >= 50:
            score += 20
        
        # Attack techniques (0-30 points)
        dangerous_techniques = ['sql_injection', 'command_injection', 'file_upload']
        if any(t in techniques for t in dangerous_techniques):
            score += 30
        elif len(techniques) > 1:
            score += 20
        elif 'unknown' not in techniques:
            score += 10
        
        # OSINT score (0-30 points)
        score += int(osint_score * 0.3)
        
        # Determine level
        if score >= 70:
            return 'critical'
        elif score >= 50:
            return 'high'
        elif score >= 30:
            return 'medium'
        else:
            return 'low'
