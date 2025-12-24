#!/usr/bin/env python3
"""
STIX 2.1 Formatter for Threat Intelligence API
Converts honeypot attack data to STIX 2.1 format
"""

import uuid
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional


class STIXFormatter:
    """
    Converts honeypot attack data to STIX 2.1 format
    Reference: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
    """
    
    def __init__(self, identity_name: str = "Honeypot Sensor Monitor"):
        """
        Initialize STIX formatter
        
        Args:
            identity_name: Name of the identity producing the intelligence
        """
        self.identity_name = identity_name
        self.identity_id = self._generate_uuid("identity", identity_name)
    
    def _generate_uuid(self, stix_type: str, value: str) -> str:
        """Generate deterministic UUID for STIX objects"""
        namespace = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")  # Custom namespace
        return f"{stix_type}--{uuid.uuid5(namespace, f'{stix_type}:{value}')}"
    
    def _get_attack_labels(self, log: Dict) -> List[str]:
        """Get STIX labels based on attack data"""
        labels = ["anomalous-activity"]
        
        attack_tool = log.get("attack_tool", "").lower()
        if attack_tool:
            labels.append(f"attack-tool:{attack_tool}")
        
        # Add labels based on threat level
        threat_level = log.get("threat_level", "").lower()
        if "critical" in threat_level or "high" in threat_level:
            labels.append("high-severity")
        
        # Add labels based on attack technique
        techniques = log.get("attack_techniques", log.get("attack_technique", []))
        if isinstance(techniques, list):
            for technique in techniques[:3]:  # Limit to 3
                labels.append(f"technique:{technique}")
        
        return labels
    
    def create_identity(self) -> Dict:
        """Create STIX Identity object for the honeypot"""
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": self.identity_id,
            "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "name": self.identity_name,
            "description": "Honeypot sensor monitoring system for threat intelligence collection",
            "identity_class": "system",
            "sectors": ["technology"],
            "contact_information": "security@honeypot.local"
        }
    
    def log_to_indicator(self, log: Dict) -> Dict:
        """
        Convert a single attack log to STIX Indicator
        
        Args:
            log: Attack log from Elasticsearch
            
        Returns:
            STIX 2.1 Indicator object
        """
        src_ip = log.get("src_ip", log.get("ip", "unknown"))
        attack_tool = log.get("attack_tool", "unknown")
        timestamp = log.get("timestamp", datetime.utcnow().isoformat())
        
        # Create deterministic ID based on IP and tool
        indicator_id = self._generate_uuid("indicator", f"{src_ip}:{attack_tool}:{timestamp[:10]}")
        
        # Build STIX pattern
        pattern = f"[ipv4-addr:value = '{src_ip}']"
        
        # Get labels
        labels = self._get_attack_labels(log)
        
        # Build name and description
        name = f"Malicious IP - {attack_tool.upper()} Activity"
        description = f"IP {src_ip} detected using {attack_tool}"
        
        if log.get("geoip", {}).get("country"):
            description += f" from {log['geoip']['country']}"
        
        threat_score = log.get("threat_score", 0)
        if threat_score:
            description += f". Threat score: {threat_score}/100"
        
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "name": name,
            "description": description,
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": timestamp,
            "labels": labels,
            "confidence": min(100, max(0, threat_score if threat_score else 50)),
            "created_by_ref": self.identity_id,
            "external_references": [
                {
                    "source_name": "honeypot-sensor",
                    "description": f"Captured from honeypot at {timestamp}"
                }
            ]
        }
        
        # Add kill chain phases if attack tool is known
        kill_chain = self._get_kill_chain(attack_tool)
        if kill_chain:
            indicator["kill_chain_phases"] = kill_chain
        
        return indicator
    
    def log_to_observed_data(self, log: Dict) -> Dict:
        """
        Convert attack log to STIX Observed-Data object
        """
        src_ip = log.get("src_ip", log.get("ip", "unknown"))
        timestamp = log.get("timestamp", datetime.utcnow().isoformat())
        
        observed_id = self._generate_uuid("observed-data", f"{src_ip}:{timestamp}")
        
        # Build SCO (STIX Cyber Observable) references
        objects = {}
        
        # IPv4 Address SCO
        ip_ref = "0"
        objects[ip_ref] = {
            "type": "ipv4-addr",
            "value": src_ip
        }
        
        # Network Traffic SCO
        if log.get("dst_port") or log.get("port"):
            port = log.get("dst_port", log.get("port", 0))
            protocol = log.get("protocol", "tcp").lower()
            objects["1"] = {
                "type": "network-traffic",
                "src_ref": ip_ref,
                "dst_port": port,
                "protocols": [protocol]
            }
        
        # HTTP Request SCO (if available)
        if log.get("method") and log.get("path"):
            objects["2"] = {
                "type": "http-request-ext",
                "request_method": log.get("method", "GET"),
                "request_value": log.get("path", "/")
            }
            if log.get("user_agent"):
                objects["2"]["request_header"] = {
                    "User-Agent": log.get("user_agent")
                }
        
        return {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_id,
            "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "first_observed": timestamp,
            "last_observed": timestamp,
            "number_observed": 1,
            "object_refs": list(objects.keys()),
            "objects": objects,
            "created_by_ref": self.identity_id
        }
    
    def ip_to_stix_object(self, ip: str, log: Dict) -> Dict:
        """
        Create comprehensive STIX object for an IP address lookup
        """
        attack_tool = log.get("attack_tool", "unknown")
        geoip = log.get("geoip", {}) if isinstance(log.get("geoip"), dict) else {}
        osint = log.get("osint", {}) if isinstance(log.get("osint"), dict) else {}
        
        # Create indicator
        indicator = self.log_to_indicator(log)
        
        # Create attack-pattern if attack tool is known
        objects = [indicator]
        
        if attack_tool and attack_tool != "unknown":
            attack_pattern = self._create_attack_pattern(attack_tool, log)
            objects.append(attack_pattern)
            
            # Create relationship
            relationship = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": self._generate_uuid("relationship", f"{indicator['id']}:indicates:{attack_pattern['id']}"),
                "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "relationship_type": "indicates",
                "source_ref": indicator["id"],
                "target_ref": attack_pattern["id"]
            }
            objects.append(relationship)
        
        # Create location if GeoIP available
        if geoip.get("country"):
            location = {
                "type": "location",
                "spec_version": "2.1",
                "id": self._generate_uuid("location", geoip.get("country", "unknown")),
                "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "country": geoip.get("country", "Unknown"),
                "region": geoip.get("region", ""),
                "city": geoip.get("city", "")
            }
            if geoip.get("lat") and geoip.get("lon"):
                location["latitude"] = geoip.get("lat")
                location["longitude"] = geoip.get("lon")
            objects.append(location)
        
        return self.create_bundle(objects)
    
    def _create_attack_pattern(self, tool: str, log: Dict) -> Dict:
        """Create STIX Attack-Pattern for known tools"""
        tool_lower = tool.lower()
        
        # Map tools to MITRE ATT&CK
        mitre_mapping = {
            "nmap": {"technique": "T1046", "name": "Network Service Discovery"},
            "sqlmap": {"technique": "T1190", "name": "Exploit Public-Facing Application"},
            "hydra": {"technique": "T1110", "name": "Brute Force"},
            "nikto": {"technique": "T1595", "name": "Active Scanning"},
            "nuclei": {"technique": "T1595", "name": "Active Scanning"},
            "dirsearch": {"technique": "T1083", "name": "File and Directory Discovery"},
            "ffuf": {"technique": "T1083", "name": "File and Directory Discovery"},
            "gobuster": {"technique": "T1083", "name": "File and Directory Discovery"},
            "wpscan": {"technique": "T1595", "name": "Active Scanning"},
            "metasploit": {"technique": "T1203", "name": "Exploitation for Client Execution"},
        }
        
        mitre = mitre_mapping.get(tool_lower, {"technique": "T1595", "name": "Active Scanning"})
        
        return {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": self._generate_uuid("attack-pattern", tool_lower),
            "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "name": f"{tool.upper()} - {mitre['name']}",
            "description": f"Attack pattern associated with {tool} tool",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": mitre["technique"],
                    "url": f"https://attack.mitre.org/techniques/{mitre['technique']}/"
                }
            ],
            "kill_chain_phases": self._get_kill_chain(tool_lower)
        }
    
    def _get_kill_chain(self, tool: str) -> List[Dict]:
        """Get kill chain phases for a tool"""
        tool_lower = tool.lower() if tool else ""
        
        phases_map = {
            "nmap": [{"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"}],
            "sqlmap": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
            "hydra": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
            "nikto": [{"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"}],
            "nuclei": [{"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"}],
            "dirsearch": [{"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"}],
            "ffuf": [{"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"}],
            "gobuster": [{"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"}],
            "wpscan": [{"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"}],
            "metasploit": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
        }
        
        return phases_map.get(tool_lower, [{"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"}])
    
    def create_bundle(self, objects: List[Dict]) -> Dict:
        """
        Create STIX Bundle containing multiple objects
        
        Args:
            objects: List of STIX objects
            
        Returns:
            STIX 2.1 Bundle
        """
        # Add identity as first object
        all_objects = [self.create_identity()] + objects
        
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": all_objects
        }
    
    def logs_to_bundle(self, logs: List[Dict]) -> Dict:
        """
        Convert multiple logs to a STIX Bundle with Indicators
        
        Args:
            logs: List of attack logs
            
        Returns:
            STIX 2.1 Bundle with all indicators
        """
        indicators = []
        seen_ips = set()
        
        for log in logs:
            src_ip = log.get("src_ip", log.get("ip", ""))
            if not src_ip or src_ip in seen_ips:
                continue
            
            seen_ips.add(src_ip)
            indicator = self.log_to_indicator(log)
            indicators.append(indicator)
        
        return self.create_bundle(indicators)


# Global instance
_stix_formatter = None


def get_stix_formatter() -> STIXFormatter:
    """Get or create global STIX formatter instance"""
    global _stix_formatter
    if _stix_formatter is None:
        _stix_formatter = STIXFormatter()
    return _stix_formatter
