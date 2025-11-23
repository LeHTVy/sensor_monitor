#!/usr/bin/env python3
"""
OSINT Enrichment Module
Integrates with threat intelligence platforms for IP reputation and context
"""

import os
import requests
from typing import Dict
from datetime import datetime, timedelta


class OSINTEnricher:
    """Enriches IP addresses with threat intelligence from multiple sources"""
    
    def __init__(self):
        # API Keys from environment
        self.shodan_key = os.getenv('SHODAN_API_KEY', '')
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY', '')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        
        # Cache to avoid repeated API calls
        self.cache = {}
        self.cache_ttl = timedelta(hours=24)
        
        print(f"✅ OSINT Enricher initialized")
        print(f"   Shodan: {'✓' if self.shodan_key else '✗'}")
        print(f"   AbuseIPDB: {'✓' if self.abuseipdb_key else '✗'}")
        print(f"   VirusTotal: {'✓' if self.virustotal_key else '✗'}")
    
    def enrich(self, ip: str) -> Dict:
        """
        Get OSINT data for an IP address
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Dictionary with threat intelligence data
        """
        # Check cache first
        if ip in self.cache:
            cached_data, cached_time = self.cache[ip]
            if datetime.now() - cached_time < self.cache_ttl:
                return cached_data
        
        # Gather data from all sources
        osint_data = {
            'shodan': self._query_shodan(ip) if self.shodan_key else {},
            'abuseipdb': self._query_abuseipdb(ip) if self.abuseipdb_key else {},
            'virustotal': self._query_virustotal(ip) if self.virustotal_key else {},
            'enriched_at': datetime.now().isoformat()
        }
        
        # Cache the result
        self.cache[ip] = (osint_data, datetime.now())
        
        return osint_data
    
    def _query_shodan(self, ip: str) -> Dict:
        """Query Shodan for IP information"""
        try:
            response = requests.get(
                f'https://api.shodan.io/shodan/host/{ip}',
                params={'key': self.shodan_key},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'open_ports': data.get('ports', []),
                    'services': [
                        {
                            'port': svc.get('port'),
                            'protocol': svc.get('transport'),
                            'product': svc.get('product', 'Unknown'),
                            'version': svc.get('version', '')
                        }
                        for svc in data.get('data', [])
                    ],
                    'hostnames': data.get('hostnames', []),
                    'os': data.get('os', 'Unknown'),
                    'vulns': list(data.get('vulns', {}).keys()),
                    'tags': data.get('tags', []),
                    'last_update': data.get('last_update', 'Unknown')
                }
            elif response.status_code == 404:
                return {'error': 'IP not found in Shodan'}
            else:
                return {'error': f'Shodan API returned {response.status_code}'}
                
        except Exception as e:
            print(f"⚠️  Shodan error for {ip}: {e}")
            return {'error': str(e)}
    
    def _query_abuseipdb(self, ip: str) -> Dict:
        """Query AbuseIPDB for abuse reports"""
        try:
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                headers={'Key': self.abuseipdb_key, 'Accept': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'num_distinct_users': data.get('numDistinctUsers', 0),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'is_tor': data.get('isTor', False),
                    'country_code': data.get('countryCode', 'Unknown'),
                    'usage_type': data.get('usageType', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'domain': data.get('domain', 'Unknown'),
                    'last_reported': data.get('lastReportedAt', 'Never')
                }
            else:
                return {'error': f'AbuseIPDB API returned {response.status_code}'}
                
        except Exception as e:
            print(f"⚠️  AbuseIPDB error for {ip}: {e}")
            return {'error': str(e)}
    
    def _query_virustotal(self, ip: str) -> Dict:
        """Query VirusTotal for malicious activity"""
        try:
            response = requests.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers={'x-apikey': self.virustotal_key},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                attributes = data.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'reputation': attributes.get('reputation', 0),
                    'as_owner': attributes.get('as_owner', 'Unknown'),
                    'network': attributes.get('network', 'Unknown'),
                    'country': attributes.get('country', 'Unknown')
                }
            else:
                return {'error': f'VirusTotal API returned {response.status_code}'}
                
        except Exception as e:
            print(f"⚠️  VirusTotal error for {ip}: {e}")
            return {'error': str(e)}
    
    def calculate_threat_score(self, osint_data: Dict) -> int:
        """
        Calculate overall threat score (0-100) based on OSINT data
        
        Args:
            osint_data: OSINT data from enrich()
            
        Returns:
            Threat score from 0 (benign) to 100 (highly malicious)
        """
        score = 0
        
        # AbuseIPDB score (40% weight)
        abuse_data = osint_data.get('abuseipdb', {})
        if 'abuse_confidence_score' in abuse_data:
            score += abuse_data['abuse_confidence_score'] * 0.4
        
        # VirusTotal score (30% weight)
        vt_data = osint_data.get('virustotal', {})
        if 'malicious' in vt_data:
            malicious = vt_data.get('malicious', 0)
            suspicious = vt_data.get('suspicious', 0)
            total = malicious + suspicious + vt_data.get('harmless', 0)
            if total > 0:
                vt_score = ((malicious * 2 + suspicious) / total) * 100
                score += vt_score * 0.3
        
        # Shodan indicators (30% weight)
        shodan_data = osint_data.get('shodan', {})
        if 'vulns' in shodan_data and len(shodan_data['vulns']) > 0:
            score += min(30, len(shodan_data['vulns']) * 10)
        
        return min(100, int(score))
