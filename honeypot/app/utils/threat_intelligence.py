#!/usr/bin/env python3
"""
Threat Intelligence Integration
Enriches attack data with external threat intelligence sources:
- Shodan API (IP reputation, open ports, vulnerabilities)
- AbuseIPDB (IP reputation, abuse reports)
- GreyNoise (Internet scanner detection)
"""

import os
import json
import requests
from datetime import datetime, timedelta
from typing import Dict, Optional
import time


class ThreatIntelligenceEnricher:
    """
    Enriches IP data with threat intelligence from multiple sources
    """

    def __init__(self):
        # API Keys
        self.shodan_api_key = os.getenv('SHODAN_API_KEY', '7ROdb5EjnZ5kO71MJNgC9mQURAcmS3pz')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY', '')

        # Cache for API results (reduce API calls)
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour

        # Rate limiting
        self.last_shodan_call = 0
        self.shodan_rate_limit = 1  # 1 second between calls (free tier: 1 req/sec)

        print("✅ Threat Intelligence Enricher initialized")
        print(f"   Shodan API: {'Enabled' if self.shodan_api_key else 'Disabled'}")
        print(f"   AbuseIPDB: {'Enabled' if self.abuseipdb_api_key else 'Disabled'}")

    def enrich_ip(self, ip: str) -> Dict:
        """
        Enrich IP address with all available threat intelligence

        Args:
            ip: IP address to enrich

        Returns:
            Dictionary with enriched data from all sources
        """
        # Check cache first
        if ip in self.cache:
            cached_data, cached_time = self.cache[ip]
            if time.time() - cached_time < self.cache_ttl:
                print(f"📦 Using cached threat intelligence for {ip}")
                return cached_data

        enriched_data = {
            'ip': ip,
            'enrichment_timestamp': datetime.now().isoformat(),
            'shodan': {},
            'abuseipdb': {},
            'reputation_score': 0,  
            'threat_level': 'unknown',  
            'is_known_scanner': False,
            'is_vpn_proxy': False,
            'is_tor_exit': False,
            'open_ports': [],
            'vulnerabilities': [],
            'malware_families': [],
            'attack_history': {},
        }

        # Skip private IPs
        if self._is_private_ip(ip):
            enriched_data['threat_level'] = 'safe'
            enriched_data['is_private'] = True
            return enriched_data

        # Enrich from Shodan
        if self.shodan_api_key:
            shodan_data = self._query_shodan(ip)
            if shodan_data:
                enriched_data['shodan'] = shodan_data
                self._parse_shodan_data(shodan_data, enriched_data)

        # Enrich from AbuseIPDB
        if self.abuseipdb_api_key:
            abuse_data = self._query_abuseipdb(ip)
            if abuse_data:
                enriched_data['abuseipdb'] = abuse_data
                self._parse_abuseipdb_data(abuse_data, enriched_data)

        # Calculate overall threat level
        enriched_data['threat_level'] = self._calculate_threat_level(enriched_data)

        # Cache result
        self.cache[ip] = (enriched_data, time.time())

        return enriched_data

    def _query_shodan(self, ip: str) -> Optional[Dict]:
        """
        Query Shodan API for IP information

        Returns detailed information about:
        - Open ports and services
        - Vulnerabilities (CVEs)
        - Organization/ISP
        - Tags (malware, scanner, compromised, etc.)
        - Operating system
        - Software versions
        """
        try:
            # Rate limiting (free tier: 1 request/second)
            current_time = time.time()
            time_since_last_call = current_time - self.last_shodan_call
            if time_since_last_call < self.shodan_rate_limit:
                time.sleep(self.shodan_rate_limit - time_since_last_call)

            print(f"🔍 Querying Shodan for {ip}...")

            url = f"https://api.shodan.io/shodan/host/{ip}"
            params = {'key': self.shodan_api_key}

            response = requests.get(url, params=params, timeout=10)
            self.last_shodan_call = time.time()

            if response.status_code == 200:
                data = response.json()
                print(f"✅ Shodan data retrieved for {ip}")
                return data
            elif response.status_code == 404:
                print(f"ℹ️  No Shodan data for {ip} (not scanned yet)")
                return None
            else:
                print(f"⚠️  Shodan API error: {response.status_code}")
                return None

        except Exception as e:
            print(f"❌ Error querying Shodan: {e}")
            return None

    def _query_abuseipdb(self, ip: str) -> Optional[Dict]:
        """
        Query AbuseIPDB for IP reputation

        Returns:
        - Abuse confidence score (0-100)
        - Number of reports
        - Last reported date
        - Categories of abuse
        """
        if not self.abuseipdb_api_key:
            return None

        try:
            print(f"🔍 Querying AbuseIPDB for {ip}...")

            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': True
            }

            response = requests.get(url, headers=headers, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                print(f"✅ AbuseIPDB data retrieved for {ip}")
                return data.get('data', {})
            else:
                print(f"⚠️  AbuseIPDB API error: {response.status_code}")
                return None

        except Exception as e:
            print(f"❌ Error querying AbuseIPDB: {e}")
            return None

    def _parse_shodan_data(self, shodan_data: Dict, enriched_data: Dict):
        """Parse Shodan response and extract useful information"""

        # Open ports
        if 'ports' in shodan_data:
            enriched_data['open_ports'] = shodan_data['ports']
            enriched_data['reputation_score'] += min(len(shodan_data['ports']) * 2, 20)

        # Tags (malware, scanner, compromised, etc.)
        if 'tags' in shodan_data and shodan_data['tags']:
            tags = shodan_data['tags']
            enriched_data['shodan']['tags'] = tags

            # Check for malicious tags
            malicious_tags = ['malware', 'botnet', 'scanner', 'compromised', 'tor', 'vpn']
            for tag in tags:
                if any(mal_tag in tag.lower() for mal_tag in malicious_tags):
                    enriched_data['reputation_score'] += 15

            # Scanner detection
            if any('scan' in tag.lower() for tag in tags):
                enriched_data['is_known_scanner'] = True
                enriched_data['reputation_score'] += 20

            # VPN/Proxy detection
            if any(tag.lower() in ['vpn', 'proxy', 'anonymizer'] for tag in tags):
                enriched_data['is_vpn_proxy'] = True
                enriched_data['reputation_score'] += 10

            # Tor exit node
            if any('tor' in tag.lower() for tag in tags):
                enriched_data['is_tor_exit'] = True
                enriched_data['reputation_score'] += 25

        # Vulnerabilities (CVEs)
        if 'vulns' in shodan_data and shodan_data['vulns']:
            enriched_data['vulnerabilities'] = list(shodan_data['vulns'])
            enriched_data['reputation_score'] += len(shodan_data['vulns']) * 5

        # Operating System
        if 'os' in shodan_data:
            enriched_data['shodan']['os'] = shodan_data['os']

        # Organization/ISP
        if 'org' in shodan_data:
            enriched_data['shodan']['organization'] = shodan_data['org']

            # Cloud provider detection
            cloud_providers = ['amazon', 'google', 'microsoft', 'digitalocean', 'ovh', 'hetzner']
            if any(provider in shodan_data['org'].lower() for provider in cloud_providers):
                enriched_data['shodan']['is_cloud'] = True

        # ISP
        if 'isp' in shodan_data:
            enriched_data['shodan']['isp'] = shodan_data['isp']

        # ASN
        if 'asn' in shodan_data:
            enriched_data['shodan']['asn'] = shodan_data['asn']

        # Services and banners (detailed)
        if 'data' in shodan_data:
            services = []
            for item in shodan_data['data']:
                service_info = {
                    'port': item.get('port'),
                    'transport': item.get('transport'),
                    'product': item.get('product'),
                    'version': item.get('version'),
                    'timestamp': item.get('timestamp')
                }
                services.append(service_info)
            enriched_data['shodan']['services'] = services

        # Last update
        if 'last_update' in shodan_data:
            enriched_data['shodan']['last_update'] = shodan_data['last_update']

    def _parse_abuseipdb_data(self, abuse_data: Dict, enriched_data: Dict):
        """Parse AbuseIPDB response and extract reputation info"""

        # Abuse confidence score (0-100)
        if 'abuseConfidenceScore' in abuse_data:
            confidence = abuse_data['abuseConfidenceScore']
            enriched_data['abuseipdb']['confidence_score'] = confidence
            enriched_data['reputation_score'] += confidence * 0.5  # Weight by 50%

        # Total reports
        if 'totalReports' in abuse_data:
            reports = abuse_data['totalReports']
            enriched_data['abuseipdb']['total_reports'] = reports
            enriched_data['reputation_score'] += min(reports * 2, 20)

        # Last reported
        if 'lastReportedAt' in abuse_data:
            enriched_data['abuseipdb']['last_reported'] = abuse_data['lastReportedAt']

        # Usage type (Commercial, Data Center, etc.)
        if 'usageType' in abuse_data:
            enriched_data['abuseipdb']['usage_type'] = abuse_data['usageType']

            # Data center IPs are often used for attacks
            if abuse_data['usageType'] in ['Data Center/Web Hosting/Transit', 'Fixed Line ISP']:
                enriched_data['reputation_score'] += 5

        # ISP
        if 'isp' in abuse_data:
            enriched_data['abuseipdb']['isp'] = abuse_data['isp']

        # Country
        if 'countryCode' in abuse_data:
            enriched_data['abuseipdb']['country'] = abuse_data['countryCode']

        # Is whitelisted
        if 'isWhitelisted' in abuse_data and abuse_data['isWhitelisted']:
            enriched_data['reputation_score'] = max(0, enriched_data['reputation_score'] - 50)

    def _calculate_threat_level(self, enriched_data: Dict) -> str:
        """Calculate overall threat level based on all data"""
        score = enriched_data['reputation_score']

        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'safe'

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        private_ranges = [
            '127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.',
            '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
            '172.29.', '172.30.', '172.31.', 'localhost', '::1'
        ]
        return any(ip.startswith(prefix) for prefix in private_ranges)

    def create_llm_context(self, ip: str, enriched_data: Dict, attack_data: Dict) -> Dict:
        """
        Create structured context for LLM analysis
        This formats all data in a way that's easy for LLM to understand

        Args:
            ip: Attacker IP
            enriched_data: Enriched threat intelligence data
            attack_data: Attack log data from honeypot

        Returns:
            Structured data optimized for LLM processing
        """
        context = {
            'attacker_profile': {
                'ip_address': ip,
                'reputation_score': enriched_data.get('reputation_score', 0),
                'threat_level': enriched_data.get('threat_level', 'unknown'),
                'location': {
                    'country': attack_data.get('geoip', {}).get('country', 'Unknown'),
                    'city': attack_data.get('geoip', {}).get('city', 'Unknown'),
                    'isp': enriched_data.get('shodan', {}).get('isp',
                           attack_data.get('geoip', {}).get('isp', 'Unknown')),
                    'organization': enriched_data.get('shodan', {}).get('organization', 'Unknown'),
                },
                'infrastructure': {
                    'is_known_scanner': enriched_data.get('is_known_scanner', False),
                    'is_vpn_proxy': enriched_data.get('is_vpn_proxy', False),
                    'is_tor_exit': enriched_data.get('is_tor_exit', False),
                    'is_cloud': enriched_data.get('shodan', {}).get('is_cloud', False),
                    'asn': enriched_data.get('shodan', {}).get('asn', 'Unknown'),
                },
                'attack_history': {
                    'abuse_reports': enriched_data.get('abuseipdb', {}).get('total_reports', 0),
                    'last_reported': enriched_data.get('abuseipdb', {}).get('last_reported', None),
                    'confidence_score': enriched_data.get('abuseipdb', {}).get('confidence_score', 0),
                }
            },
            'attack_details': {
                'timestamp': attack_data.get('timestamp'),
                'attack_tool': attack_data.get('attack_tool', 'unknown'),
                'attack_technique': attack_data.get('attack_technique', []),
                'threat_score': attack_data.get('threat_score', 0),
                'http_method': attack_data.get('method', 'UNKNOWN'),
                'target_path': attack_data.get('path', '/'),
                'user_agent': attack_data.get('user_agent', ''),
                'payload': {
                    'query_string': attack_data.get('args', {}),
                    'form_data': attack_data.get('form_data', {}),
                    'files': attack_data.get('files', []),
                },
                'response_code': attack_data.get('response_code', 0),
            },
            'technical_intelligence': {
                'open_ports': enriched_data.get('open_ports', []),
                'services': enriched_data.get('shodan', {}).get('services', []),
                'vulnerabilities': enriched_data.get('vulnerabilities', []),
                'operating_system': enriched_data.get('shodan', {}).get('os',
                                   attack_data.get('os_info', {}).get('os', 'Unknown')),
                'tags': enriched_data.get('shodan', {}).get('tags', []),
            },
            'behavioral_indicators': {
                'request_rate': attack_data.get('request_rate', 0),
                'failed_auth_attempts': attack_data.get('failed_auth_attempts', 0),
                'unique_paths_accessed': attack_data.get('unique_paths', 0),
                'scan_detected': any('scan' in t for t in attack_data.get('attack_technique', [])),
                'malicious_payload_detected': attack_data.get('is_attack', False),
                'ids_blocked': attack_data.get('blocked', False),
            }
        }

        return context

    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        return {
            'cached_ips': len(self.cache),
            'cache_ttl_seconds': self.cache_ttl
        }
