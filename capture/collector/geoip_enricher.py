#!/usr/bin/env python3
"""
GeoIP Enrichment Module
Provides geographic and network information for IP addresses
"""

import os
import requests
from typing import Dict, Optional


class GeoIPEnricher:
    """Enriches IP addresses with geographic and network information"""
    
    def __init__(self):
        self.api_key = os.getenv('GEOIP_API_KEY', '')
        self.use_premium = bool(self.api_key)
        
        if self.use_premium:
            print("✅ GeoIP: Using MaxMind premium API")
        else:
            print("ℹ️  GeoIP: Using free ip-api.com (no API key)")
    
    def enrich(self, ip: str) -> Dict:
        """
        Get GeoIP information for an IP address
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Dictionary with geographic and network information
        """
        # Skip private/local IPs
        if self._is_private_ip(ip):
            return {
                'country': 'Private Network',
                'city': 'Local',
                'region': 'Private',
                'isp': 'Private',
                'org': 'Private Network',
                'asn': 'Private',
                'lat': 0.0,
                'lon': 0.0,
                'timezone': 'Local',
                'postal': 'N/A'
            }
        
        # Try premium API first if available
        if self.use_premium:
            result = self._query_maxmind(ip)
            if result:
                return result
        
        # Fallback to free API
        return self._query_free(ip)
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        return (ip.startswith('127.') or 
                ip.startswith('192.168.') or 
                ip.startswith('10.') or 
                ip.startswith('172.16.') or
                ip.startswith('172.17.') or
                ip.startswith('172.18.') or
                ip.startswith('172.19.') or
                ip.startswith('172.20.') or
                ip.startswith('172.21.') or
                ip.startswith('172.22.') or
                ip.startswith('172.23.') or
                ip.startswith('172.24.') or
                ip.startswith('172.25.') or
                ip.startswith('172.26.') or
                ip.startswith('172.27.') or
                ip.startswith('172.28.') or
                ip.startswith('172.29.') or
                ip.startswith('172.30.') or
                ip.startswith('172.31.'))
    
    def _query_maxmind(self, ip: str) -> Optional[Dict]:
        """Query MaxMind GeoIP2 Precision API"""
        try:
            response = requests.get(
                f'https://geoip.maxmind.com/geoip/v2.1/city/{ip}',
                headers={'Authorization': f'Bearer {self.api_key}'},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country', {}).get('names', {}).get('en', 'Unknown'),
                    'city': data.get('city', {}).get('names', {}).get('en', 'Unknown'),
                    'region': data.get('subdivisions', [{}])[0].get('names', {}).get('en', 'Unknown'),
                    'isp': data.get('traits', {}).get('isp', 'Unknown'),
                    'org': data.get('traits', {}).get('organization', 'Unknown'),
                    'asn': f"AS{data.get('traits', {}).get('autonomous_system_number', 'Unknown')}",
                    'lat': data.get('location', {}).get('latitude', 0.0),
                    'lon': data.get('location', {}).get('longitude', 0.0),
                    'timezone': data.get('location', {}).get('time_zone', 'Unknown'),
                    'postal': data.get('postal', {}).get('code', 'Unknown')
                }
        except Exception as e:
            print(f"⚠️  MaxMind GeoIP error for {ip}: {e}")
        return None
    
    def _query_free(self, ip: str) -> Dict:
        """Query free ip-api.com service"""
        try:
            response = requests.get(
                f'http://ip-api.com/json/{ip}',
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'asn': data.get('as', 'Unknown'),
                        'lat': data.get('lat', 0.0),
                        'lon': data.get('lon', 0.0),
                        'timezone': data.get('timezone', 'Unknown'),
                        'postal': data.get('zip', 'Unknown')
                    }
        except Exception as e:
            print(f"⚠️  Free GeoIP error for {ip}: {e}")
        
        # Return unknown if all fails
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'region': 'Unknown',
            'isp': 'Unknown',
            'org': 'Unknown',
            'asn': 'Unknown',
            'lat': 0.0,
            'lon': 0.0,
            'timezone': 'Unknown',
            'postal': 'Unknown'
        }
