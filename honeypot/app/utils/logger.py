#!/usr/bin/env python3
"""
Honeypot Logger
Logs all requests and attack attempts
"""

import json
import os
import requests
from datetime import datetime
from flask import request

class HoneypotLogger:
    def __init__(self, log_dir='/app/logs'):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Create log files
        self.request_log = os.path.join(log_dir, 'requests.log')
        self.attack_log = os.path.join(log_dir, 'attacks.log')
        self.error_log = os.path.join(log_dir, 'errors.log')
        
        # Attack rate monitoring
        self.attack_counts = {}  # IP -> count
        self.last_reset = datetime.now()
    
    def log_request(self, request):
        """Log detailed request information"""
        try:
            # Get real IP from nginx headers
            real_ip = request.headers.get('X-Real-IP', request.remote_addr)
            forwarded_for = request.headers.get('X-Forwarded-For', '')
            forwarded_proto = request.headers.get('X-Forwarded-Proto', 'http')
            
            # Debug IP information
            print(f"🌐 IP Debug for request:")
            print(f"   Remote Addr: {request.remote_addr}")
            print(f"   X-Real-IP: {request.headers.get('X-Real-IP', 'None')}")
            print(f"   X-Forwarded-For: {forwarded_for}")
            print(f"   X-Forwarded-Proto: {forwarded_proto}")
            print(f"   Final IP: {real_ip}")
            print(f"   All Headers: {dict(request.headers)}")
            
            # Detect attack tool/technique
            user_agent = request.headers.get('User-Agent', '')
            attack_tool_info = self._detect_attack_tool(request)
            attack_tool = attack_tool_info['tool'] if isinstance(attack_tool_info, dict) else attack_tool_info
            attack_technique = self._detect_attack_technique(request)
            
            # Debug logging
            print(f"🔍 Detection Debug for {real_ip}:")
            print(f"   User-Agent: {user_agent}")
            print(f"   Attack Tool Info: {attack_tool_info}")
            print(f"   Attack Tool: {attack_tool}")
            print(f"   Attack Technique: {attack_technique}")
            
            # Get GeoIP information
            geoip_info = self._get_geoip_info(real_ip)
            
            # Detect OS from User-Agent
            os_info = self._detect_os(user_agent)
            
            # Determine log category
            log_category = self._categorize_log(attack_tool, attack_technique)
            print(f"   Log Category: {log_category}")
            
            # Monitor attack rate
            self._monitor_attack_rate(real_ip, log_category)
            
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'method': request.method,
                'url': request.url,
                'path': request.path,
                'protocol': forwarded_proto,
                'ip': real_ip,
                'forwarded_for': forwarded_for,
                'user_agent': user_agent,
                'attack_tool': attack_tool,
                'attack_tool_info': attack_tool_info,  # Include detailed detection info
                'attack_technique': attack_technique,
                'geoip': geoip_info,
                'os_info': os_info,
                'log_category': log_category,
                'referer': request.headers.get('Referer', ''),
                'content_type': request.headers.get('Content-Type', ''),
                'content_length': request.headers.get('Content-Length', ''),
                'headers': dict(request.headers),
                'args': dict(request.args),
                'form_data': dict(request.form) if request.form else {},
                'files': list(request.files.keys()) if request.files else [],
                'is_attack': self._is_potential_attack(request)
            }
            
            with open(self.request_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
            
            return log_entry
                
        except Exception as e:
            self.log_error(f"Error logging request: {str(e)}")
            return {}
    
    def log_attack(self, attack_data):
        """Log attack attempt with detailed information"""
        try:
            attack_data['log_timestamp'] = datetime.now().isoformat()
            
            with open(self.attack_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(attack_data, ensure_ascii=False) + '\n')
                
        except Exception as e:
            self.log_error(f"Error logging attack: {str(e)}")
    
    def log_error(self, error_message):
        """Log error messages"""
        try:
            error_entry = {
                'timestamp': datetime.now().isoformat(),
                'error': error_message
            }
            
            with open(self.error_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(error_entry, ensure_ascii=False) + '\n')
                
        except Exception as e:
            print(f"Critical error in logger: {str(e)}")
    
    def get_recent_attacks(self, limit=100):
        """Get recent attack logs"""
        try:
            attacks = []
            if os.path.exists(self.attack_log):
                with open(self.attack_log, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for line in lines[-limit:]:
                        try:
                            attacks.append(json.loads(line.strip()))
                        except json.JSONDecodeError:
                            continue
            return attacks
        except Exception as e:
            self.log_error(f"Error reading attack logs: {str(e)}")
            return []
    
    def get_stats(self):
        """Get basic statistics"""
        try:
            stats = {
                'total_requests': 0,
                'total_attacks': 0,
                'attack_types': {},
                'unique_ips': set(),
                'last_activity': None
            }
            
            # Count requests
            if os.path.exists(self.request_log):
                with open(self.request_log, 'r', encoding='utf-8') as f:
                    stats['total_requests'] = len(f.readlines())
            
            # Count attacks and analyze types
            if os.path.exists(self.attack_log):
                with open(self.attack_log, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            attack = json.loads(line.strip())
                            stats['total_attacks'] += 1
                            
                            attack_type = attack.get('type', 'unknown')
                            stats['attack_types'][attack_type] = stats['attack_types'].get(attack_type, 0) + 1
                            
                            if 'ip' in attack:
                                stats['unique_ips'].add(attack['ip'])
                            
                            if not stats['last_activity'] or attack.get('timestamp', '') > stats['last_activity']:
                                stats['last_activity'] = attack.get('timestamp', '')
                                
                        except json.JSONDecodeError:
                            continue
            
            stats['unique_ips'] = len(stats['unique_ips'])
            return stats
            
        except Exception as e:
            self.log_error(f"Error getting stats: {str(e)}")
            return {}
    
    def _detect_attack_tool(self, request):
        """Enhanced attack tool detection from User-Agent and request patterns"""
        user_agent = request.headers.get('User-Agent', '').lower()
        
        # Enhanced detection based on network patterns and headers
        detection_score = 0
        detected_tool = 'unknown'
        confidence = 0
        
        # 1. User-Agent based detection
        tools_ua = {
            'nmap': ['nmap', 'nse'],
            'sqlmap': ['sqlmap'],
            'nikto': ['nikto'],
            'dirb': ['dirb'],
            'gobuster': ['gobuster'],
            'burp': ['burp'],
            'zap': ['zaproxy', 'owasp zap'],
            'w3af': ['w3af'],
            'metasploit': ['metasploit', 'msf'],
            'curl': ['curl'],
            'wget': ['wget'],
            'python': ['python-requests', 'python-urllib'],
            'perl': ['perl'],
            'ruby': ['ruby'],
            'php': ['php'],
            'java': ['java'],
            'scanner': ['scanner', 'scan'],
            'bot': ['bot', 'crawler', 'spider'],
            'automated': ['automated', 'script']
        }
        
        for tool, patterns in tools_ua.items():
            for pattern in patterns:
                if pattern in user_agent:
                    detected_tool = tool
                    confidence = 80
                    break
            if confidence > 0:
                break
        
        # 2. HTTP Header Analysis (Scanner Detection)
        headers = request.headers
        
        # Missing common browser headers = scanner indicator
        browser_headers = ['accept-language', 'accept-encoding', 'cache-control', 'sec-fetch-site', 'sec-fetch-mode']
        missing_headers = sum(1 for h in browser_headers if h not in headers)
        
        if missing_headers >= 3:
            detection_score -= 30
            if detected_tool == 'unknown':
                detected_tool = 'scanner'
                confidence = 60
        
        # 3. Request Pattern Analysis
        path = request.path.lower()
        method = request.method
        
        # Common scanner paths
        scanner_paths = [
            '/admin', '/wp-admin', '/phpmyadmin', '/.env', '/config',
            '/backup', '/test', '/api', '/robots.txt', '/sitemap.xml'
        ]
        
        if any(scanner_path in path for scanner_path in scanner_paths):
            detection_score -= 20
            if detected_tool == 'unknown':
                detected_tool = 'web_scanner'
                confidence = 70
        
        # 4. Telnet Detection (if applicable)
        if 'telnet' in user_agent or 'telnet' in path:
            detected_tool = 'telnet'
            confidence = 90
        
        # 5. Empty or minimal User-Agent
        if not user_agent or user_agent in ['', '-', 'none']:
            detection_score -= 40
            if detected_tool == 'unknown':
                detected_tool = 'minimal_client'
                confidence = 50
        
        # 6. Request method analysis
        if method not in ['GET', 'POST', 'HEAD']:
            detection_score -= 25
            if detected_tool == 'unknown':
                detected_tool = 'unusual_method'
                confidence = 60
        
        # 7. Query parameter analysis
        if request.args:
            # Common attack parameters
            attack_params = ['id', 'cmd', 'exec', 'eval', 'system', 'shell']
            if any(param in request.args for param in attack_params):
                detection_score -= 15
                if detected_tool == 'unknown':
                    detected_tool = 'parameter_attack'
                    confidence = 65
        
        # Final confidence calculation
        final_confidence = max(confidence, abs(detection_score))
        
        return {
            'tool': detected_tool,
            'confidence': min(final_confidence, 100),
            'score': detection_score,
            'user_agent': user_agent,
            'missing_headers': missing_headers
        }
    
    def _detect_attack_technique(self, request):
        """Detect attack technique from request"""
        techniques = []
        
        # SQL Injection
        query_string = str(request.query_string.decode())
        form_data = str(request.form)
        if any(pattern in query_string.lower() or pattern in form_data.lower() 
               for pattern in ['union', 'select', 'insert', 'delete', 'drop', 'or 1=1', 'or 1=1--', 'admin\'--']):
            techniques.append('sql_injection')
        
        # XSS
        if any(pattern in query_string.lower() or pattern in form_data.lower() 
               for pattern in ['<script>', 'javascript:', 'onload=', 'onerror=']):
            techniques.append('xss')
        
        # Directory Traversal
        if any(pattern in request.path for pattern in ['../', '..\\', '/etc/passwd', '/etc/shadow']):
            techniques.append('directory_traversal')
        
        # Command Injection
        if any(pattern in query_string.lower() or pattern in form_data.lower() 
               for pattern in [';', '|', '&', '`', '$(', 'exec', 'system', 'shell']):
            techniques.append('command_injection')
        
        # File Upload
        if request.files:
            techniques.append('file_upload')
        
        # Brute Force (multiple login attempts)
        if request.path in ['/login', '/auth'] and request.method == 'POST':
            techniques.append('brute_force')
        
        # Reconnaissance
        if any(pattern in request.path for pattern in ['/admin', '/phpmyadmin', '/wp-admin', '/.env', '/config']):
            techniques.append('reconnaissance')
        
        return techniques if techniques else ['normal_browsing']
    
    def _is_potential_attack(self, request):
        """Determine if request is potentially malicious"""
        techniques = self._detect_attack_technique(request)
        return any(tech != 'normal_browsing' for tech in techniques)
    
    def _get_geoip_info(self, ip):
        """Get GeoIP information for an IP address"""
        try:
            # Skip private IPs
            if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                return {
                    'country': 'Private Network',
                    'city': 'Local',
                    'isp': 'Private',
                    'org': 'Private Network'
                }
            
            # Try premium GeoIP service first (if API key provided)
            api_key = os.getenv('GEOIP_API_KEY', '')
            print(f"GeoIP API Key loaded: {'Yes' if api_key else 'No'}")
            
            if api_key:
                try:
                    print(f"Trying MaxMind GeoIP for {ip}")
                    # Using MaxMind GeoIP2 service
                    response = requests.get(f'https://geoip.maxmind.com/geoip/v2.1/city/{ip}', 
                                          headers={'Authorization': f'Bearer {api_key}'}, 
                                          timeout=3)
                    print(f"Premium GeoIP response status: {response.status_code}")
                    
                    if response.status_code == 200:
                        data = response.json()
                        print(f"Premium GeoIP data: {data}")
                        return {
                            'country': data.get('country', {}).get('names', {}).get('en', 'Unknown'),
                            'city': data.get('city', {}).get('names', {}).get('en', 'Unknown'),
                            'isp': data.get('traits', {}).get('isp', 'Unknown'),
                            'org': data.get('traits', {}).get('organization', 'Unknown'),
                            'lat': data.get('location', {}).get('latitude', 0),
                            'lon': data.get('location', {}).get('longitude', 0),
                            'timezone': data.get('location', {}).get('time_zone', 'Unknown'),
                            'region': data.get('subdivisions', [{}])[0].get('names', {}).get('en', 'Unknown'),
                            'postal': data.get('postal', {}).get('code', 'Unknown')
                        }
                    else:
                        print(f"Premium GeoIP failed with status {response.status_code}")
                except Exception as e:
                    print(f"Premium GeoIP error for {ip}: {str(e)}")
            
            # Fallback to free ip-api.com
            print(f"Trying free GeoIP for {ip}")
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
            print(f"Free GeoIP response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"Free GeoIP data: {data}")
                return {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'timezone': data.get('timezone', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'postal': data.get('zip', 'Unknown')
                }
        except Exception as e:
            print(f"Error getting GeoIP for {ip}: {str(e)}")
        
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown',
            'org': 'Unknown'
        }
    
    def _detect_os(self, user_agent):
        """Detect operating system from User-Agent"""
        user_agent_lower = user_agent.lower()
        
        # Windows detection
        if 'windows nt 10.0' in user_agent_lower:
            return {'os': 'Windows', 'version': '10', 'architecture': 'x64'}
        elif 'windows nt 6.3' in user_agent_lower:
            return {'os': 'Windows', 'version': '8.1', 'architecture': 'x64'}
        elif 'windows nt 6.2' in user_agent_lower:
            return {'os': 'Windows', 'version': '8', 'architecture': 'x64'}
        elif 'windows nt 6.1' in user_agent_lower:
            return {'os': 'Windows', 'version': '7', 'architecture': 'x64'}
        elif 'windows nt 6.0' in user_agent_lower:
            return {'os': 'Windows', 'version': 'Vista', 'architecture': 'x64'}
        elif 'windows nt 5.1' in user_agent_lower:
            return {'os': 'Windows', 'version': 'XP', 'architecture': 'x86'}
        elif 'windows' in user_agent_lower:
            return {'os': 'Windows', 'version': 'Unknown', 'architecture': 'Unknown'}
        
        # macOS detection
        elif 'mac os x' in user_agent_lower:
            if 'mac os x 10_15' in user_agent_lower:
                return {'os': 'macOS', 'version': 'Catalina', 'architecture': 'x64'}
            elif 'mac os x 10_14' in user_agent_lower:
                return {'os': 'macOS', 'version': 'Mojave', 'architecture': 'x64'}
            elif 'mac os x 10_13' in user_agent_lower:
                return {'os': 'macOS', 'version': 'High Sierra', 'architecture': 'x64'}
            elif 'mac os x 10_12' in user_agent_lower:
                return {'os': 'macOS', 'version': 'Sierra', 'architecture': 'x64'}
            else:
                return {'os': 'macOS', 'version': 'Unknown', 'architecture': 'x64'}
        
        # Linux detection
        elif 'linux' in user_agent_lower:
            if 'ubuntu' in user_agent_lower:
                return {'os': 'Linux', 'version': 'Ubuntu', 'architecture': 'x64'}
            elif 'centos' in user_agent_lower:
                return {'os': 'Linux', 'version': 'CentOS', 'architecture': 'x64'}
            elif 'debian' in user_agent_lower:
                return {'os': 'Linux', 'version': 'Debian', 'architecture': 'x64'}
            elif 'fedora' in user_agent_lower:
                return {'os': 'Linux', 'version': 'Fedora', 'architecture': 'x64'}
            else:
                return {'os': 'Linux', 'version': 'Unknown', 'architecture': 'x64'}
        
        # Android detection
        elif 'android' in user_agent_lower:
            return {'os': 'Android', 'version': 'Unknown', 'architecture': 'ARM'}
        
        # iOS detection
        elif 'iphone' in user_agent_lower or 'ipad' in user_agent_lower:
            return {'os': 'iOS', 'version': 'Unknown', 'architecture': 'ARM'}
        
        # Unknown OS
        else:
            return {'os': 'Unknown', 'version': 'Unknown', 'architecture': 'Unknown'}
    
    def _categorize_log(self, attack_tool, attack_technique):
        """Categorize log based on tool and technique"""
        # High-risk techniques → attack even if tool unknown
        technique_list = [t.lower() for t in (attack_technique or [])]
        high_risk = {
            'sql_injection', 'sqli', 'command_injection', 'rce', 'remote_code_execution',
            'brute_force', 'credential_stuffing', 'xss', 'path_traversal', 'directory_traversal',
            'lfi', 'rfi', 'ssrf', 'csrf', 'deserialization', 'insecure_direct_object_reference'
        }
        if any(t in high_risk for t in technique_list):
            return 'attack'

        # Normal browsing → traffic
        if attack_tool == 'browser':
            return 'traffic'
        
        # Attack logs: security tools
        attack_tools = [
            # Scanners / Recon
            'nmap', 'masscan', 'amass', 'subfinder', 'theharvester',
            # Web vul scanners / dir bruteforce
            'nikto', 'wapiti', 'w3af', 'gobuster', 'dirb',
            # Proxies / fuzzers
            'burp', 'zap',
            # Exploit frameworks / C2
            'metasploit', 'cobalt strike', 'empire',
            # Auth bruteforce
            'hydra', 'medusa', 'crowbar',
            # CLI / network tools often seen in probing
            'curl', 'httpie', 'wget', 'netcat', 'nc', 'socat', 'telnet',
            # Packet capture / analysis
            'wireshark', 'tshark', 'tcpdump', 'ngrep',
            # SMB/AD enum
            'smbclient', 'enum4linux', 'rpcclient', 'bloodhound',
            # Scripting runtimes often used for tooling
            'python', 'perl', 'ruby', 'php', 'java', 'openssl',
            # Heuristics
            'scanner', 'bot', 'automated', 'malformed', 'suspicious',
            'web_scanner', 'minimal_client', 'unusual_method', 'parameter_attack'
        ]
        
        if attack_tool in attack_tools:
            return 'attack'
        
        # Unknown tool → default to traffic
        if attack_tool == 'unknown' or not attack_tool:
            return 'traffic'
        
        return 'unknown'
    
    def _monitor_attack_rate(self, ip, category):
        """Monitor attack rate and generate alerts"""
        current_time = datetime.now()
        
        # Reset counters every hour
        if (current_time - self.last_reset).seconds > 3600:
            self.attack_counts.clear()
            self.last_reset = current_time
        
        # Count attacks per IP
        if category == 'attack':
            self.attack_counts[ip] = self.attack_counts.get(ip, 0) + 1
            
            # Generate alert if too many attacks
            if self.attack_counts[ip] > 50:  # More than 50 attacks per hour
                self.log_error(f"HIGH ATTACK RATE ALERT: IP {ip} has {self.attack_counts[ip]} attacks in the last hour")
            elif self.attack_counts[ip] > 20:  # More than 20 attacks per hour
                self.log_error(f"MODERATE ATTACK RATE: IP {ip} has {self.attack_counts[ip]} attacks in the last hour")
