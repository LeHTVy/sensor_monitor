#!/usr/bin/env python3
"""
Honeypot Logger
Logs all requests and attack attempts
"""

import json
import os
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
    
    def log_request(self, request):
        """Log detailed request information"""
        try:
            # Get real IP from nginx headers
            real_ip = request.headers.get('X-Real-IP', request.remote_addr)
            forwarded_for = request.headers.get('X-Forwarded-For', '')
            forwarded_proto = request.headers.get('X-Forwarded-Proto', 'http')
            
            # Detect attack tool/technique
            user_agent = request.headers.get('User-Agent', '')
            attack_tool = self._detect_attack_tool(user_agent)
            attack_technique = self._detect_attack_technique(request)
            
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
                'attack_technique': attack_technique,
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
                
        except Exception as e:
            self.log_error(f"Error logging request: {str(e)}")
    
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
    
    def _detect_attack_tool(self, user_agent):
        """Detect attack tool from User-Agent"""
        user_agent_lower = user_agent.lower()
        
        # Common attack tools
        tools = {
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
        
        for tool, keywords in tools.items():
            for keyword in keywords:
                if keyword in user_agent_lower:
                    return tool
        
        # Check for suspicious patterns
        if any(pattern in user_agent_lower for pattern in ['sql', 'injection', 'xss', 'csrf']):
            return 'suspicious'
        
        return 'unknown'
    
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
