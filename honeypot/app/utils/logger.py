#!/usr/bin/env python3
"""
Simplified Honeypot Logger
Logs raw requests and forwards to Kafka for enrichment on capture server
"""

import json
import os
from datetime import datetime
from flask import request


class HoneypotLogger:
    """Lightweight logger that captures raw request data without processing"""
    
    def __init__(self, log_dir='/app/logs'):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Create log files (for local backup)
        self.request_log = os.path.join(log_dir, 'requests.log')
        self.attack_log = os.path.join(log_dir, 'attacks.log')
        self.error_log = os.path.join(log_dir, 'errors.log')
        
        print("✅ Lightweight HoneypotLogger initialized")
    
    def log_request(self, request):
        """Log raw request information without processing"""
        try:
            # Get real IP from nginx headers
            real_ip = request.headers.get('X-Real-IP', request.remote_addr)
            
            # Capture form data (for application/x-www-form-urlencoded)
            form_data = dict(request.form) if request.form else {}
            
            # Capture JSON body (for application/json)
            json_body = {}
            try:
                if request.is_json:
                    json_body = request.get_json(silent=True) or {}
            except:
                pass
            
            # Capture raw body for other content types (limit to 10KB)
            raw_body = ""
            try:
                if not form_data and not json_body and request.content_length:
                    if request.content_length < 10240:  # 10KB limit
                        raw_body = request.get_data(as_text=True)
            except:
                pass
            
            # Build raw log entry
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'method': request.method,
                'url': request.url,
                'path': request.path,
                'ip': real_ip,
                'user_agent': request.headers.get('User-Agent', ''),
                'referer': request.headers.get('Referer', ''),
                'content_type': request.headers.get('Content-Type', ''),
                'content_length': request.headers.get('Content-Length', ''),
                'headers': dict(request.headers),
                'args': dict(request.args),
                'form_data': form_data,
                'json_body': json_body,
                'raw_body': raw_body,
                'files': list(request.files.keys()) if request.files else [],
                # Simple categorization based on path only
                'log_category': self._simple_categorize(request.path)
            }
            
            # Write to local log file (backup)
            with open(self.request_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
            
            return log_entry
                
        except Exception as e:
            self.log_error(f"Error logging request: {str(e)}")
            return {}
    
    def log_attack(self, attack_data):
        """Log attack attempt (for backward compatibility)"""
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
            
            print(f"❌ Error: {error_message}")
                
        except Exception as e:
            print(f"Critical error in logger: {str(e)}")
    
    def _simple_categorize(self, path):
        """Simple path-based categorization (no heavy processing)"""
        path_lower = path.lower()
        
        # Suspicious paths
        suspicious_paths = [
            '/admin', '/phpmyadmin', '/wp-admin', '/wp-login',
            '/.env', '/config', '/.git', '/backup',
            '/shell', '/cmd', '/exec'
        ]
        
        if any(p in path_lower for p in suspicious_paths):
            return 'attack'
        
        # File uploads
        if '/upload' in path_lower:
            return 'attack'
        
        # Default to traffic
        return 'traffic'
    
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
                'unique_ips': set(),
                'last_activity': None
            }
            
            # Count requests
            if os.path.exists(self.request_log):
                with open(self.request_log, 'r', encoding='utf-8') as f:
                    stats['total_requests'] = len(f.readlines())
            
            # Count attacks
            if os.path.exists(self.attack_log):
                with open(self.attack_log, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            attack = json.loads(line.strip())
                            stats['total_attacks'] += 1
                            
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
