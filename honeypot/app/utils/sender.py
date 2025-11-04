#!/usr/bin/env python3
"""
Log Sender
Sends logs to capture server
"""

import os
import json
import requests
import time
from datetime import datetime

class LogSender:
    def __init__(self, capture_server_url=None):
        self.capture_server_url = capture_server_url or os.getenv('CAPTURE_SERVER_URL', 'http://172.232.224.160:8080')
        self.api_endpoint = f"{self.capture_server_url}/api/logs/receive"  
        self.retry_attempts = 3
        self.retry_delay = 1
    
    def send_log(self, log_data):
        """Send log data to capture server"""
        try:
            print(f"📤 Sending log to capture server: {log_data.get('type', 'request')} from {log_data.get('ip', 'unknown')}")
            
            # Add metadata
            log_data['source'] = 'honeypot'
            log_data['server_ip'] = '172.235.245.60'
            log_data['sent_at'] = datetime.now().isoformat()
            
            # Ensure all required fields are present
            if 'ip' not in log_data:
                log_data['ip'] = 'unknown'
            if 'timestamp' not in log_data:
                log_data['timestamp'] = datetime.now().isoformat()
            if 'attack_tool' not in log_data:
                log_data['attack_tool'] = 'unknown'
            if 'attack_technique' not in log_data:
                log_data['attack_technique'] = ['unknown']
            if 'geoip' not in log_data:
                log_data['geoip'] = {'country': 'Unknown', 'city': 'Unknown'}
            if 'os_info' not in log_data:
                log_data['os_info'] = {'os': 'Unknown', 'version': 'Unknown'}
            if 'log_category' not in log_data:
                log_data['log_category'] = 'unknown'
            
            print(f"📋 Log data prepared: {log_data}")
            
            # Send with retry logic
            for attempt in range(self.retry_attempts):
                try:
                    print(f"🔄 Attempt {attempt + 1}/{self.retry_attempts} to send log")
                    response = requests.post(
                        self.api_endpoint,
                        json=log_data,
                        timeout=5,
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    print(f"📡 Response status: {response.status_code}")
                    
                    if response.status_code == 200:
                        print(f"✅ Log sent successfully: {log_data.get('type', 'request')} from {log_data.get('ip', 'unknown')}")
                        return True
                    else:
                        print(f"❌ Failed to send log: HTTP {response.status_code}")
                        print(f"Response content: {response.text}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"❌ Request error (attempt {attempt + 1}): {str(e)}")
                    if attempt < self.retry_attempts - 1:
                        time.sleep(self.retry_delay * (attempt + 1))
            
            return False
            
        except Exception as e:
            print(f"❌ Error sending log: {str(e)}")
            return False
    
    def send_batch_logs(self, logs):
        """Send multiple logs in batch"""
        try:
            batch_data = {
                'source': 'honeypot',
                'server_ip': '172.235.245.60',
                'sent_at': datetime.now().isoformat(),
                'logs': logs
            }
            
            for attempt in range(self.retry_attempts):
                try:
                    response = requests.post(
                        f"{self.capture_server_url}/api/logs/batch",
                        json=batch_data,
                        timeout=10,
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    if response.status_code == 200:
                        return True
                    else:
                        print(f"Failed to send batch logs: HTTP {response.status_code}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"Batch request error (attempt {attempt + 1}): {str(e)}")
                    if attempt < self.retry_attempts - 1:
                        time.sleep(self.retry_delay * (attempt + 1))
                
            return False
            
        except Exception as e:
            print(f"Error sending batch logs: {str(e)}")
            return False
    
    def test_connection(self):
        """Test connection to capture server"""
        try:
            response = requests.get(
                f"{self.capture_server_url}/api/health",
                timeout=5
            )
            return response.status_code == 200
        except:
            return False
