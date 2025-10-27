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
        self.capture_server_url = capture_server_url or os.getenv('CAPTURE_SERVER_URL', 'http://172.232.246.68:8080')
        self.api_endpoint = f"{self.capture_server_url}/api/logs/receive"  # ✅ Sửa đây
        self.retry_attempts = 3
        self.retry_delay = 1
    
    def send_log(self, log_data):
        """Send log data to capture server"""
        try:
            # Add metadata
            log_data['source'] = 'honeypot'
            log_data['server_ip'] = '172.235.245.60'
            log_data['sent_at'] = datetime.now().isoformat()
            
            # Send with retry logic
            for attempt in range(self.retry_attempts):
                try:
                    response = requests.post(
                        self.api_endpoint,
                        json=log_data,
                        timeout=5,
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    if response.status_code == 200:
                        return True
                    else:
                        print(f"Failed to send log: HTTP {response.status_code}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"Request error (attempt {attempt + 1}): {str(e)}")
                    if attempt < self.retry_attempts - 1:
                        time.sleep(self.retry_delay * (attempt + 1))
                
            return False
            
        except Exception as e:
            print(f"Error sending log: {str(e)}")
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
