#!/usr/bin/env python3
"""
Log Receiver
Receives logs from honeypot server via HTTP API
"""

import os
import json
import threading
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

class LogReceiver:
    def __init__(self, log_dir="/app/logs"):
        self.log_dir = log_dir
        self.honeypot_log = os.path.join(log_dir, "honeypot", "honeypot_logs.log")
        
        # Create directories
        os.makedirs(os.path.dirname(self.honeypot_log), exist_ok=True)
        
        # Statistics
        self.stats = {
            'total_logs_received': 0,
            'honeypot_logs': 0,
            'attack_logs': 0,
            'error_logs': 0,
            'last_received': None,
            'start_time': datetime.now().isoformat()
        }
    
    def receive_log(self, log_data):
        """Receive and process log from honeypot"""
        try:
            # Add metadata
            log_data['received_at'] = datetime.now().isoformat()
            log_data['receiver_ip'] = request.remote_addr
            
            # Determine log type
            log_type = log_data.get('type', 'unknown')
            
            # Update statistics
            self.stats['total_logs_received'] += 1
            self.stats['last_received'] = datetime.now().isoformat()
            
            if 'honeypot' in log_type or 'attack' in log_type:
                self.stats['honeypot_logs'] += 1
                if 'attack' in log_type:
                    self.stats['attack_logs'] += 1
            else:
                self.stats['error_logs'] += 1
            
            # Log to file
            self._write_log(log_data)
            
            # Process log for analysis
            self._process_log(log_data)
            
            return True
            
        except Exception as e:
            print(f"Error receiving log: {str(e)}")
            return False
    
    def receive_batch_logs(self, batch_data):
        """Receive multiple logs in batch"""
        try:
            logs = batch_data.get('logs', [])
            received_count = 0
            
            for log_data in logs:
                if self.receive_log(log_data):
                    received_count += 1
            
            return received_count == len(logs)
            
        except Exception as e:
            print(f"Error receiving batch logs: {str(e)}")
            return False
    
    def _write_log(self, log_data):
        """Write log to file"""
        try:
            with open(self.honeypot_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_data, ensure_ascii=False) + '\n')
        except Exception as e:
            print(f"Error writing log: {str(e)}")
    
    def _process_log(self, log_data):
        """Process log for analysis"""
        try:
            # Extract key information
            log_type = log_data.get('type', 'unknown')
            src_ip = log_data.get('ip', 'unknown')
            timestamp = log_data.get('timestamp', datetime.now().isoformat())
            
            # Log processing
            print(f"Processed {log_type} log from {src_ip} at {timestamp}")
            
            # Additional processing based on log type
            if 'sql_injection' in log_type:
                self._process_sql_injection(log_data)
            elif 'file_upload' in log_type:
                self._process_file_upload(log_data)
            elif 'command_injection' in log_type:
                self._process_command_injection(log_data)
            elif 'authentication_attempt' in log_type:
                self._process_auth_attempt(log_data)
                
        except Exception as e:
            print(f"Error processing log: {str(e)}")
    
    def _process_sql_injection(self, log_data):
        """Process SQL injection attempt"""
        query = log_data.get('query', '')
        username = log_data.get('username', '')
        
        print(f"SQL Injection detected: {username} -> {query[:100]}...")
        
        # Log to separate SQL injection log
        sql_log = os.path.join(self.log_dir, "analysis", "sql_injection.log")
        with open(sql_log, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_data, ensure_ascii=False) + '\n')
    
    def _process_file_upload(self, log_data):
        """Process file upload attempt"""
        filename = log_data.get('filename', '')
        filepath = log_data.get('filepath', '')
        
        print(f"File upload detected: {filename} -> {filepath}")
        
        # Log to separate file upload log
        upload_log = os.path.join(self.log_dir, "analysis", "file_uploads.log")
        with open(upload_log, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_data, ensure_ascii=False) + '\n')
    
    def _process_command_injection(self, log_data):
        """Process command injection attempt"""
        command = log_data.get('command', '')
        
        print(f"Command injection detected: {command}")
        
        # Log to separate command injection log
        cmd_log = os.path.join(self.log_dir, "analysis", "command_injection.log")
        with open(cmd_log, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_data, ensure_ascii=False) + '\n')
    
    def _process_auth_attempt(self, log_data):
        """Process authentication attempt"""
        username = log_data.get('username', '')
        success = log_data.get('success', False)
        
        print(f"Auth attempt: {username} -> {'Success' if success else 'Failed'}")
        
        # Log to separate auth log
        auth_log = os.path.join(self.log_dir, "analysis", "auth_attempts.log")
        with open(auth_log, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_data, ensure_ascii=False) + '\n')
    
    def get_stats(self):
        """Get receiver statistics"""
        self.stats['uptime'] = (datetime.now() - datetime.fromisoformat(self.stats['start_time'])).total_seconds()
        return self.stats
    
    def get_recent_logs(self, limit=100):
        """Get recent logs"""
        try:
            logs = []
            if os.path.exists(self.honeypot_log):
                with open(self.honeypot_log, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for line in lines[-limit:]:
                        try:
                            logs.append(json.loads(line.strip()))
                        except json.JSONDecodeError:
                            continue
            return logs
        except Exception as e:
            print(f"Error reading logs: {str(e)}")
            return []

# Global receiver instance
receiver = LogReceiver()

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'stats': receiver.get_stats()
    })

@app.route('/api/logs', methods=['POST'])
def receive_log():
    """Receive single log from honeypot"""
    try:
        log_data = request.get_json()
        
        if not log_data:
            return jsonify({'error': 'No data provided'}), 400
        
        success = receiver.receive_log(log_data)
        
        if success:
            return jsonify({'status': 'success', 'message': 'Log received'})
        else:
            return jsonify({'error': 'Failed to process log'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/batch', methods=['POST'])
def receive_batch_logs():
    """Receive multiple logs from honeypot"""
    try:
        batch_data = request.get_json()
        
        if not batch_data or 'logs' not in batch_data:
            return jsonify({'error': 'No batch data provided'}), 400
        
        success = receiver.receive_batch_logs(batch_data)
        
        if success:
            return jsonify({'status': 'success', 'message': 'Batch logs received'})
        else:
            return jsonify({'error': 'Failed to process batch logs'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get receiver statistics"""
    return jsonify(receiver.get_stats())

@app.route('/api/logs/recent', methods=['GET'])
def get_recent_logs():
    """Get recent logs"""
    limit = request.args.get('limit', 100, type=int)
    logs = receiver.get_recent_logs(limit)
    return jsonify(logs)

@app.route('/api/attacks', methods=['GET'])
def get_attacks():
    """Get attack logs"""
    try:
        attack_log = os.path.join(receiver.log_dir, "analysis", "attack_analysis.log")
        attacks = []
        
        if os.path.exists(attack_log):
            with open(attack_log, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        attacks.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
        
        return jsonify(attacks)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting Log Receiver...")
    app.run(host='0.0.0.0', port=8080, debug=True)
