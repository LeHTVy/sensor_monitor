#!/usr/bin/env python3
"""
Kafka Consumer for Capture Server
Consumes logs from Kafka topics and processes them
"""

import json
import os
import time
import threading
from datetime import datetime
import pytz
from kafka import KafkaConsumer
from kafka.errors import KafkaError

class CaptureKafkaConsumer:
    def __init__(self, bootstrap_servers=None):
        self.bootstrap_servers = bootstrap_servers or os.getenv('KAFKA_BOOTSTRAP_SERVERS', '172.232.246.68:9092')
        self.consumer = None
        self.running = False
        self.vn_timezone = pytz.timezone('Asia/Ho_Chi_Minh')
        
        # Log storage
        self.browser_logs = []
        self.attack_logs = []
        self.error_logs = []
        
        # Initialize consumer
        self._init_consumer()
    
    def _init_consumer(self):
        """Initialize Kafka consumer"""
        try:
            print(f"🔄 Initializing Kafka consumer")
            self.consumer = KafkaConsumer(
                'honeypot-browser',
                'honeypot-attacks', 
                'honeypot-errors',
                bootstrap_servers=[self.bootstrap_servers],
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                key_deserializer=lambda k: k.decode('utf-8') if k else None,
                auto_offset_reset='latest',
                enable_auto_commit=True,
                group_id='capture-server-group',
                api_version=(2, 5, 0)
            )
            print(f"✅ Kafka consumer initialized successfully")
        except Exception as e:
            print(f"❌ Failed to initialize Kafka consumer: {str(e)}")
            self.consumer = None
    
    def convert_to_vietnam_time(self, timestamp):
        """Convert timestamp to Vietnam timezone"""
        try:
            if isinstance(timestamp, str):
                # Parse ISO format timestamp
                if timestamp.endswith('Z'):
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                elif '+' in timestamp or timestamp.endswith('00:00'):
                    dt = datetime.fromisoformat(timestamp)
                else:
                    dt = datetime.fromisoformat(timestamp)
            else:
                dt = timestamp
            
            # Convert to Vietnam timezone
            if dt.tzinfo is None:
                dt = pytz.utc.localize(dt)
            
            vn_time = dt.astimezone(self.vn_timezone)
            return vn_time.isoformat()
        except Exception as e:
            print(f"❌ Error converting timestamp {timestamp}: {str(e)}")
            return timestamp
    
    def process_log(self, message):
        """Process individual log message"""
        try:
            topic = message.topic
            log_data = message.value
            key = message.key
            
            # Convert timestamp to Vietnam timezone
            if 'timestamp' in log_data:
                log_data['timestamp_vn'] = self.convert_to_vietnam_time(log_data['timestamp'])
            
            # Add processing metadata
            log_data['processed_at'] = datetime.now().isoformat()
            log_data['kafka_partition'] = message.partition
            log_data['kafka_offset'] = message.offset
            
            # Store in appropriate list based on topic
            if topic == 'honeypot-browser':
                self.browser_logs.append(log_data)
                print(f"🌐 Processed browser log: {log_data.get('method', 'GET')} {log_data.get('path', '/')} from {log_data.get('ip', 'unknown')}")
                
            elif topic == 'honeypot-attacks':
                self.attack_logs.append(log_data)
                print(f"⚔️ Processed attack log: {log_data.get('attack_tool', 'unknown')} from {log_data.get('ip', 'unknown')}")
                
            elif topic == 'honeypot-errors':
                self.error_logs.append(log_data)
                print(f"❌ Processed error log: {log_data.get('error', 'unknown error')}")
            
            # Keep only last 1000 logs to prevent memory issues
            if len(self.browser_logs) > 1000:
                self.browser_logs = self.browser_logs[-1000:]
            if len(self.attack_logs) > 1000:
                self.attack_logs = self.attack_logs[-1000:]
            if len(self.error_logs) > 1000:
                self.error_logs = self.error_logs[-1000:]
                
        except Exception as e:
            print(f"❌ Error processing log: {str(e)}")
    
    def start_consuming(self):
        """Start consuming messages from Kafka"""
        if not self.consumer:
            print("❌ Kafka consumer not initialized")
            return
        
        self.running = True
        print("🔄 Starting Kafka consumer...")
        
        try:
            for message in self.consumer:
                if not self.running:
                    break
                
                self.process_log(message)
                
        except KafkaError as e:
            print(f"❌ Kafka error: {str(e)}")
        except Exception as e:
            print(f"❌ Consumer error: {str(e)}")
        finally:
            print("🔒 Kafka consumer stopped")
    
    def stop_consuming(self):
        """Stop consuming messages"""
        self.running = False
        if self.consumer:
            self.consumer.close()
    
    def get_browser_logs(self, limit=100):
        """Get browser logs"""
        return self.browser_logs[-limit:] if self.browser_logs else []
    
    def get_attack_logs(self, limit=100):
        """Get attack logs"""
        return self.attack_logs[-limit:] if self.attack_logs else []
    
    def get_error_logs(self, limit=100):
        """Get error logs"""
        return self.error_logs[-limit:] if self.error_logs else []
    
    def get_all_logs(self, limit=100):
        """Get all logs combined"""
        all_logs = []
        all_logs.extend(self.browser_logs[-limit//3:])
        all_logs.extend(self.attack_logs[-limit//3:])
        all_logs.extend(self.error_logs[-limit//3:])
        
        # Sort by timestamp
        all_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return all_logs[:limit]
