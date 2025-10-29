#!/usr/bin/env python3
"""
Kafka Producer for Honeypot
Sends logs to Kafka topics based on log type
"""

import json
import os
import time
from datetime import datetime
from kafka import KafkaProducer
from kafka.errors import KafkaError

class HoneypotKafkaProducer:
    def __init__(self, bootstrap_servers=None):
        self.bootstrap_servers = bootstrap_servers or os.getenv('KAFKA_BOOTSTRAP_SERVERS', '172.232.224.160:9093')
        self.producer = None
        self.max_retries = 3
        self.retry_delay = 1
        
        # Initialize producer
        self._init_producer()
    
    def _init_producer(self):
        """Initialize Kafka producer with retry logic"""
        for attempt in range(self.max_retries):
            try:
                print(f"🔄 Initializing Kafka producer (attempt {attempt + 1}/{self.max_retries})")
                self.producer = KafkaProducer(
                    bootstrap_servers=[self.bootstrap_servers],
                    value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode('utf-8'),
                    key_serializer=lambda k: k.encode('utf-8') if k else None,
                    retries=3,
                    retry_backoff_ms=1000,
                    request_timeout_ms=30000,
                    api_version=(2, 5, 0)
                )
                print(f"✅ Kafka producer initialized successfully")
                return
            except Exception as e:
                print(f"❌ Failed to initialize Kafka producer (attempt {attempt + 1}): {str(e)}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
                else:
                    print(f"❌ Failed to initialize Kafka producer after {self.max_retries} attempts")
                    self.producer = None
    
    def _send_to_topic(self, topic, log_data, key=None):
        """Send log data to specific Kafka topic"""
        if not self.producer:
            print(f"❌ Kafka producer not initialized, cannot send to topic {topic}")
            return False
        
        try:
            # Add metadata
            log_data['kafka_topic'] = topic
            log_data['kafka_timestamp'] = datetime.now().isoformat()
            
            # Send to Kafka
            future = self.producer.send(topic, value=log_data, key=key)
            
            # Wait for confirmation
            record_metadata = future.get(timeout=10)
            print(f"✅ Log sent to topic {topic}, partition {record_metadata.partition}, offset {record_metadata.offset}")
            return True
            
        except KafkaError as e:
            print(f"❌ Kafka error sending to topic {topic}: {str(e)}")
            return False
        except Exception as e:
            print(f"❌ Error sending to topic {topic}: {str(e)}")
            return False
    
    def send_browser_log(self, log_data):
        """Send browser logs to honeypot-browser topic"""
        print(f"🌐 Sending browser log: {log_data.get('method', 'GET')} {log_data.get('path', '/')} from {log_data.get('ip', 'unknown')}")
        return self._send_to_topic('honeypot-browser', log_data, key=log_data.get('ip'))
    
    def send_attack_log(self, log_data):
        """Send attack logs to honeypot-attacks topic"""
        print(f"⚔️ Sending attack log: {log_data.get('attack_tool', 'unknown')} from {log_data.get('ip', 'unknown')}")
        return self._send_to_topic('honeypot-attacks', log_data, key=log_data.get('ip'))
    
    def send_error_log(self, log_data):
        """Send error logs to honeypot-errors topic"""
        print(f"❌ Sending error log: {log_data.get('error', 'unknown error')}")
        return self._send_to_topic('honeypot-errors', log_data, key=log_data.get('ip'))
    
    def close(self):
        """Close Kafka producer"""
        if self.producer:
            self.producer.flush()
            self.producer.close()
            print("🔒 Kafka producer closed")
