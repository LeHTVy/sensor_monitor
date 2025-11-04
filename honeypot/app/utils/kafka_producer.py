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

class HoneypotKafkaProducer:
    def __init__(self, bootstrap_servers=None):
        self.bootstrap_servers = bootstrap_servers or os.getenv('KAFKA_BOOTSTRAP_SERVERS', '172.232.224.160:9093')
        self.producer = None
        self.max_retries = 5  
        self.retry_delay = 2  
        
        self._init_producer()
    
    def _init_producer(self):
        """Initialize Kafka producer with retry logic - MANDATORY, will raise exception if fails"""
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                print(f"🔄 Initializing Kafka producer (attempt {attempt + 1}/{self.max_retries}) to {self.bootstrap_servers}")
                self.producer = KafkaProducer(
                    bootstrap_servers=[self.bootstrap_servers],
                    value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode('utf-8'),
                    key_serializer=lambda k: k.encode('utf-8') if k else None,
                    retries=3,
                    retry_backoff_ms=1000,
                    request_timeout_ms=10000,  
                    connections_max_idle_ms=540000,
                    api_version=(2, 5, 0),
                    metadata_max_age_ms=300000,
                    metadata_request_timeout_ms=5000  
                )
                
                # Test connection by getting metadata
                self.producer.bootstrap_connected()
                
                print(f"✅ Kafka producer initialized successfully and connected to {self.bootstrap_servers}")
                return
                
            except Exception as e:
                last_error = e
                print(f"❌ Failed to initialize Kafka producer (attempt {attempt + 1}/{self.max_retries}): {str(e)}")
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (attempt + 1)
                    print(f"⏳ Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)
                else:
                    # Final attempt failed - raise exception
                    error_msg = f"❌ CRITICAL: Failed to initialize Kafka producer after {self.max_retries} attempts. Kafka connection is REQUIRED for honeypot to function. Last error: {str(e)}"
                    print(error_msg)
                    if self.producer:
                        try:
                            self.producer.close()
                        except:
                            pass
                    raise ConnectionError(f"Cannot connect to Kafka at {self.bootstrap_servers} after {self.max_retries} attempts. Error: {str(last_error)}")
    
    def _send_to_topic(self, topic, log_data, key=None, retry_count=2):
        """Send log data to specific Kafka topic with retry logic (non-blocking)"""
        if not self.producer:
            raise RuntimeError(f"Kafka producer not initialized, cannot send to topic {topic}")
        
        last_error = None
        
        for attempt in range(retry_count):
            try:
                # Add metadata
                log_data['kafka_topic'] = topic
                log_data['kafka_timestamp'] = datetime.now().isoformat()
                
                future = self.producer.send(topic, value=log_data, key=key)
                
                try:
                    record_metadata = future.get(timeout=2) 
                    print(f"✅ Log sent to topic {topic}, partition {record_metadata.partition}, offset {record_metadata.offset}")
                    return True
                except Exception as timeout_error:
                    print(f"⏳ Log queued to {topic} (async send, may complete later)")
                    return True  
                
            except Exception as e:
                last_error = e
                if "Connection" in str(e) or "Broker" in str(e):
                    if attempt < retry_count - 1:
                        wait_time = 0.3 * (attempt + 1)  
                        print(f"⚠️ Failed to send to {topic} (attempt {attempt + 1}/{retry_count}), retrying in {wait_time}s: {str(e)}")
                        time.sleep(wait_time)
                    else:
                        error_msg = f"❌ Failed to send log to topic {topic} after {retry_count} attempts: {str(e)}"
                        print(error_msg)
                        return False
                else:
                    print(f"⚠️ Error sending to {topic}: {str(e)}")
                    return False
        
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

    def send_traffic_log(self, log_data):
        """Send normal traffic logs to honeypot-traffic topic"""
        print(f"🚦 Sending traffic log: {log_data.get('method', 'GET')} {log_data.get('path', '/')} from {log_data.get('ip', 'unknown')}")
        return self._send_to_topic('honeypot-traffic', log_data, key=log_data.get('ip'))
    
    def close(self):
        """Close Kafka producer"""
        if self.producer:
            self.producer.flush()
            self.producer.close()
            print("🔒 Kafka producer closed")
