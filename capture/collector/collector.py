#!/usr/bin/env python3
"""
Kafka to Elasticsearch Collector
Consumes logs from Kafka topics and bulk indexes to Elasticsearch
"""

import os
import json
import time
from datetime import datetime
from kafka import KafkaConsumer
from elasticsearch import Elasticsearch, helpers

# Configuration from environment
bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
topics = [t.strip() for t in os.getenv("KAFKA_TOPICS", "honeypot-attacks,honeypot-browser,honeypot-traffic").split(",")]
group_id = os.getenv("KAFKA_GROUP", "capture-es-collector")
es_host = os.getenv("ES_HOST", "http://elasticsearch:9200")
index_prefix = os.getenv("ES_INDEX_PREFIX", "sensor-logs")
batch_size = int(os.getenv("BATCH_SIZE", "500"))
flush_interval_ms = int(os.getenv("FLUSH_INTERVAL_MS", "1000"))
auto_offset_reset = os.getenv("AUTO_OFFSET_RESET", "latest")

# Initialize Elasticsearch
es = None
consumer = None

def wait_for_elasticsearch(max_retries=30, retry_delay=2):
    """Wait for Elasticsearch to be ready"""
    global es
    print(f"⏳ Waiting for Elasticsearch at {es_host}...")
    
    for attempt in range(max_retries):
        try:
            es = Elasticsearch(es_host)
            if es.ping():
                print(f"✅ Elasticsearch is ready!")
                return True
        except Exception as e:
            pass
        
        if attempt < max_retries - 1:
            print(f"⏳ Elasticsearch not ready (attempt {attempt + 1}/{max_retries}), retrying in {retry_delay}s...")
            time.sleep(retry_delay)
    
    print(f"❌ Elasticsearch not available after {max_retries} attempts")
    return False

def index_name_for_topic(topic: str) -> str:
    """Generate clean index name without date suffix"""
    # Map topics to clean index names
    topic_mapping = {
        'honeypot-attacks': f"{index_prefix}-attacks",
        'honeypot-browser': f"{index_prefix}-honeypot", 
        'honeypot-traffic': f"{index_prefix}-traffic",
        # Backward compat if còn log cũ
        'honeypot-errors': f"{index_prefix}-traffic"
    }
    return topic_mapping.get(topic, f"{index_prefix}-{topic}")

def ensure_template():
    """Create Elasticsearch index template"""
    if not es:
        print("❌ Elasticsearch client not initialized")
        return False
    
    template = {
        "index_patterns": [f"{index_prefix}-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": {
                "dynamic": "true",
                "properties": {
                    "timestamp": {"type": "date"},
                    "ip": {"type": "ip"},
                    "src_ip": {"type": "ip"},
                    "dst_ip": {"type": "ip"},
                    "attack_tool": {"type": "keyword"},
                    "attack_technique": {"type": "keyword"},
                    "log_category": {"type": "keyword"},
                    "user_agent": {"type": "text"},
                    "kafka_topic": {"type": "keyword"},
                    "method": {"type": "keyword"},
                    "path": {"type": "keyword"},
                    "protocol": {"type": "keyword"},
                },
            },
        },
        "priority": 1,
    }
    
    max_retries = 5
    for attempt in range(max_retries):
        try:
            es.indices.put_index_template(
                name=f"{index_prefix}-template", 
                body=template, 
                create=True, 
                ignore=409
            )
            print("✅ Elasticsearch template created")
            return True
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"⚠️ Error creating template (attempt {attempt + 1}/{max_retries}): {e}, retrying...")
                time.sleep(2)
            else:
                print(f"❌ Error creating template after {max_retries} attempts: {e}")
                return False
    return False

def run():
    """Main collector loop"""
    global es, consumer
    
    print("🔄 Starting Kafka to Elasticsearch collector...")
    print(f"📊 Topics: {topics}")
    print(f"📦 Batch size: {batch_size}")
    print(f"⏱️ Flush interval: {flush_interval_ms}ms")
    
    # Wait for Elasticsearch to be ready
    if not wait_for_elasticsearch():
        print("❌ Cannot start collector: Elasticsearch not available")
        return
    
    # Ensure template exists
    if not ensure_template():
        print("⚠️ Warning: Could not create template, continuing anyway...")
    
    # Initialize Kafka Consumer
    print(f"📡 Connecting to Kafka at {bootstrap}...")
    try:
        consumer = KafkaConsumer(
            *topics,
            bootstrap_servers=[bootstrap],
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            key_deserializer=lambda k: k.decode("utf-8") if k else None,
            enable_auto_commit=True,
            group_id=group_id,
            auto_offset_reset=auto_offset_reset,
            api_version=(2, 5, 0),
        )
        print("✅ Kafka consumer connected")
    except Exception as e:
        print(f"❌ Failed to connect to Kafka: {e}")
        return
    
    buffer = []
    last_flush = time.time()
    processed_count = 0
    
    try:
        for msg in consumer:
            doc = msg.value.copy()
            
            # Normalize timestamp
            if "timestamp" not in doc:
                doc["timestamp"] = datetime.utcnow().isoformat()
            
            # Add metadata
            doc["kafka_topic"] = msg.topic
            doc["@ingested_at"] = datetime.utcnow().isoformat()
            doc["kafka_partition"] = msg.partition
            doc["kafka_offset"] = msg.offset
            
            # Create bulk action
            action = {
                "_index": index_name_for_topic(msg.topic),
                "_source": doc,
            }
            buffer.append(action)
            
            # Flush when batch size reached or time interval passed
            if len(buffer) >= batch_size or (time.time() - last_flush) * 1000 >= flush_interval_ms:
                try:
                    helpers.bulk(es, buffer, raise_on_error=False)
                    processed_count += len(buffer)
                    print(f"📤 Indexed {len(buffer)} documents (total: {processed_count})")
                    buffer.clear()
                    last_flush = time.time()
                except Exception as e:
                    print(f"❌ Error indexing batch: {e}")
                    buffer.clear()
                    
    except KeyboardInterrupt:
        print("🛑 Collector stopped by user")
    except Exception as e:
        print(f"❌ Collector error: {e}")
        import traceback
        print(traceback.format_exc())
    finally:
        # Flush remaining documents
        if buffer and es:
            try:
                helpers.bulk(es, buffer, raise_on_error=False)
                print(f"📤 Final flush: {len(buffer)} documents")
            except Exception as e:
                print(f"❌ Error in final flush: {e}")
        if consumer:
            consumer.close()
        print("🔒 Collector shutdown complete")

if __name__ == "__main__":
    run()