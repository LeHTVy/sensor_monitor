#!/usr/bin/env python3
"""
Kafka to Elasticsearch Collector with Enrichment
Consumes logs from Kafka, enriches them, and bulk indexes to Elasticsearch
"""

import os
import json
import time
import sys
from datetime import datetime
from kafka import KafkaConsumer
from elasticsearch import Elasticsearch, helpers

# Add parent directory to path for imports
sys.path.append('/app')
from enrichment_engine import EnrichmentEngine

# Configuration from environment
bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
topics = [t.strip() for t in os.getenv("KAFKA_TOPICS", "honeypot-attacks,honeypot-traffic").split(",")]
group_id = os.getenv("KAFKA_GROUP", "capture-es-collector")
es_host = os.getenv("ES_HOST", "http://elasticsearch:9200")
index_prefix = os.getenv("ES_INDEX_PREFIX", "sensor-logs")
batch_size = int(os.getenv("BATCH_SIZE", "50"))  
flush_interval_ms = int(os.getenv("FLUSH_INTERVAL_MS", "500"))  
auto_offset_reset = os.getenv("AUTO_OFFSET_RESET", "earliest")
enable_enrichment = os.getenv("ENABLE_ENRICHMENT", "true").lower() == "true"
enable_osint = os.getenv("ENABLE_OSINT", "false").lower() == "true"

# Global instances
es = None
consumer = None
enrichment_engine = None

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

def initialize_enrichment():
    """Initialize enrichment engine"""
    global enrichment_engine
    
    if not enable_enrichment:
        print("ℹ️  Enrichment disabled")
        return True
    
    try:
        print("\n🔧 Initializing enrichment engine...")
        enrichment_engine = EnrichmentEngine(enable_osint=enable_osint)
        print("✅ Enrichment engine ready")
        return True
    except Exception as e:
        print(f"❌ Failed to initialize enrichment engine: {e}")
        return False

def index_name_for_topic(topic: str) -> str:
    """Generate clean index name (2 topics only)"""
    topic_mapping = {
        'honeypot-attacks': f"{index_prefix}-attacks",
        'honeypot-traffic': f"{index_prefix}-traffic"
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
                    "@ingested_at": {"type": "date"},
                    "ip": {"type": "ip"},
                    "src_ip": {"type": "ip"},
                    "dst_ip": {"type": "ip"},
                    "attack_tool": {"type": "keyword"},
                    "attack_techniques": {"type": "keyword"},
                    "log_category": {"type": "keyword"},
                    "type": {"type": "keyword"},
                    "user_agent": {"type": "text"},
                    "method": {"type": "keyword"},
                    "path": {"type": "keyword"},
                    "threat_level": {"type": "keyword"},
                    "threat_score": {"type": "integer"},
                    "geoip": {
                        "properties": {
                            "country": {"type": "keyword"},
                            "city": {"type": "keyword"},
                            "isp": {"type": "keyword"},
                            "lat": {"type": "float"},
                            "lon": {"type": "float"}
                        }
                    },
                    "osint": {"type": "object", "enabled": True}
                }
            }
        }
    }
    
    try:
        es.indices.put_index_template(name=f"{index_prefix}-template", body=template)
        print(f"✅ Created index template: {index_prefix}-template")
        return True
    except Exception as e:
        print(f"⚠️  Warning: Could not create template: {e}")
        return False

def normalize_log(log: dict, topic: str) -> dict:
    """Normalize log data before indexing"""
    # Ensure timestamp exists
    if 'timestamp' not in log:
        log['timestamp'] = datetime.now().isoformat()
    
    # Add ingestion timestamp
    log['@ingested_at'] = datetime.now().isoformat()
    
    # Add source topic
    log['kafka_topic'] = topic
    
    return log

def bulk_index(batch: list, topic: str):
    """Bulk index documents to Elasticsearch"""
    if not batch or not es:
        return
    
    index_name = index_name_for_topic(topic)
    
    actions = [
        {
            "_index": index_name,
            "_source": doc
        }
        for doc in batch
    ]
    
    try:
        success, failed = helpers.bulk(es, actions, raise_on_error=False, raise_on_exception=False)
        if success:
            print(f"✅ Indexed {success} documents to {index_name}")
        if failed:
            print(f"⚠️  Failed to index {len(failed)} documents")
    except Exception as e:
        print(f"❌ Bulk indexing error: {e}")

def process_log(log: dict, topic: str) -> dict:
    """Process and enrich a single log"""
    # Normalize first
    log = normalize_log(log, topic)
    
    # Enrich if enabled
    if enable_enrichment and enrichment_engine:
        try:
            log = enrichment_engine.enrich_log(log)
        except Exception as e:
            print(f"⚠️  Enrichment failed for log: {e}")
            # Continue with unenriched log
    
    return log

def run():
    """Main collector loop"""
    global es, consumer
    
    print("\n" + "="*70)
    print("🚀 Starting Kafka to Elasticsearch Collector")
    print("="*70)
    print(f"📊 Topics: {topics}")
    print(f"📦 Batch size: {batch_size}")
    print(f"⏱️  Flush interval: {flush_interval_ms}ms")
    print(f"🔧 Enrichment: {'✓' if enable_enrichment else '✗'}")
    print(f"🔎 OSINT: {'✓' if enable_osint else '✗'}")
    print("="*70 + "\n")
    
    # Wait for Elasticsearch to be ready
    if not wait_for_elasticsearch():
        print("❌ Cannot start collector: Elasticsearch not available")
        return
    
    # Initialize enrichment
    if not initialize_enrichment():
        print("⚠️  Warning: Enrichment initialization failed, continuing without enrichment...")
    
    # Create template
    if not ensure_template():
        print("⚠️  Warning: Could not create template, continuing anyway...")
    
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
        print("✅ Kafka consumer connected\n")
    except Exception as e:
        print(f"❌ Failed to connect to Kafka: {e}")
        return
    
    buffer = {}  # topic -> list of docs
    last_flush = time.time()
    
    print("👂 Listening for logs...\n")
    
    try:
        for message in consumer:
            topic = message.topic
            log = message.value
            
            # Process and enrich log
            processed_log = process_log(log, topic)
            
            # Add to buffer
            if topic not in buffer:
                buffer[topic] = []
            buffer[topic].append(processed_log)
            
            # Flush if batch size reached or time elapsed
            current_time = time.time()
            should_flush = (
                any(len(docs) >= batch_size for docs in buffer.values()) or
                (current_time - last_flush) * 1000 >= flush_interval_ms
            )
            
            if should_flush:
                for topic_name, docs in buffer.items():
                    if docs:
                        bulk_index(docs, topic_name)
                
                buffer = {}
                last_flush = current_time
    
    except KeyboardInterrupt:
        print("\n⏸️  Shutting down...")
    except Exception as e:
        print(f"❌ Error in collector loop: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Flush remaining docs
        for topic_name, docs in buffer.items():
            if docs:
                bulk_index(docs, topic_name)
        
        if consumer:
            consumer.close()
            print("🔒 Kafka consumer closed")

if __name__ == "__main__":
    run()