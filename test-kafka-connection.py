#!/usr/bin/env python3
"""
Test Kafka Connection Script
"""

import json
import time
from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import KafkaError

def test_kafka_producer():
    """Test Kafka Producer"""
    print("🔄 Testing Kafka Producer...")
    try:
        producer = KafkaProducer(
            bootstrap_servers=['172.232.246.68:9093'],
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            api_version=(2, 5, 0)
        )
        
        # Send test message
        test_message = {
            'test': True,
            'timestamp': time.time(),
            'message': 'Test message from producer'
        }
        
        future = producer.send('test-topic', test_message)
        record_metadata = future.get(timeout=10)
        
        print(f"✅ Producer test successful: partition {record_metadata.partition}, offset {record_metadata.offset}")
        producer.close()
        return True
        
    except Exception as e:
        print(f"❌ Producer test failed: {str(e)}")
        return False

def test_kafka_consumer():
    """Test Kafka Consumer"""
    print("🔄 Testing Kafka Consumer...")
    try:
        consumer = KafkaConsumer(
            'test-topic',
            bootstrap_servers=['172.232.246.68:9093'],
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='latest',
            consumer_timeout_ms=5000,
            api_version=(2, 5, 0)
        )
        
        print("✅ Consumer initialized successfully")
        consumer.close()
        return True
        
    except Exception as e:
        print(f"❌ Consumer test failed: {str(e)}")
        return False

def test_topics():
    """Test Kafka Topics"""
    print("🔄 Testing Kafka Topics...")
    try:
        consumer = KafkaConsumer(
            bootstrap_servers=['172.232.246.68:9093'],
            api_version=(2, 5, 0)
        )
        
        topics = consumer.list_consumer_groups()
        print(f"✅ Available topics: {list(consumer.topics())}")
        consumer.close()
        return True
        
    except Exception as e:
        print(f"❌ Topics test failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("🚀 Starting Kafka Connection Tests...")
    
    # Test producer
    producer_ok = test_kafka_producer()
    
    # Test consumer
    consumer_ok = test_kafka_consumer()
    
    # Test topics
    topics_ok = test_topics()
    
    print("\n📊 Test Results:")
    print(f"Producer: {'✅ PASS' if producer_ok else '❌ FAIL'}")
    print(f"Consumer: {'✅ PASS' if consumer_ok else '❌ FAIL'}")
    print(f"Topics: {'✅ PASS' if topics_ok else '❌ FAIL'}")
    
    if producer_ok and consumer_ok and topics_ok:
        print("\n🎉 All Kafka tests passed!")
    else:
        print("\n⚠️ Some Kafka tests failed!")
