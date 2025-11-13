#!/usr/bin/env python3
"""
Test script to verify VPN and Kafka connectivity
Tests the complete log flow from honeypot to capture server
"""

import sys
import os
import socket
import time
from datetime import datetime

# Add app to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

print("="*60)
print("🧪 Honeypot VPN & Kafka Connectivity Test")
print("="*60)
print()

# Test 1: VPN Connectivity
print("📡 Test 1: VPN Connectivity")
print("-" * 60)

vpn_interface = "wg0"
capture_server_ip = "10.8.0.1"
kafka_port = 9093
backend_port = 8082

# Test VPN interface
print(f"✓ Checking VPN interface: {vpn_interface}")
try:
    import subprocess
    result = subprocess.run(['ip', 'addr', 'show', vpn_interface],
                          capture_output=True, text=True, timeout=5)
    if result.returncode == 0 and '10.8.0.' in result.stdout:
        print(f"  ✅ VPN interface {vpn_interface} is UP")
        # Extract IP
        for line in result.stdout.split('\n'):
            if 'inet ' in line and '10.8.0.' in line:
                ip = line.strip().split()[1]
                print(f"  📍 VPN IP: {ip}")
    else:
        print(f"  ❌ VPN interface {vpn_interface} is DOWN or not configured")
        print("  ⚠️  Please check WireGuard configuration")
except Exception as e:
    print(f"  ⚠️  Cannot check VPN interface: {e}")
    print(f"  ℹ️  If running in Docker, this is expected")

print()

# Test 2: Capture Server Reachability
print("🌐 Test 2: Capture Server Reachability")
print("-" * 60)

def test_tcp_connection(host, port, service_name, timeout=5):
    """Test TCP connection to a service"""
    print(f"✓ Testing {service_name} at {host}:{port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start_time = time.time()
        result = sock.connect_ex((host, port))
        latency = (time.time() - start_time) * 1000
        sock.close()

        if result == 0:
            print(f"  ✅ {service_name} is reachable (latency: {latency:.1f}ms)")
            return True
        else:
            print(f"  ❌ {service_name} is NOT reachable (error code: {result})")
            return False
    except socket.timeout:
        print(f"  ❌ {service_name} connection timeout")
        return False
    except Exception as e:
        print(f"  ❌ {service_name} connection error: {e}")
        return False

# Test Kafka
kafka_ok = test_tcp_connection(capture_server_ip, kafka_port, "Kafka")

# Test Backend API
backend_ok = test_tcp_connection(capture_server_ip, backend_port, "Backend API")

print()

# Test 3: Kafka Producer
print("📤 Test 3: Kafka Producer")
print("-" * 60)

try:
    print("✓ Importing KafkaProducer...")
    from utils.kafka_producer import KafkaProducer

    print(f"✓ Connecting to Kafka at {capture_server_ip}:{kafka_port}...")
    producer = KafkaProducer(bootstrap_servers=f"{capture_server_ip}:{kafka_port}")
    print("  ✅ Kafka producer created successfully")

    # Send test message
    print("✓ Sending test attack log...")
    test_log = {
        'type': 'test',
        'timestamp': datetime.now().isoformat(),
        'source': 'connectivity_test',
        'message': 'This is a test log from VPN connectivity test',
        'test_id': f"test-{int(time.time())}",
        'ip': '127.0.0.1',
        'attack_tool': 'test_tool',
        'attack_tool_info': {
            'tool': 'test_tool',
            'confidence': 100,
            'method': 'test',
            'details': {}
        },
        'log_category': 'attack'
    }

    producer.send_attack_log(test_log)
    print("  ✅ Test log sent successfully to 'honeypot-attacks' topic")

    producer.close()
    print("  ✅ Kafka producer closed")

    kafka_producer_ok = True

except ImportError as e:
    print(f"  ❌ Cannot import KafkaProducer: {e}")
    print(f"  ⚠️  Check if kafka-python is installed: pip install kafka-python")
    kafka_producer_ok = False
except Exception as e:
    print(f"  ❌ Kafka producer error: {e}")
    print(f"  ⚠️  Check Kafka connection and configuration")
    kafka_producer_ok = False

print()

# Test 4: Collector Verification (Optional)
print("📥 Test 4: Collector Status (Optional)")
print("-" * 60)
print("ℹ️  To verify the test log was received:")
print(f"   1. SSH to capture server")
print(f"   2. Check Elasticsearch: curl http://localhost:9200/sensor-logs-attacks/_search?q=test_id:test-*")
print(f"   3. Or check Kibana dashboard")
print()

# Summary
print("="*60)
print("📊 Test Summary")
print("="*60)

tests = [
    ("Kafka Reachability", kafka_ok),
    ("Backend API Reachability", backend_ok),
    ("Kafka Producer", kafka_producer_ok)
]

passed = sum(1 for _, ok in tests if ok)
total = len(tests)

for test_name, ok in tests:
    status = "✅ PASS" if ok else "❌ FAIL"
    print(f"  {status} - {test_name}")

print()
print(f"Result: {passed}/{total} tests passed")

if passed == total:
    print()
    print("🎉 All tests passed! Your honeypot is properly connected.")
    print("   Logs should be flowing: Honeypot → VPN → Kafka → Elasticsearch")
    sys.exit(0)
else:
    print()
    print("⚠️  Some tests failed. Please check:")
    if not kafka_ok:
        print("   • VPN tunnel is running (wg-quick up wg0)")
        print("   • Capture server Kafka is running")
        print(f"   • Firewall allows connection to {capture_server_ip}:{kafka_port}")
    if not kafka_producer_ok:
        print("   • kafka-python is installed")
        print("   • Kafka configuration in .env is correct")
    sys.exit(1)
