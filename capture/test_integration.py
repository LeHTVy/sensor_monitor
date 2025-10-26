#!/usr/bin/env python3
"""
Test script for honeypot and capture server integration
"""

import requests
import json
import time
import random
from datetime import datetime

def test_capture_server():
    """Test capture server endpoints"""
    base_url = "http://172.232.246.68:8080"
    
    print("Testing Capture Server...")
    
    # Test health endpoint
    try:
        response = requests.get(f"{base_url}/api/health")
        if response.status_code == 200:
            print("✅ Health check passed")
            print(f"   Status: {response.json()['status']}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Health check error: {e}")
    
    # Test main page
    try:
        response = requests.get(f"{base_url}/")
        if response.status_code == 200:
            print("✅ Main page accessible")
        else:
            print(f"❌ Main page failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Main page error: {e}")
    
    # Test logs endpoint
    try:
        response = requests.get(f"{base_url}/api/logs")
        if response.status_code == 200:
            print("✅ Logs endpoint working")
            logs = response.json()['logs']
            print(f"   Found {len(logs)} logs")
        else:
            print(f"❌ Logs endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Logs endpoint error: {e}")
    
    # Test stats endpoint
    try:
        response = requests.get(f"{base_url}/api/stats")
        if response.status_code == 200:
            print("✅ Stats endpoint working")
            stats = response.json()['stats']
            print(f"   Total logs: {stats['total_logs_received']}")
            print(f"   Attack logs: {stats['attack_logs']}")
            print(f"   Honeypot logs: {stats['honeypot_logs']}")
        else:
            print(f"❌ Stats endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Stats endpoint error: {e}")

def send_test_logs():
    """Send test logs to capture server"""
    base_url = "http://172.232.246.68:8080"
    
    print("\nSending test logs...")
    
    # Test single log
    test_log = {
        "type": "attack",
        "timestamp": datetime.now().isoformat(),
        "src_ip": "192.168.1.100",
        "dst_ip": "172.232.246.68",
        "protocol": "TCP",
        "src_port": 12345,
        "dst_port": 22,
        "payload": "SSH brute force attempt",
        "flags": 2
    }
    
    try:
        response = requests.post(f"{base_url}/api/logs/receive", json=test_log)
        if response.status_code == 200:
            print("✅ Single log sent successfully")
        else:
            print(f"❌ Single log failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Single log error: {e}")
    
    # Test bulk logs
    bulk_logs = []
    for i in range(5):
        log = {
            "type": random.choice(["attack", "honeypot", "error"]),
            "timestamp": datetime.now().isoformat(),
            "src_ip": f"192.168.1.{100 + i}",
            "dst_ip": "172.232.246.68",
            "protocol": random.choice(["TCP", "UDP"]),
            "src_port": random.randint(10000, 65535),
            "dst_port": random.choice([22, 80, 443, 3389]),
            "payload": f"Test payload {i}",
            "flags": random.randint(0, 15)
        }
        bulk_logs.append(log)
    
    try:
        response = requests.post(f"{base_url}/api/logs/bulk", json={"logs": bulk_logs})
        if response.status_code == 200:
            print("✅ Bulk logs sent successfully")
        else:
            print(f"❌ Bulk logs failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Bulk logs error: {e}")

def test_honeypot_integration():
    """Test integration with honeypot server"""
    honeypot_url = "http://172.232.246.68:5000"
    capture_url = "http://172.232.246.68:8080"
    
    print("\nTesting Honeypot Integration...")
    
    # Test honeypot health
    try:
        response = requests.get(f"{honeypot_url}/api/health")
        if response.status_code == 200:
            print("✅ Honeypot server accessible")
        else:
            print(f"❌ Honeypot server failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Honeypot server error: {e}")
    
    # Test honeypot login (should generate logs)
    try:
        response = requests.post(f"{honeypot_url}/login", data={
            "username": "admin",
            "password": "wrongpassword"
        })
        print("✅ Honeypot login test completed")
    except Exception as e:
        print(f"❌ Honeypot login error: {e}")
    
    # Wait a bit for logs to be processed
    time.sleep(2)
    
    # Check if logs appeared in capture server
    try:
        response = requests.get(f"{capture_url}/api/logs")
        if response.status_code == 200:
            logs = response.json()['logs']
            print(f"✅ Found {len(logs)} logs in capture server")
            
            # Show recent logs
            for log in logs[:3]:
                print(f"   - {log['type']}: {log['src_ip']} -> {log['dst_ip']}:{log.get('dst_port', 'N/A')}")
        else:
            print(f"❌ Failed to get logs: {response.status_code}")
    except Exception as e:
        print(f"❌ Log retrieval error: {e}")

def main():
    """Main test function"""
    print("=" * 50)
    print("CAPTURE SERVER INTEGRATION TEST")
    print("=" * 50)
    
    # Test capture server
    test_capture_server()
    
    # Send test logs
    send_test_logs()
    
    # Test honeypot integration
    test_honeypot_integration()
    
    print("\n" + "=" * 50)
    print("TEST COMPLETED")
    print("=" * 50)
    
    print("\nTo view the dashboard, open:")
    print("http://172.232.246.68:8080")

if __name__ == "__main__":
    main()
