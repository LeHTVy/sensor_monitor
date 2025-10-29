#!/usr/bin/env python3
"""
Log Receiver and Web Interface for Capture Server
Receives logs from honeypot servers and provides web interface
"""

from flask import Flask, request, jsonify, render_template, send_from_directory
import json
import os
import sqlite3
from datetime import datetime, timedelta
import threading
import queue
import time
import logging
from collections import defaultdict, deque
import hashlib
from kafka_consumer import CaptureKafkaConsumer
from security_middleware import CaptureSecurity, admin_required, api_key_required, ip_whitelist_required
from elasticsearch import Elasticsearch

app = Flask(__name__)

# Initialize security middleware
security = CaptureSecurity(app)
# Ensure middleware instance is attached to the app for decorators to access
app.security = security

# Global variables for logging and statistics
log_queue = queue.Queue()
kafka_consumer = CaptureKafkaConsumer()

# Elasticsearch configuration
USE_ELASTICSEARCH = os.getenv('USE_ELASTICSEARCH', 'false').lower() == 'true'
ES_URL = os.getenv('ELASTICSEARCH_URL', 'http://elasticsearch:9200')
ES_PREFIX = os.getenv('ES_INDEX_PREFIX', 'sensor-logs')
es_client = Elasticsearch(ES_URL) if USE_ELASTICSEARCH else None

stats = {
    'total_logs_received': 0,
    'attack_logs': 0,
    'honeypot_logs': 0,
    'error_logs': 0,
    'last_received': None,
    'start_time': datetime.now().isoformat(),
    'uptime': 0
}

# Recent logs storage
recent_logs = deque(maxlen=1000)
attack_logs = deque(maxlen=500)
honeypot_logs = deque(maxlen=500)

# Database setup
DB_FILE = 'logs/capture.db'

def init_database():
    """Initialize SQLite database"""
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            log_type TEXT NOT NULL,
            source_ip TEXT,
            target_ip TEXT,
            port INTEGER,
            protocol TEXT,
            payload TEXT,
            raw_data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create attack patterns table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL,
            count INTEGER DEFAULT 1,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def log_to_database(log_data):
    """Log data to SQLite database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO logs (timestamp, log_type, source_ip, target_ip, port, protocol, payload, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_data.get('timestamp', ''),
            log_data.get('type', 'unknown'),
            log_data.get('src_ip', ''),
            log_data.get('dst_ip', ''),
            log_data.get('dst_port', 0),
            log_data.get('protocol', ''),
            log_data.get('payload', ''),
            json.dumps(log_data)
        ))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Database error: {e}")

def process_log_queue():
    """Process logs from queue"""
    while True:
        try:
            log_data = log_queue.get(timeout=1)
            if log_data:
                # Update statistics
                stats['total_logs_received'] += 1
                stats['last_received'] = datetime.now().isoformat()
                
                log_type = log_data.get('type', 'unknown')
                if log_type == 'attack':
                    stats['attack_logs'] += 1
                    attack_logs.append(log_data)
                elif log_type == 'honeypot':
                    stats['honeypot_logs'] += 1
                    honeypot_logs.append(log_data)
                else:
                    stats['error_logs'] += 1
                
                # Store in recent logs
                recent_logs.append(log_data)
                
                # Log to database
                log_to_database(log_data)
                
                # Update attack patterns
                update_attack_patterns(log_data)
                
                log_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logging.error(f"Error processing log: {e}")

def es_search_logs(log_type: str, limit: int):
    """Search logs from Elasticsearch"""
    if not es_client:
        return []
    
    try:
        # Search in today's and yesterday's indices
        today = datetime.utcnow().strftime('%Y.%m.%d')
        yesterday = (datetime.utcnow() - timedelta(days=1)).strftime('%Y.%m.%d')
        query_index = f"{ES_PREFIX}-*"
        
        must = []
        if log_type != "all":
            must.append({"term": {"log_category": log_type}})
        
        body = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": must}},
        }
        
        res = es_client.search(index=query_index, body=body)
        logs = []
        for hit in res["hits"]["hits"]:
            source = hit["_source"]
            # Normalize log format for frontend
            log = {
                "timestamp": source.get("timestamp", ""),
                "type": source.get("log_category", "unknown"),
                "src_ip": source.get("src_ip", source.get("ip", "")),
                "dst_ip": source.get("dst_ip", ""),
                "attack_tool": source.get("attack_tool", ""),
                "geoip": {
                    "country": source.get("geoip", {}).get("country", ""),
                    "city": source.get("geoip", {}).get("city", ""),
                    "isp": source.get("geoip", {}).get("isp", "")
                },
                "message": source.get("payload", ""),
                "method": source.get("method", ""),
                "path": source.get("path", ""),
                "user_agent": source.get("user_agent", ""),
                "protocol": source.get("protocol", ""),
                "port": source.get("dst_port", source.get("port", 0))
            }
            logs.append(log)
        
        return logs
    except Exception as e:
        logging.error(f"Elasticsearch search error: {e}")
        return []

def update_attack_patterns(log_data):
    """Update attack pattern statistics"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Extract attack pattern from payload
        payload = log_data.get('payload', '')
        if payload:
            # Simple pattern extraction (can be enhanced)
            pattern = payload[:50]  # First 50 characters as pattern
            
            cursor.execute('''
                SELECT id, count FROM attack_patterns WHERE pattern = ?
            ''', (pattern,))
            
            result = cursor.fetchone()
            if result:
                # Update existing pattern
                cursor.execute('''
                    UPDATE attack_patterns 
                    SET count = count + 1, last_seen = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (result[0],))
            else:
                # Insert new pattern
                cursor.execute('''
                    INSERT INTO attack_patterns (pattern, count)
                    VALUES (?, 1)
                ''', (pattern,))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Error updating attack patterns: {e}")

# API Routes
@app.route('/')
def index():
    """Health landing - API only server"""
    return jsonify({
        'service': 'capture-server',
        'message': 'API service. Use frontend at port 3000.',
        'docs': '/api/health'
    })

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login endpoint to get API key"""
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Simple authentication (in production, use proper user management)
    # NOTE: use fixed API key if provided via env (docker-compose)
    if username == 'admin' and password == 'capture2024':
        api_key = os.getenv('CAPTURE_API_KEY', 'capture_secure_key_2024')
        jwt_token = security.generate_jwt_token('admin')
        
        print(f"Login successful for {username}, API key: {api_key}")
        
        return jsonify({
            'success': True,
            'api_key': api_key,
            'jwt_token': jwt_token,
            'message': 'Login successful'
        })
    
    return jsonify({
        'success': False,
        'message': 'Invalid credentials'
    }), 401

@app.route('/api/health')
def health():
    """Health check endpoint"""
    stats['uptime'] = (datetime.now() - datetime.fromisoformat(stats['start_time'])).total_seconds()
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'stats': stats
    })

@app.route('/api/logs')
@api_key_required
def get_logs():
    """Get recent logs from Elasticsearch or Kafka"""
    limit = request.args.get('limit', 100, type=int)
    log_type = request.args.get('type', 'all')
    
    print(f"🔄 API /api/logs called with type={log_type}, limit={limit}")
    
    logs = []
    if USE_ELASTICSEARCH:
        logs = es_search_logs(log_type, limit)
        print(f"🔍 Retrieved {len(logs)} logs from Elasticsearch")
    else:
        # Fallback to Kafka consumer
        if log_type == 'attack':
            logs = kafka_consumer.get_attack_logs(limit)
            print(f"⚔️ Retrieved {len(logs)} attack logs from Kafka")
        elif log_type == 'honeypot':
            logs = kafka_consumer.get_browser_logs(limit)
            print(f"🌐 Retrieved {len(logs)} browser logs from Kafka")
        elif log_type == 'error':
            logs = kafka_consumer.get_error_logs(limit)
            print(f"❌ Retrieved {len(logs)} error logs from Kafka")
        else:
            logs = kafka_consumer.get_all_logs(limit)
            print(f"📊 Retrieved {len(logs)} total logs from Kafka")
    
    # Debug: Print sample log if available
    if logs:
        print(f"📝 Sample log: {logs[0]}")
    
    return jsonify({
        'logs': logs,
        'total': len(logs),
        'type': log_type,
        'limit': limit,
        'kafka_status': 'via_elasticsearch' if USE_ELASTICSEARCH else ('connected' if kafka_consumer.consumer else 'disconnected'),
        'timestamp': datetime.now().isoformat()
    })

def es_get_stats():
    """Get statistics from Elasticsearch"""
    if not es_client:
        return stats
    
    try:
        # Search in all indices
        query_index = f"{ES_PREFIX}-*"
        
        # Get total count
        total_res = es_client.count(index=query_index)
        total_logs = total_res['count']
        
        # Get counts by log_category
        body = {
            "size": 0,
            "aggs": {
                "by_category": {
                    "terms": {
                        "field": "log_category.keyword",
                        "size": 10
                    }
                }
            }
        }
        
        res = es_client.search(index=query_index, body=body)
        
        # Parse aggregations
        attack_logs = 0
        honeypot_logs = 0
        error_logs = 0
        
        for bucket in res['aggregations']['by_category']['buckets']:
            category = bucket['key']
            count = bucket['doc_count']
            
            if category == 'attack':
                attack_logs = count
            elif category == 'honeypot':
                honeypot_logs = count
            elif category == 'error':
                error_logs = count
        
        # Get latest timestamp
        latest_res = es_client.search(
            index=query_index,
            body={
                "size": 1,
                "sort": [{"timestamp": {"order": "desc"}}]
            }
        )
        
        last_received = None
        if latest_res['hits']['hits']:
            last_received = latest_res['hits']['hits'][0]['_source']['timestamp']
        
        return {
            'total_logs_received': total_logs,
            'attack_logs': attack_logs,
            'honeypot_logs': honeypot_logs,
            'error_logs': error_logs,
            'last_received': last_received,
            'start_time': stats['start_time'],
            'uptime': (datetime.now() - datetime.fromisoformat(stats['start_time'])).total_seconds()
        }
    except Exception as e:
        logging.error(f"Elasticsearch stats error: {e}")
        return stats

@app.route('/api/stats')
@api_key_required
def get_stats():
    """Get statistics"""
    if USE_ELASTICSEARCH:
        es_stats = es_get_stats()
        print(f"📊 Stats API called - ES: {es_stats}")
        return jsonify({
            'stats': es_stats,
            'kafka_stats': {'source': 'elasticsearch'},
            'timestamp': datetime.now().isoformat()
        })
    else:
        # Fallback to original Kafka stats
        stats['uptime'] = (datetime.now() - datetime.fromisoformat(stats['start_time'])).total_seconds()
        
        kafka_stats = {
            'browser_logs': len(kafka_consumer.browser_logs),
            'attack_logs': len(kafka_consumer.attack_logs),
            'error_logs': len(kafka_consumer.error_logs),
            'consumer_running': kafka_consumer.running,
            'consumer_connected': kafka_consumer.consumer is not None
        }
        
        print(f"📊 Stats API called - Kafka: {kafka_stats}")
        
        return jsonify({
            'stats': stats,
            'kafka_stats': kafka_stats,
            'timestamp': datetime.now().isoformat()
        })

@app.route('/api/attack-patterns')
@api_key_required
def get_attack_patterns():
    """Get attack patterns from database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT pattern, count, first_seen, last_seen
            FROM attack_patterns
            ORDER BY count DESC
            LIMIT 50
        ''')
        
        patterns = []
        for row in cursor.fetchall():
            patterns.append({
                'pattern': row[0],
                'count': row[1],
                'first_seen': row[2],
                'last_seen': row[3]
            })
        
        conn.close()
        return jsonify({
            'patterns': patterns,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/search')
def search_logs():
    """Search logs by criteria"""
    query = request.args.get('q', '')
    log_type = request.args.get('type', 'all')
    limit = request.args.get('limit', 100, type=int)
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        sql = '''
            SELECT timestamp, log_type, source_ip, target_ip, port, protocol, payload
            FROM logs
            WHERE 1=1
        '''
        params = []
        
        if query:
            sql += ' AND (payload LIKE ? OR source_ip LIKE ? OR target_ip LIKE ?)'
            params.extend([f'%{query}%', f'%{query}%', f'%{query}%'])
        
        if log_type != 'all':
            sql += ' AND log_type = ?'
            params.append(log_type)
        
        sql += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(sql, params)
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'timestamp': row[0],
                'type': row[1],
                'src_ip': row[2],
                'dst_ip': row[3],
                'port': row[4],
                'protocol': row[5],
                'payload': row[6]
            })
        
        conn.close()
        return jsonify({
            'logs': logs,
            'total': len(logs),
            'query': query,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/export')
def export_logs():
    """Export logs to JSON"""
    log_type = request.args.get('type', 'all')
    limit = request.args.get('limit', 1000, type=int)
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        sql = 'SELECT * FROM logs'
        params = []
        
        if log_type != 'all':
            sql += ' WHERE log_type = ?'
            params.append(log_type)
        
        sql += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(sql, params)
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'id': row[0],
                'timestamp': row[1],
                'log_type': row[2],
                'source_ip': row[3],
                'target_ip': row[4],
                'port': row[5],
                'protocol': row[6],
                'payload': row[7],
                'raw_data': json.loads(row[8]) if row[8] else None,
                'created_at': row[9]
            })
        
        conn.close()
        return jsonify({
            'logs': logs,
            'total': len(logs),
            'exported_at': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Log receiving endpoints
@app.route('/api/logs/receive', methods=['POST'])
def receive_log():
    """Receive log from honeypot server"""
    try:
        log_data = request.get_json()
        if not log_data:
            return jsonify({'error': 'No data received'}), 400
        
        # Add timestamp if not present
        if 'timestamp' not in log_data:
            log_data['timestamp'] = datetime.now().isoformat()
        
        # Add to queue for processing
        log_queue.put(log_data)
        
        return jsonify({
            'status': 'success',
            'message': 'Log received',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/bulk', methods=['POST'])
def receive_bulk_logs():
    """Receive multiple logs from honeypot server"""
    try:
        data = request.get_json()
        logs = data.get('logs', [])
        
        if not logs:
            return jsonify({'error': 'No logs received'}), 400
        
        # Process each log
        for log_data in logs:
            if 'timestamp' not in log_data:
                log_data['timestamp'] = datetime.now().isoformat()
            log_queue.put(log_data)
        
        return jsonify({
            'status': 'success',
            'message': f'{len(logs)} logs received',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Static files
@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('static', filename)

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Start log processing thread
    log_thread = threading.Thread(target=process_log_queue)
    log_thread.daemon = True
    log_thread.start()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/receiver.log'),
            logging.StreamHandler()
        ]
    )
    
@app.route('/api/test', methods=['GET'])
def test_endpoint():
    """Test endpoint without authentication"""
    return jsonify({
        'message': 'Test endpoint working',
        'timestamp': datetime.now().isoformat(),
        'kafka_connected': kafka_consumer is not None
    })

if __name__ == '__main__':
    print("Starting Log Receiver...")
    
    # Start Kafka consumer in background thread
    kafka_thread = threading.Thread(target=kafka_consumer.start_consuming, daemon=True)
    kafka_thread.start()
    print("✅ Kafka consumer started")
    
    app.run(host='0.0.0.0', port=8080, debug=True)