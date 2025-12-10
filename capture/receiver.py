#!/usr/bin/env python3
"""
Log Receiver and Web Interface for Capture Server
Receives logs from honeypot servers and provides web interface
"""

from flask import Flask, request, jsonify
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
from recon_service import create_recon_job, get_recon_status, get_recon_results, active_recon_jobs

app = Flask(__name__)

# Initialize security middleware
security = CaptureSecurity(app)
# Ensure middleware instance is attached to the app for decorators to access
app.security = security

# Global variables for logging and statistics
log_queue = queue.Queue()
kafka_consumer = CaptureKafkaConsumer()

print("ℹ️  Receiver: HTTP API only - logs sent directly to Kafka from honeypot")
print("ℹ️  Enrichment: Handled by collector service")

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
                
                # Note: Logs from honeypot go directly to Kafka
                # No need to send from here - collector handles enrichment

                log_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logging.error(f"Error processing log: {e}")

def es_search_logs(log_type: str, limit: int, date_from: str = None, date_to: str = None):
    """Search logs from Elasticsearch with date filtering"""
    if not es_client:
        print("⚠️ Elasticsearch client not available")
        return []
    
    try:
        # Search in all indices matching prefix
        query_index = f"{ES_PREFIX}-*"
        
        # Build query
        must = []
        
        # Filter by log category
        if log_type != "all":
            must.append({
                "bool": {
                    "should": [
                        {"term": {"log_category.keyword": log_type}},
                        {"term": {"log_category": log_type}}
                    ],
                    "minimum_should_match": 1
                }
            })
        
        # Filter by date range
        if date_from or date_to:
            date_filter = {}
            if date_from:
                date_filter["gte"] = date_from
            if date_to:
                date_filter["lte"] = date_to
            must.append({"range": {"timestamp": date_filter}})
        
        body = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
        }
        
        print(f"🔍 ES Query: index={query_index}, type={log_type}, limit={limit}, date_from={date_from}, date_to={date_to}")
        
        res = es_client.search(index=query_index, body=body)
        
        # Handle both old and new ES response formats
        total = res['hits']['total']
        if isinstance(total, dict):
            total = total.get('value', 0)
        
        print(f"📊 ES Search results: {total} total hits, {len(res['hits']['hits'])} returned")
        
        logs = []
        for hit in res["hits"]["hits"]:
            source = hit["_source"]
            # Return full log data with all fields
            log = {
                "id": hit.get("_id", ""),
                "timestamp": source.get("timestamp", ""),
                "type": source.get("log_category", source.get("type", "unknown")),
                "src_ip": source.get("src_ip", source.get("ip", "")),
                "dst_ip": source.get("dst_ip", ""),
                "attack_tool": source.get("attack_tool", "unknown"),
                "attack_tool_info": source.get("attack_tool_info", {}),
                "attack_technique": source.get("attack_technique", []),
                "geoip": {
                    "country": source.get("geoip", {}).get("country", "") if isinstance(source.get("geoip"), dict) else "",
                    "city": source.get("geoip", {}).get("city", "") if isinstance(source.get("geoip"), dict) else "",
                    "isp": source.get("geoip", {}).get("isp", "") if isinstance(source.get("geoip"), dict) else "",
                    "org": source.get("geoip", {}).get("org", "") if isinstance(source.get("geoip"), dict) else "",
                    "lat": source.get("geoip", {}).get("lat", 0) if isinstance(source.get("geoip"), dict) else 0,
                    "lon": source.get("geoip", {}).get("lon", 0) if isinstance(source.get("geoip"), dict) else 0,
                    "timezone": source.get("geoip", {}).get("timezone", "") if isinstance(source.get("geoip"), dict) else "",
                    "region": source.get("geoip", {}).get("region", "") if isinstance(source.get("geoip"), dict) else "",
                    "postal": source.get("geoip", {}).get("postal", "") if isinstance(source.get("geoip"), dict) else ""
                },
                "os_info": source.get("os_info", {}),
                "method": source.get("method", ""),
                "path": source.get("path", ""),
                "url": source.get("url", ""),
                "user_agent": source.get("user_agent", ""),
                "headers": source.get("headers", {}),
                "protocol": source.get("protocol", ""),
                "args": source.get("args", {}),
                "form_data": source.get("form_data", {}),
                "message": source.get("payload", source.get("message", "")),
                "port": source.get("dst_port", source.get("port", 0)),
                "kafka_topic": source.get("kafka_topic", ""),
                "@ingested_at": source.get("@ingested_at", ""),
                "llm_analysis": source.get("llm_analysis", None),
                "defense_playbook": source.get("defense_playbook", None),
                "threat_level": source.get("threat_level", ""),
                "threat_score": source.get("threat_score", 0),
                "osint": source.get("osint", {})
            }
            logs.append(log)
        
        print(f"✅ Normalized {len(logs)} logs for frontend")
        return logs
    except Exception as e:
        logging.error(f"Elasticsearch search error: {e}")
        import traceback
        print(f"❌ ES Search error traceback: {traceback.format_exc()}")
        return []

def update_attack_patterns(log_data):
    """Update attack pattern statistics"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        payload = log_data.get('payload', '')
        if payload:
            pattern = payload[:50] 
            
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
    """Get logs from Elasticsearch with optional date filtering"""
    limit = request.args.get('limit', 100, type=int)
    log_type = request.args.get('type', 'all')
    date_from = request.args.get('date_from', None)  # Format: YYYY-MM-DD or YYYY-MM-DDTHH:mm:ss
    date_to = request.args.get('date_to', None)  # Format: YYYY-MM-DD or YYYY-MM-DDTHH:mm:ss
    
    print(f"🔄 API /api/logs called with type={log_type}, limit={limit}, date_from={date_from}, date_to={date_to}")
    
    logs = []
    if USE_ELASTICSEARCH:
        logs = es_search_logs(log_type, limit, date_from, date_to)
        print(f"🔍 Retrieved {len(logs)} logs from Elasticsearch")
    else:
        # Fallback: return empty if Elasticsearch not available
        print("⚠️ Elasticsearch not enabled, returning empty logs")
        logs = []
    
    return jsonify({
        'logs': logs,
        'total': len(logs),
        'type': log_type,
        'limit': limit,
        'date_from': date_from,
        'date_to': date_to,
        'timestamp': datetime.now().isoformat()
    })

def es_get_stats(hours=24):
    """Get actionable SOC statistics from Elasticsearch
    
    Returns:
        - high_severity_count: Events with threat_score >= 70
        - unique_attackers: Distinct attacker IPs in time window
        - top_attack_type: Most common attack tool
        - most_targeted_port: Most targeted port
        - total_logs_received: Total logs in ES
    """
    if not es_client:
        return stats
    
    try:
        # Search in all indices
        query_index = f"{ES_PREFIX}-*"
        
        # Calculate time range
        now = datetime.now()
        time_from = (now - timedelta(hours=hours)).isoformat()
        
        # Get total count (all time)
        total_res = es_client.count(index=query_index)
        total_logs = total_res['count']
        
        # Build SOC-focused aggregation query with time filter
        body = {
            "size": 0,
            "query": {
                "range": {
                    "timestamp": {
                        "gte": time_from
                    }
                }
            },
            "aggs": {
                # High severity events (threat_score >= 70 OR threat_level = high/critical)
                "high_severity": {
                    "filter": {
                        "bool": {
                            "should": [
                                {"range": {"threat_score": {"gte": 70}}},
                                {"term": {"threat_level.keyword": "high"}},
                                {"term": {"threat_level.keyword": "critical"}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                },
                # Unique attacker IPs (try src_ip first, fallback to ip)
                "unique_attackers": {
                    "cardinality": {
                        "field": "src_ip.keyword"
                    }
                },
                # Top attack tools
                "top_attack_types": {
                    "terms": {
                        "field": "attack_tool.keyword",
                        "size": 5,
                        "exclude": ["unknown", ""]
                    }
                },
                # Most targeted ports (dst_port)
                "top_targeted_ports": {
                    "terms": {
                        "field": "dst_port",
                        "size": 5
                    }
                },
                # Logs in time window
                "logs_in_period": {
                    "value_count": {
                        "field": "timestamp"
                    }
                }
            }
        }
        
        res = es_client.search(index=query_index, body=body)
        
        # Parse aggregations
        high_severity_count = 0
        unique_attackers = 0
        top_attack_type = "None detected"
        most_targeted_port = 0
        logs_in_period = 0
        
        if 'aggregations' in res:
            aggs = res['aggregations']
            
            # High severity count
            high_severity_count = aggs.get('high_severity', {}).get('doc_count', 0)
            
            # Unique attackers
            unique_attackers = aggs.get('unique_attackers', {}).get('value', 0)
            
            # Top attack type
            attack_buckets = aggs.get('top_attack_types', {}).get('buckets', [])
            if attack_buckets:
                top_attack_type = attack_buckets[0].get('key', 'Unknown')
            
            # Most targeted port
            port_buckets = aggs.get('top_targeted_ports', {}).get('buckets', [])
            if port_buckets:
                most_targeted_port = port_buckets[0].get('key', 0)
            
            # Logs in period
            logs_in_period = aggs.get('logs_in_period', {}).get('value', 0)
        
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
            last_received = latest_res['hits']['hits'][0]['_source'].get('timestamp')
        
        print(f"📊 SOC Stats (last {hours}h) - High severity: {high_severity_count}, Unique attackers: {unique_attackers}, Top tool: {top_attack_type}, Top port: {most_targeted_port}")
        
        return {
            # New SOC-focused stats
            'high_severity_count': high_severity_count,
            'unique_attackers': int(unique_attackers),
            'top_attack_type': top_attack_type,
            'most_targeted_port': int(most_targeted_port),
            'logs_in_period': int(logs_in_period),
            # Keep backwards compatibility
            'total_logs_received': total_logs,
            'last_received': last_received,
            'start_time': stats['start_time'],
            'uptime': (datetime.now() - datetime.fromisoformat(stats['start_time'])).total_seconds(),
            'time_window_hours': hours
        }
    except Exception as e:
        logging.error(f"Elasticsearch stats error: {e}")
        import traceback
        print(f"❌ Stats error traceback: {traceback.format_exc()}")
        return stats

@app.route('/api/stats')
@api_key_required
def get_stats():
    """Get SOC statistics with optional time window"""
    # Get time window from query params (default 24 hours)
    hours = request.args.get('hours', 24, type=int)
    hours = max(1, min(hours, 8760))  # Clamp between 1 hour and 365 days
    
    if USE_ELASTICSEARCH:
        es_stats = es_get_stats(hours=hours)
        print(f"📊 Stats API called - ES (hours={hours}): {es_stats}")
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

@app.route('/api/logs/timeline')
@api_key_required
def get_attack_timeline():
    """Get attack timeline data for charts (last 24 hours by default)"""
    try:
        # Get time range from query params
        hours = int(request.args.get('hours', 24))
        interval = request.args.get('interval', '1h')  # 1h, 30m, 15m, etc.
        
        if not USE_ELASTICSEARCH or not es_client:
            return jsonify({'error': 'Elasticsearch not configured'}), 503
        
        # Calculate time range
        now = datetime.now()
        start_time = (now - timedelta(hours=hours)).isoformat()
        
        # Query ES with date histogram aggregation
        query = {
            "size": 0,
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_time
                    }
                }
            },
            "aggs": {
                "timeline": {
                    "date_histogram": {
                        "field": "timestamp",
                        "fixed_interval": interval,
                        "min_doc_count": 0
                    },
                    "aggs": {
                        "by_tool": {
                            "terms": {
                                "field": "attack_tool.keyword",
                                "size": 10
                            }
                        },
                        "by_severity": {
                            "terms": {
                                "field": "threat_level.keyword",
                                "size": 5
                            }
                        }
                    }
                }
            }
        }
        
        res = es_client.search(index=f"{ES_PREFIX}-*", body=query)
        
        # Parse timeline data
        timeline = []
        if 'aggregations' in res and 'timeline' in res['aggregations']:
            buckets = res['aggregations']['timeline'].get('buckets', [])
            
            for bucket in buckets:
                timestamp = bucket['key_as_string'] if 'key_as_string' in bucket else bucket['key']
                count = bucket['doc_count']
                
                # Get top tools and severities for this time bucket
                tools = {}
                if 'by_tool' in bucket:
                    for tool_bucket in bucket['by_tool'].get('buckets', []):
                        tools[tool_bucket['key']] = tool_bucket['doc_count']
                
                severities = {}
                if 'by_severity' in bucket:
                    for sev_bucket in bucket['by_severity'].get('buckets', []):
                        severities[sev_bucket['key']] = sev_bucket['doc_count']
                
                timeline.append({
                    'timestamp': timestamp,
                    'count': count,
                    'tools': tools,
                    'severities': severities
                })
        
        return jsonify({
            'timeline': timeline,
            'total': res['hits']['total']['value'],
            'time_range': {'start': start_time, 'end': now.isoformat()},
            'interval': interval
        })
        
    except Exception as e:
        logging.error(f"Timeline error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/heatmap')
@api_key_required
def get_endpoint_heatmap():
    """Get attack frequency by endpoint (heatmap data)"""
    try:
        # Get time range from query params
        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 20))
        
        if not USE_ELASTICSEARCH or not es_client:
            return jsonify({'error': 'Elasticsearch not configured'}), 503
        
        # Calculate time range
        now = datetime.now()
        start_time = (now - timedelta(hours=hours)).isoformat()
        
        # Query ES for endpoint aggregation
        query = {
            "size": 0,
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_time
                    }
                }
            },
            "aggs": {
                "endpoints": {
                    "terms": {
                        "field": "path.keyword",
                        "size": limit,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "methods": {
                            "terms": {
                                "field": "method.keyword"
                            }
                        },
                        "threat_levels": {
                            "terms": {
                                "field": "threat_level.keyword"
                            }
                        },
                        "unique_ips": {
                            "cardinality": {
                                "field": "ip.keyword"
                            }
                        }
                    }
                }
            }
        }
        
        res = es_client.search(index=f"{ES_PREFIX}-*", body=query)
        
        # Parse heatmap data
        heatmap = []
        if 'aggregations' in res and 'endpoints' in res['aggregations']:
            buckets = res['aggregations']['endpoints'].get('buckets', [])
            
            for bucket in buckets:
                endpoint = bucket['key']
                count = bucket['doc_count']
                
                # Get methods distribution
                methods = {}
                if 'methods' in bucket:
                    for method_bucket in bucket['methods'].get('buckets', []):
                        methods[method_bucket['key']] = method_bucket['doc_count']
                
                # Get threat levels
                threat_levels = {}
                if 'threat_levels' in bucket:
                    for threat_bucket in bucket['threat_levels'].get('buckets', []):
                        threat_levels[threat_bucket['key']] = threat_bucket['doc_count']
                
                # Get unique IPs
                unique_ips = bucket.get('unique_ips', {}).get('value', 0)
                
                heatmap.append({
                    'endpoint': endpoint,
                    'count': count,
                    'unique_ips': unique_ips,
                    'methods': methods,
                    'threat_levels': threat_levels
                })
        
        return jsonify({
            'heatmap': heatmap,
            'total_endpoints': len(heatmap),
            'time_range': {'start': start_time, 'end': now.isoformat()}
        })
        
    except Exception as e:
        logging.error(f"Heatmap error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/attackers')
@api_key_required
def get_attackers():
    """Get unique attacker IPs aggregated from Elasticsearch with metadata"""
    try:
        # Get query parameters
        limit = int(request.args.get('limit', 50))
        page = int(request.args.get('page', 1))
        sort_by = request.args.get('sort_by', 'total_attacks')  # total_attacks, threat_score, last_seen
        sort_order = request.args.get('order', 'desc')  # asc or desc
        
        if not USE_ELASTICSEARCH or not es_client:
            return jsonify({'error': 'Elasticsearch not configured'}), 503
        
        print(f"🔍 Attackers endpoint called: limit={limit}, page={page}, sort_by={sort_by}")

        # Base query structure
        query = {
            "size": 0,
            "aggs": {
                "unique_ips": {
                    "terms": {
                        "field": "ip.keyword",  # Placeholder, will be replaced in loop
                        "size": 500,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "first_seen": {"min": {"field": "timestamp"}},
                        "last_seen": {"max": {"field": "timestamp"}},
                        "avg_threat_score": {"avg": {"field": "threat_score"}},
                        "max_threat_score": {"max": {"field": "threat_score"}},
                        # GeoIP data (mapped as keyword type, no .keyword suffix needed)
                        "country": {"terms": {"field": "geoip.country", "size": 1, "missing": "Unknown"}},
                        "city": {"terms": {"field": "geoip.city", "size": 1, "missing": "Unknown"}},
                        "isp": {"terms": {"field": "geoip.isp", "size": 1, "missing": "Unknown"}},
                        "attack_tools": {"terms": {"field": "attack_tool.keyword", "size": 5}}
                    }
                }
            }
        }

        try:
            debug_res = es_client.search(
                index=f"{ES_PREFIX}-*", 
                body={"size": 1, "sort": [{"timestamp": {"order": "desc"}}]}
            )
            if debug_res['hits']['hits']:
                source = debug_res['hits']['hits'][0]['_source']
                print(f"🕵️ DEBUG: Sample document keys: {list(source.keys())}")
                if 'ip' in source: print(f"   -> Found 'ip': {source['ip']}")
                if 'src_ip' in source: print(f"   -> Found 'src_ip': {source['src_ip']}")
        except Exception as e:
            print(f"⚠️ Debug query failed: {e}")

        candidates = ["ip.keyword", "src_ip.keyword", "ip", "src_ip"]
        
        res = {}
        for field in candidates:
            print(f"🔄 Trying aggregation on field: {field}")
            query["aggs"]["unique_ips"]["terms"]["field"] = field
            try:
                res = es_client.search(index=f"{ES_PREFIX}-*", body=query)
                
                # Check if we got buckets
                if 'aggregations' in res and 'unique_ips' in res['aggregations']:
                    buckets = res['aggregations']['unique_ips'].get('buckets', [])
                    if len(buckets) > 0:
                        print(f"✅ Success with field: {field} - Found {len(buckets)} buckets")
                        break
                    else:
                        print(f"⚠️ No buckets with field: {field}")
                else:
                    print(f"⚠️ No 'unique_ips' aggregation in response for {field}")
                    
            except Exception as e:
                print(f"❌ Query failed for field {field}: {e}")

        attackers = []
        if 'aggregations' in res and 'unique_ips' in res['aggregations']:
            buckets = res['aggregations']['unique_ips'].get('buckets', [])
            print(f"📊 Found {len(buckets)} unique IPs in aggregation")
            
            for bucket in buckets:
                ip = bucket['key']
                total_attacks = bucket['doc_count']
                
                first_seen = bucket.get('first_seen', {}).get('value_as_string', '')
                last_seen = bucket.get('last_seen', {}).get('value_as_string', '')
                avg_threat = bucket.get('avg_threat_score', {}).get('value', 0)
                max_threat = bucket.get('max_threat_score', {}).get('value', 0)
                
                # Check for missing values in buckets
                country_buckets = bucket.get('country', {}).get('buckets', [])
                country = country_buckets[0]['key'] if country_buckets and len(country_buckets) > 0 else 'Unknown'
                
                city_buckets = bucket.get('city', {}).get('buckets', [])
                city = city_buckets[0]['key'] if city_buckets and len(city_buckets) > 0 else 'Unknown'
                
                isp_buckets = bucket.get('isp', {}).get('buckets', [])
                isp = isp_buckets[0]['key'] if isp_buckets and len(isp_buckets) > 0 else 'Unknown'
                
                tool_buckets = bucket.get('attack_tools', {}).get('buckets', [])
                tools = [t['key'] for t in tool_buckets if t['key'] != 'unknown']
                
                attackers.append({
                    'ip': ip,
                    'total_attacks': total_attacks,
                    'first_seen': first_seen,
                    'last_seen': last_seen,
                    'avg_threat_score': round(avg_threat, 2) if avg_threat else 0,
                    'max_threat_score': int(max_threat) if max_threat else 0,
                    'country': country,
                    'city': city,
                    'isp': isp,
                    'attack_tools': tools
                })
        else:
            print(f"⚠️ No aggregations found in response: {list(res.keys())}")
        
        # Sort
        if sort_by == 'total_attacks':
            attackers.sort(key=lambda x: x['total_attacks'], reverse=(sort_order == 'desc'))
        elif sort_by == 'threat_score':
            attackers.sort(key=lambda x: x['max_threat_score'], reverse=(sort_order == 'desc'))
        elif sort_by == 'last_seen':
            attackers.sort(key=lambda x: x['last_seen'], reverse=(sort_order == 'desc'))
        elif sort_by == 'first_seen':
            attackers.sort(key=lambda x: x['first_seen'], reverse=(sort_order == 'desc'))
        
        # Pagination
        total_attackers = len(attackers)
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_attackers = attackers[start_idx:end_idx]
        
        print(f"✅ Returning {len(paginated_attackers)} attackers out of {total_attackers} total")
        
        return jsonify({
            'attackers': paginated_attackers,
            'total': total_attackers,
            'page': page,
            'limit': limit,
            'total_pages': (total_attackers + limit - 1) // limit,
            'sort_by': sort_by,
            'sort_order': sort_order,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Attackers endpoint error: {e}")
        import traceback
        print(f"❌ Attackers error: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/recon/start', methods=['POST'])
@api_key_required
def start_reconnaissance():
    """Start black box reconnaissance on a target IP"""
    print("🔫 Recon endpoint called")
    try:
        data = request.get_json()
        print(f"🔫 Recon data received: {data}")
        target_ip = data.get('target_ip')
        scan_types = data.get('scan_types', ['nmap', 'amass', 'subfinder', 'bbot'])
        
        if not target_ip:
            return jsonify({'error': 'target_ip is required'}), 400
        
        # Validate IP format (basic validation)
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, target_ip):
            return jsonify({'error': 'Invalid IP address format'}), 400
        
        # Create and start recon job
        recon_id = create_recon_job(target_ip, scan_types, es_client)
        
        logging.info(f"Started reconnaissance job {recon_id} for {target_ip}")
        
        return jsonify({
            'recon_id': recon_id,
            'status': 'queued',
            'target_ip': target_ip,
            'scan_types': scan_types,
            'message': 'Reconnaissance job started'
        })
    
    except Exception as e:
        import traceback
        print(f"❌ Recon start error: {traceback.format_exc()}")
        logging.error(f"Error starting reconnaissance: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/recon/stats')
@api_key_required
def get_recon_stats():
    """Get recon job statistics from Elasticsearch"""
    try:
        # Also count active jobs from memory (not yet saved to ES)
        active_in_memory = len([
            job for job in active_recon_jobs.values()
            if job.results.get('status') in ('running', 'pending', 'queued')
        ])
        
        if not USE_ELASTICSEARCH or not es_client:
            # Fallback to memory-only stats
            completed_in_memory = len([
                job for job in active_recon_jobs.values()
                if job.results.get('status') == 'completed'
            ])
            return jsonify({
                'active': active_in_memory,
                'completed': completed_in_memory,
                'failed': 0,
                'total': active_in_memory + completed_in_memory
            })
        
        # Query recon-results-* index for persisted stats
        try:
            query = {
                "size": 0,
                "aggs": {
                    "by_status": {
                        "terms": {"field": "status.keyword", "size": 10}
                    },
                    "total_recons": {
                        "value_count": {"field": "recon_id.keyword"}
                    }
                }
            }
            res = es_client.search(index="recon-results-*", body=query, ignore_unavailable=True)
            
            # Parse results
            stats = {'running': 0, 'pending': 0, 'queued': 0, 'completed': 0, 'error': 0}
            if 'aggregations' in res and 'by_status' in res['aggregations']:
                for bucket in res['aggregations']['by_status'].get('buckets', []):
                    stats[bucket['key']] = bucket['doc_count']
            
            total = res['aggregations'].get('total_recons', {}).get('value', 0) if 'aggregations' in res else 0
            
            return jsonify({
                'active': active_in_memory + stats.get('running', 0) + stats.get('pending', 0) + stats.get('queued', 0),
                'completed': stats.get('completed', 0),
                'failed': stats.get('error', 0),
                'total': int(total)
            })
            
        except Exception as es_error:
            logging.warning(f"Recon stats ES query failed: {es_error}")
            # Fallback to memory
            return jsonify({
                'active': active_in_memory,
                'completed': 0,
                'failed': 0,
                'total': active_in_memory
            })
    
    except Exception as e:
        logging.error(f"Error getting recon stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recon/status/<recon_id>')
@api_key_required
def get_reconnaissance_status(recon_id):
    """Get status of a reconnaissance job"""
    try:
        status = get_recon_status(recon_id)
        
        if not status:
            return jsonify({'error': 'Reconnaissance job not found'}), 404
        
        return jsonify(status)
    
    except Exception as e:
        logging.error(f"Error getting recon status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recon/results/<recon_id>')
@api_key_required
def get_reconnaissance_results(recon_id):
    """Get full results of a reconnaissance job"""
    try:
        results = get_recon_results(recon_id)
        
        if not results:
            return jsonify({'error': 'Reconnaissance job not found'}), 404
        
        return jsonify(results)
    
    except Exception as e:
        logging.error(f"Error getting recon results: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recon/report/<recon_id>/download')
@api_key_required
def download_reconnaissance_report(recon_id):
    """Download reconnaissance report in DOCX or PDF format"""
    try:
        from flask import send_file
        from report_generator import generate_report
        
        # Get format from query param (default: docx)
        report_format = request.args.get('format', 'docx').lower()
        
        if report_format not in ['docx', 'pdf']:
            return jsonify({'error': 'Invalid format. Use docx or pdf'}), 400
        
        # Get recon results
        results = get_recon_results(recon_id)
        
        if not results:
            return jsonify({'error': 'Reconnaissance job not found'}), 404
        
        # Check if scan is complete
        if results.get('status') != 'completed':
            return jsonify({'error': 'Reconnaissance scan not yet completed'}), 400
        
        # Generate report
        report_path = generate_report(results, report_format)
        
        # Determine MIME type
        mime_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' if report_format == 'docx' else 'application/pdf'
        
        # Send file
        return send_file(
            report_path,
            mimetype=mime_type,
            as_attachment=True,
            download_name=os.path.basename(report_path)
        )
    
    except Exception as e:
        logging.error(f"Error downloading report: {e}")
        import traceback
        print(f"❌ Report download error: {traceback.format_exc()}")
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