#!/usr/bin/env python3
"""
Log Receiver and Web Interface for Capture Server
Main Flask application that registers route blueprints

Primary data store: Elasticsearch
System logs: File-based logging (logs/receiver.log)
"""

from flask import Flask, jsonify
import json
import os
from datetime import datetime, timedelta
import threading
import queue
import time
import logging
from logging.handlers import RotatingFileHandler
from collections import defaultdict, deque
import hashlib
from core.kafka_consumer import CaptureKafkaConsumer
from core.security_middleware import CaptureSecurity, admin_required, api_key_required, ip_whitelist_required
from elasticsearch import Elasticsearch
from recon.recon_service import create_recon_job, get_recon_status, get_recon_results, active_recon_jobs

# Create Flask app
app = Flask(__name__)

# Initialize security middleware
security = CaptureSecurity(app)
app.security = security

# Global variables for logging and statistics
log_queue = queue.Queue()
kafka_consumer = CaptureKafkaConsumer()

# Elasticsearch configuration
USE_ELASTICSEARCH = os.getenv('USE_ELASTICSEARCH', 'false').lower() == 'true'
ES_URL = os.getenv('ELASTICSEARCH_URL', 'http://elasticsearch:9200')
ES_PREFIX = os.getenv('ES_INDEX_PREFIX', 'sensor-logs')
es_client = Elasticsearch(ES_URL) if USE_ELASTICSEARCH else None

# Store config in app for blueprints to access
app.config['es_client'] = es_client
app.config['ES_PREFIX'] = ES_PREFIX
app.config['USE_ELASTICSEARCH'] = USE_ELASTICSEARCH
app.config['log_queue'] = log_queue

stats = {
    'total_logs_received': 0,
    'attack_logs': 0,
    'honeypot_logs': 0,
    'error_logs': 0,
    'high_threat_count': 0,
    'last_received': None,
    'start_time': datetime.now().isoformat(),
    'uptime': 0
}
app.config['stats'] = stats

# Recent logs storage (in-memory cache)
recent_logs = deque(maxlen=1000)
attack_logs = deque(maxlen=500)
honeypot_logs = deque(maxlen=500)


def setup_logging():
    """
    Setup comprehensive file-based logging for system monitoring:
    - receiver.log: General system events and threat processing
    - security.log: Authentication and API key events (audit trail)
    """
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    
    # Format with timestamp, level, and structured message
    log_format = '%(asctime)s | %(levelname)-8s | %(name)-12s | %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    # Main receiver logger with rotation (max 10MB, keep 5 backups)
    main_handler = RotatingFileHandler(
        f'{log_dir}/receiver.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    main_handler.setFormatter(logging.Formatter(log_format, date_format))
    
    # Security logger for auth/API key events (separate file for audit)
    security_handler = RotatingFileHandler(
        f'{log_dir}/security.log',
        maxBytes=10*1024*1024,
        backupCount=10  # Keep more backups for security audit
    )
    security_handler.setFormatter(logging.Formatter(log_format, date_format))
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    security_logger.addHandler(security_handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        handlers=[main_handler, console_handler]
    )
    
    # Log startup info
    logging.info("=" * 60)
    logging.info("[SERVER] Capture Server Starting")
    logging.info(f"[SERVER] Elasticsearch: {'ENABLED' if USE_ELASTICSEARCH else 'DISABLED'}")
    logging.info(f"[SERVER] ES URL: {ES_URL if USE_ELASTICSEARCH else 'N/A'}")
    logging.info(f"[SERVER] ES Index Prefix: {ES_PREFIX}")
    logging.info("=" * 60)
    
    security_logger.info("=" * 60)
    security_logger.info("[STARTUP] Security logging initialized")
    security_logger.info("=" * 60)


def log_server_event(event_type: str, details: str = None):
    """Log server state events"""
    log_entry = f"[SERVER] {event_type}"
    if details:
        log_entry += f" | {details}"
    logging.info(log_entry)


def log_threat_event(src_ip: str, threat_score: int, attack_tool: str = None):
    """Log high-priority threat events"""
    security_logger = logging.getLogger('security')
    log_entry = f"[THREAT] HIGH PRIORITY | IP: {src_ip} | Score: {threat_score}"
    if attack_tool:
        log_entry += f" | Tool: {attack_tool}"
    security_logger.warning(log_entry)


def process_log_queue():
    """Process logs from queue - update in-memory stats and log significant events"""
    while True:
        try:
            log_data = log_queue.get(timeout=1)
            
            # Update statistics
            stats['total_logs_received'] += 1
            stats['last_received'] = datetime.now().isoformat()
            
            log_type = log_data.get('type', 'unknown')
            if log_type == 'attack' or 'attack' in str(log_type):
                stats['attack_logs'] += 1
                attack_logs.appendleft(log_data)
            elif log_type == 'honeypot':
                stats['honeypot_logs'] += 1
                honeypot_logs.appendleft(log_data)
            else:
                stats['error_logs'] += 1
            
            recent_logs.appendleft(log_data)
            
            # Log high-priority threats to security log
            threat_score = log_data.get('threat_score', 0)
            if threat_score >= 70:
                stats['high_threat_count'] += 1
                log_threat_event(
                    src_ip=log_data.get('src_ip', log_data.get('ip', 'unknown')),
                    threat_score=threat_score,
                    attack_tool=log_data.get('attack_tool')
                )
            
            # Log every 100 logs for monitoring throughput
            if stats['total_logs_received'] % 100 == 0:
                log_server_event("THROUGHPUT", f"Processed {stats['total_logs_received']} logs, {stats['attack_logs']} attacks")
            
        except queue.Empty:
            continue
        except Exception as e:
            logging.error(f"[ERROR] Log processing failed: {e}")


# =============================================================================
# REGISTER BLUEPRINTS
# =============================================================================

log_server_event("INIT", "Registering route blueprints")

try:
    from routes.auth import auth_bp
    app.register_blueprint(auth_bp)
    log_server_event("BLUEPRINT", "auth - OK")
except ImportError as e:
    logging.warning(f"[BLUEPRINT] auth - FAILED: {e}")

try:
    from routes.stats import stats_bp
    app.register_blueprint(stats_bp)
    log_server_event("BLUEPRINT", "stats - OK")
except ImportError as e:
    logging.warning(f"[BLUEPRINT] stats - FAILED: {e}")

try:
    from routes.logs import logs_bp
    app.register_blueprint(logs_bp)
    log_server_event("BLUEPRINT", "logs - OK")
except ImportError as e:
    logging.warning(f"[BLUEPRINT] logs - FAILED: {e}")

try:
    from routes.attackers import attackers_bp
    app.register_blueprint(attackers_bp)
    log_server_event("BLUEPRINT", "attackers - OK")
except ImportError as e:
    logging.warning(f"[BLUEPRINT] attackers - FAILED: {e}")

try:
    from routes.stix import stix_bp
    app.register_blueprint(stix_bp)
    log_server_event("BLUEPRINT", "stix - OK")
except ImportError as e:
    logging.warning(f"[BLUEPRINT] stix - FAILED: {e}")


# =============================================================================
# ROOT ROUTES (kept in main file)
# =============================================================================

@app.route('/')
def index():
    """Health landing - API only server"""
    return jsonify({
        'service': 'capture-server',
        'message': 'API service. Use frontend at port 3000.',
        'docs': '/api/health'
    })


@app.route('/api/test', methods=['GET'])
def test_endpoint():
    """Test endpoint without authentication"""
    return jsonify({
        'message': 'Test endpoint working',
        'timestamp': datetime.now().isoformat(),
        'kafka_connected': kafka_consumer is not None
    })


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    # Setup logging first
    setup_logging()
    
    log_server_event("STARTUP", "Initializing components")
    
    # Start log processing thread
    log_thread = threading.Thread(target=process_log_queue)
    log_thread.daemon = True
    log_thread.start()
    log_server_event("THREAD", "Log processor started")
    
    # Start Kafka consumer in background thread
    kafka_thread = threading.Thread(target=kafka_consumer.start_consuming, daemon=True)
    kafka_thread.start()
    log_server_event("KAFKA", "Consumer thread started")
    
    log_server_event("READY", f"Server listening on 0.0.0.0:8080")
    
    app.run(host='0.0.0.0', port=8080, debug=True)