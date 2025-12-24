"""
Logs Routes - Log retrieval, search, export, and receiving
All data from Elasticsearch only
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
import json
import logging

logs_bp = Blueprint('logs', __name__, url_prefix='/api')


def get_es_client():
    """Get Elasticsearch client from app context"""
    return current_app.config.get('es_client')


def get_es_prefix():
    """Get Elasticsearch index prefix"""
    return current_app.config.get('ES_PREFIX', 'sensor-logs')


def use_elasticsearch():
    """Check if Elasticsearch is enabled"""
    return current_app.config.get('USE_ELASTICSEARCH', False)


def get_log_queue():
    """Get log queue from app context"""
    return current_app.config.get('log_queue')


def es_search_logs(log_type, limit, date_from=None, date_to=None):
    """Search logs from Elasticsearch with date filtering"""
    es_client = get_es_client()
    ES_PREFIX = get_es_prefix()
    
    if not es_client:
        return []
    
    try:
        query_index = f"{ES_PREFIX}-*"
        
        # Build query with date filtering
        must_clauses = []
        
        if date_from or date_to:
            date_range = {}
            if date_from:
                date_range["gte"] = date_from
            if date_to:
                date_range["lte"] = date_to
            must_clauses.append({"range": {"timestamp": date_range}})
        
        # Filter by log type if not 'all'
        if log_type != 'all':
            must_clauses.append({"term": {"log_type": log_type}})
        
        body = {
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": min(limit, 500)
        }
        
        if must_clauses:
            body["query"] = {"bool": {"must": must_clauses}}
        
        res = es_client.search(index=query_index, body=body)
        
        logs = []
        for hit in res['hits']['hits']:
            log = hit['_source']
            log['_id'] = hit['_id']
            logs.append(log)
        
        return logs
        
    except Exception as e:
        logging.error(f"ES search error: {e}")
        return []


@logs_bp.route('/logs')
def get_logs():
    """Get logs from Elasticsearch with optional date filtering"""
    limit = request.args.get('limit', 100, type=int)
    log_type = request.args.get('type', 'all')
    date_from = request.args.get('date_from', None)
    date_to = request.args.get('date_to', None)
    
    logs = []
    if use_elasticsearch():
        logs = es_search_logs(log_type, limit, date_from, date_to)
    
    return jsonify({
        'logs': logs,
        'total': len(logs),
        'type': log_type,
        'limit': limit,
        'date_from': date_from,
        'date_to': date_to,
        'timestamp': datetime.now().isoformat()
    })


@logs_bp.route('/logs/search')
def search_logs():
    """Search logs by criteria using Elasticsearch"""
    query_str = request.args.get('q', '')
    log_type = request.args.get('type', 'all')
    limit = request.args.get('limit', 100, type=int)
    
    es_client = get_es_client()
    ES_PREFIX = get_es_prefix()
    
    if not use_elasticsearch() or not es_client:
        return jsonify({'error': 'Elasticsearch not configured'}), 503
    
    try:
        must_clauses = []
        
        if query_str:
            # Multi-field search
            must_clauses.append({
                "multi_match": {
                    "query": query_str,
                    "fields": ["payload", "src_ip", "path", "user_agent", "attack_tool"],
                    "type": "phrase_prefix"
                }
            })
        
        if log_type != 'all':
            must_clauses.append({"term": {"log_type": log_type}})
        
        body = {
            "size": min(limit, 500),
            "sort": [{"timestamp": {"order": "desc"}}]
        }
        
        if must_clauses:
            body["query"] = {"bool": {"must": must_clauses}}
        
        res = es_client.search(index=f"{ES_PREFIX}-*", body=body)
        
        logs = []
        for hit in res['hits']['hits']:
            src = hit['_source']
            logs.append({
                '_id': hit['_id'],
                'timestamp': src.get('timestamp'),
                'type': src.get('log_type', src.get('type', '')),
                'src_ip': src.get('src_ip', src.get('ip', '')),
                'dst_ip': src.get('dst_ip', ''),
                'port': src.get('dst_port', src.get('port', 0)),
                'path': src.get('path', ''),
                'attack_tool': src.get('attack_tool', '')
            })
        
        return jsonify({
            'logs': logs,
            'total': res['hits']['total']['value'],
            'query': query_str,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Search error: {e}")
        return jsonify({'error': str(e)}), 500


@logs_bp.route('/logs/export')
def export_logs():
    """Export logs to JSON from Elasticsearch"""
    log_type = request.args.get('type', 'all')
    limit = request.args.get('limit', 1000, type=int)
    
    es_client = get_es_client()
    ES_PREFIX = get_es_prefix()
    
    if not use_elasticsearch() or not es_client:
        return jsonify({'error': 'Elasticsearch not configured'}), 503
    
    try:
        must_clauses = []
        
        if log_type != 'all':
            must_clauses.append({"term": {"log_type": log_type}})
        
        body = {
            "size": min(limit, 10000),
            "sort": [{"timestamp": {"order": "desc"}}]
        }
        
        if must_clauses:
            body["query"] = {"bool": {"must": must_clauses}}
        
        res = es_client.search(index=f"{ES_PREFIX}-*", body=body)
        
        logs = []
        for hit in res['hits']['hits']:
            log = hit['_source']
            log['_id'] = hit['_id']
            logs.append(log)
        
        return jsonify({
            'logs': logs,
            'total': len(logs),
            'exported_at': datetime.now().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Export error: {e}")
        return jsonify({'error': str(e)}), 500


# Log receiving endpoints
@logs_bp.route('/logs/receive', methods=['POST'])
def receive_log():
    """Receive log from honeypot server"""
    try:
        log_data = request.get_json()
        if not log_data:
            return jsonify({'error': 'No data received'}), 400
        
        if 'timestamp' not in log_data:
            log_data['timestamp'] = datetime.now().isoformat()
        
        q = get_log_queue()
        if q:
            q.put(log_data)
        
        return jsonify({
            'status': 'success',
            'message': 'Log received',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@logs_bp.route('/logs/bulk', methods=['POST'])
def receive_bulk_logs():
    """Receive multiple logs from honeypot server"""
    try:
        data = request.get_json()
        logs = data.get('logs', [])
        
        if not logs:
            return jsonify({'error': 'No logs received'}), 400
        
        q = get_log_queue()
        if q:
            for log_data in logs:
                if 'timestamp' not in log_data:
                    log_data['timestamp'] = datetime.now().isoformat()
                q.put(log_data)
        
        return jsonify({
            'status': 'success',
            'message': f'{len(logs)} logs received',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
