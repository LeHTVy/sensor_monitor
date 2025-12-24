"""
Statistics Routes - Health, Stats, Timeline, Heatmap, Attack Patterns
All data from Elasticsearch only
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timedelta
import logging

stats_bp = Blueprint('stats', __name__, url_prefix='/api')


def get_es_client():
    """Get Elasticsearch client from app context"""
    return current_app.config.get('es_client')


def get_es_prefix():
    """Get Elasticsearch index prefix"""
    return current_app.config.get('ES_PREFIX', 'sensor-logs')


def use_elasticsearch():
    """Check if Elasticsearch is enabled"""
    return current_app.config.get('USE_ELASTICSEARCH', False)


def get_stats():
    """Get stats dict from app context"""
    return current_app.config.get('stats', {})


@stats_bp.route('/health')
def health():
    """Health check endpoint"""
    app_stats = get_stats()
    if app_stats.get('start_time'):
        app_stats['uptime'] = (datetime.now() - datetime.fromisoformat(app_stats['start_time'])).total_seconds()
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'stats': app_stats
    })


@stats_bp.route('/stats')
def api_stats():
    """Get SOC statistics with optional time window"""
    hours = request.args.get('hours', 24, type=int)
    
    if not use_elasticsearch():
        return jsonify({
            'error': 'Elasticsearch not configured',
            'stats': get_stats()
        }), 503
    
    try:
        es_stats = es_get_stats(hours)
        return jsonify(es_stats)
    except Exception as e:
        logging.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e), 'stats': get_stats()}), 500


def es_get_stats(hours=24):
    """Get actionable SOC statistics from Elasticsearch"""
    es_client = get_es_client()
    ES_PREFIX = get_es_prefix()
    stats = get_stats()
    
    if not es_client:
        return stats
    
    try:
        query_index = f"{ES_PREFIX}-*"
        now = datetime.now()
        time_from = (now - timedelta(hours=hours)).isoformat()
        
        total_res = es_client.count(index=query_index)
        total_logs = total_res['count']
        
        body = {
            "size": 0,
            "query": {
                "range": {
                    "timestamp": {"gte": time_from}
                }
            },
            "aggs": {
                "high_severity": {
                    "filter": {
                        "bool": {
                            "should": [
                                {"range": {"threat_score": {"gte": 40}}},
                                {"wildcard": {"threat_level": "*critical*"}},
                                {"wildcard": {"threat_level": "*high*"}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                },
                "unique_attackers": {
                    "cardinality": {"field": "src_ip"}
                },
                "top_attack_types": {
                    "terms": {
                        "field": "attack_tool",
                        "size": 5,
                        "exclude": ["unknown", ""]
                    }
                },
                "top_targeted_ports": {
                    "terms": {"field": "dst_port", "size": 5}
                },
                "logs_in_period": {
                    "value_count": {"field": "timestamp"}
                }
            }
        }
        
        res = es_client.search(index=query_index, body=body)
        
        high_severity_count = 0
        unique_attackers = 0
        top_attack_type = "None detected"
        most_targeted_port = 0
        logs_in_period = 0
        
        if 'aggregations' in res:
            aggs = res['aggregations']
            high_severity_count = aggs.get('high_severity', {}).get('doc_count', 0)
            unique_attackers = aggs.get('unique_attackers', {}).get('value', 0)
            
            top_tools = aggs.get('top_attack_types', {}).get('buckets', [])
            if top_tools:
                top_attack_type = top_tools[0]['key']
            
            top_ports = aggs.get('top_targeted_ports', {}).get('buckets', [])
            if top_ports:
                most_targeted_port = top_ports[0]['key']
            
            logs_in_period = int(aggs.get('logs_in_period', {}).get('value', 0))
        
        return {
            'high_severity_count': high_severity_count,
            'unique_attackers': unique_attackers,
            'top_attack_type': top_attack_type,
            'most_targeted_port': most_targeted_port,
            'total_logs_received': total_logs,
            'logs_in_time_window': logs_in_period,
            'time_window_hours': hours,
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logging.error(f"ES stats error: {e}")
        return stats


@stats_bp.route('/attack-patterns')
def get_attack_patterns():
    """Get attack patterns from Elasticsearch aggregation"""
    es_client = get_es_client()
    ES_PREFIX = get_es_prefix()
    hours = request.args.get('hours', 168, type=int)  # Default 7 days
    
    if not use_elasticsearch() or not es_client:
        return jsonify({'error': 'Elasticsearch not configured'}), 503
    
    try:
        time_from = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        query = {
            "size": 0,
            "query": {
                "range": {"timestamp": {"gte": time_from}}
            },
            "aggs": {
                "attack_patterns": {
                    "terms": {
                        "field": "attack_tool",
                        "size": 50,
                        "exclude": ["unknown", ""]
                    },
                    "aggs": {
                        "first_seen": {"min": {"field": "timestamp"}},
                        "last_seen": {"max": {"field": "timestamp"}}
                    }
                }
            }
        }
        
        res = es_client.search(index=f"{ES_PREFIX}-*", body=query)
        
        patterns = []
        if 'aggregations' in res and 'attack_patterns' in res['aggregations']:
            for bucket in res['aggregations']['attack_patterns'].get('buckets', []):
                patterns.append({
                    'pattern': bucket['key'],
                    'count': bucket['doc_count'],
                    'first_seen': bucket.get('first_seen', {}).get('value_as_string', ''),
                    'last_seen': bucket.get('last_seen', {}).get('value_as_string', '')
                })
        
        return jsonify({
            'patterns': patterns,
            'time_window_hours': hours,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Attack patterns error: {e}")
        return jsonify({'error': str(e)}), 500


@stats_bp.route('/logs/timeline')
def get_attack_timeline():
    """Get attack timeline data for charts (last 24 hours by default)"""
    try:
        hours = int(request.args.get('hours', 24))
        interval = request.args.get('interval', '1h')
        
        es_client = get_es_client()
        ES_PREFIX = get_es_prefix()
        
        if not use_elasticsearch() or not es_client:
            return jsonify({'error': 'Elasticsearch not configured'}), 503
        
        now = datetime.now()
        start_time = (now - timedelta(hours=hours)).isoformat()
        
        query = {
            "size": 0,
            "query": {
                "range": {"timestamp": {"gte": start_time}}
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
                            "terms": {"field": "attack_tool.keyword", "size": 10}
                        },
                        "by_severity": {
                            "terms": {"field": "threat_level.keyword", "size": 5}
                        }
                    }
                }
            }
        }
        
        res = es_client.search(index=f"{ES_PREFIX}-*", body=query)
        
        timeline = []
        if 'aggregations' in res and 'timeline' in res['aggregations']:
            buckets = res['aggregations']['timeline'].get('buckets', [])
            
            for bucket in buckets:
                timestamp = bucket.get('key_as_string', bucket['key'])
                count = bucket['doc_count']
                
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


@stats_bp.route('/logs/heatmap')
def get_endpoint_heatmap():
    """Get attack frequency by endpoint (heatmap data)"""
    try:
        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 20))
        
        es_client = get_es_client()
        ES_PREFIX = get_es_prefix()
        
        if not use_elasticsearch() or not es_client:
            return jsonify({'error': 'Elasticsearch not configured'}), 503
        
        now = datetime.now()
        start_time = (now - timedelta(hours=hours)).isoformat()
        
        query = {
            "size": 0,
            "query": {
                "range": {"timestamp": {"gte": start_time}}
            },
            "aggs": {
                "by_endpoint": {
                    "terms": {"field": "path.keyword", "size": limit}
                },
                "by_method": {
                    "terms": {"field": "method.keyword", "size": 10}
                },
                "by_status": {
                    "terms": {"field": "status_code", "size": 10}
                }
            }
        }
        
        res = es_client.search(index=f"{ES_PREFIX}-*", body=query)
        
        endpoints = []
        methods = []
        statuses = []
        
        if 'aggregations' in res:
            aggs = res['aggregations']
            
            for bucket in aggs.get('by_endpoint', {}).get('buckets', []):
                endpoints.append({'path': bucket['key'], 'count': bucket['doc_count']})
            
            for bucket in aggs.get('by_method', {}).get('buckets', []):
                methods.append({'method': bucket['key'], 'count': bucket['doc_count']})
            
            for bucket in aggs.get('by_status', {}).get('buckets', []):
                statuses.append({'status': bucket['key'], 'count': bucket['doc_count']})
        
        return jsonify({
            'endpoints': endpoints,
            'methods': methods,
            'statuses': statuses,
            'time_range': {'start': start_time, 'end': now.isoformat()},
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Heatmap error: {e}")
        return jsonify({'error': str(e)}), 500
