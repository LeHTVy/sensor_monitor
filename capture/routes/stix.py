"""
STIX 2.1 Threat Intelligence Routes
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timedelta
import json
import logging

stix_bp = Blueprint('stix', __name__, url_prefix='/api/v1')


def get_es_client():
    """Get Elasticsearch client from app context"""
    return current_app.config.get('es_client')


def get_es_prefix():
    """Get Elasticsearch index prefix"""
    return current_app.config.get('ES_PREFIX', 'sensor-logs')


def use_elasticsearch():
    """Check if Elasticsearch is enabled"""
    return current_app.config.get('USE_ELASTICSEARCH', False)


def is_stix_available():
    """Check if STIX formatter is available"""
    try:
        from services.stix_formatter import get_stix_formatter
        return True
    except ImportError:
        return False


def get_stix_formatter():
    """Get STIX formatter if available"""
    from services.stix_formatter import get_stix_formatter as _get_formatter
    return _get_formatter()


@stix_bp.route('/threats/latest')
def get_latest_threats():
    """
    Get latest threat indicators in simple JSON format
    
    Query params:
        - limit: Number of results (default 50, max 200)
        - hours: Time window in hours (default 24)
        - tool: Filter by attack tool (optional)
    """
    limit = min(request.args.get('limit', 50, type=int), 200)
    hours = request.args.get('hours', 24, type=int)
    tool_filter = request.args.get('tool', None)
    
    es_client = get_es_client()
    ES_PREFIX = get_es_prefix()
    
    if not use_elasticsearch() or not es_client:
        return jsonify({'error': 'Elasticsearch not available'}), 503
    
    try:
        time_from = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        must = [{"range": {"timestamp": {"gte": time_from}}}]
        if tool_filter:
            must.append({"term": {"attack_tool": tool_filter}})
        
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": must}},
            "_source": ["src_ip", "attack_tool", "threat_score", "threat_level", 
                       "timestamp", "geoip", "attack_techniques", "method", "path"]
        }
        
        res = es_client.search(index=f"{ES_PREFIX}-*", body=query)
        
        # Aggregate by IP (deduplicate)
        ip_threats = {}
        for hit in res['hits']['hits']:
            src = hit['_source']
            ip = src.get('src_ip', src.get('ip', 'unknown'))
            
            if ip not in ip_threats:
                geoip = src.get('geoip', {}) if isinstance(src.get('geoip'), dict) else {}
                ip_threats[ip] = {
                    'ip': ip,
                    'attack_tool': src.get('attack_tool', 'unknown'),
                    'threat_score': src.get('threat_score', 0),
                    'threat_level': src.get('threat_level', 'unknown'),
                    'first_seen': src.get('timestamp'),
                    'last_seen': src.get('timestamp'),
                    'country': geoip.get('country', 'Unknown'),
                    'city': geoip.get('city', ''),
                    'isp': geoip.get('isp', ''),
                    'techniques': src.get('attack_techniques', []),
                    'hit_count': 1
                }
            else:
                ip_threats[ip]['hit_count'] += 1
                ip_threats[ip]['last_seen'] = src.get('timestamp')
                if src.get('threat_score', 0) > ip_threats[ip]['threat_score']:
                    ip_threats[ip]['threat_score'] = src.get('threat_score', 0)
                    ip_threats[ip]['threat_level'] = src.get('threat_level', 'unknown')
        
        threats = sorted(ip_threats.values(), key=lambda x: x['threat_score'], reverse=True)
        
        return jsonify({
            'threats': threats[:limit],
            'total': len(threats),
            'time_window_hours': hours,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Error getting latest threats: {e}")
        return jsonify({'error': str(e)}), 500


@stix_bp.route('/ip/<ip_address>')
def lookup_ip(ip_address):
    """Lookup an IP address for threat intelligence"""
    output_format = request.args.get('format', 'json')
    limit = min(request.args.get('limit', 20, type=int), 100)
    
    es_client = get_es_client()
    ES_PREFIX = get_es_prefix()
    
    if not use_elasticsearch() or not es_client:
        return jsonify({'error': 'Elasticsearch not available'}), 503
    
    try:
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "should": [
                        {"term": {"src_ip": ip_address}},
                        {"term": {"ip": ip_address}}
                    ],
                    "minimum_should_match": 1
                }
            }
        }
        
        res = es_client.search(index=f"{ES_PREFIX}-*", body=query)
        
        if res['hits']['total']['value'] == 0:
            return jsonify({
                'ip': ip_address,
                'found': False,
                'message': 'IP not found in honeypot logs',
                'timestamp': datetime.now().isoformat()
            })
        
        hits = res['hits']['hits']
        first_seen = hits[-1]['_source'].get('timestamp')
        last_seen = hits[0]['_source'].get('timestamp')
        
        attack_tools = {}
        attack_techniques = set()
        max_threat_score = 0
        geoip_data = {}
        osint_data = {}
        
        attack_history = []
        for hit in hits:
            src = hit['_source']
            
            tool = src.get('attack_tool', 'unknown')
            if tool not in attack_tools:
                attack_tools[tool] = 0
            attack_tools[tool] += 1
            
            techniques = src.get('attack_techniques', src.get('attack_technique', []))
            if isinstance(techniques, list):
                attack_techniques.update(techniques)
            
            if src.get('threat_score', 0) > max_threat_score:
                max_threat_score = src.get('threat_score', 0)
            
            if not geoip_data and isinstance(src.get('geoip'), dict):
                geoip_data = src.get('geoip', {})
            
            if not osint_data and isinstance(src.get('osint'), dict):
                osint_data = src.get('osint', {})
            
            attack_history.append({
                'timestamp': src.get('timestamp'),
                'attack_tool': tool,
                'method': src.get('method', ''),
                'path': src.get('path', ''),
                'threat_score': src.get('threat_score', 0)
            })
        
        if max_threat_score >= 70:
            threat_level = 'critical'
        elif max_threat_score >= 50:
            threat_level = 'high'
        elif max_threat_score >= 30:
            threat_level = 'medium'
        else:
            threat_level = 'low'
        
        result = {
            'ip': ip_address,
            'found': True,
            'threat_summary': {
                'threat_level': threat_level,
                'threat_score': max_threat_score,
                'total_attacks': res['hits']['total']['value'],
                'first_seen': first_seen,
                'last_seen': last_seen,
                'attack_tools': attack_tools,
                'techniques': list(attack_techniques)
            },
            'geoip': geoip_data,
            'osint': osint_data,
            'attack_history': attack_history[:10],
            'timestamp': datetime.now().isoformat()
        }
        
        if output_format.lower() == 'stix':
            if not is_stix_available():
                result['stix_error'] = 'STIX formatter not available on this server'
            else:
                stix = get_stix_formatter()
                result['stix'] = stix.ip_to_stix_object(ip_address, hits[0]['_source'])
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"Error looking up IP {ip_address}: {e}")
        return jsonify({'error': str(e)}), 500


@stix_bp.route('/stix/indicators')
def get_stix_indicators():
    """Get threat indicators in STIX 2.1 Bundle format"""
    limit = min(request.args.get('limit', 50, type=int), 100)
    hours = request.args.get('hours', 24, type=int)
    min_score = request.args.get('min_score', 0, type=int)
    
    es_client = get_es_client()
    ES_PREFIX = get_es_prefix()
    
    if not use_elasticsearch() or not es_client:
        return jsonify({'error': 'Elasticsearch not available'}), 503
    
    if not is_stix_available():
        return jsonify({'error': 'STIX formatter not available on this server'}), 503
    
    try:
        time_from = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        query = {
            "size": limit * 2,
            "sort": [{"threat_score": {"order": "desc"}}, {"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": time_from}}},
                        {"range": {"threat_score": {"gte": min_score}}}
                    ]
                }
            }
        }
        
        res = es_client.search(index=f"{ES_PREFIX}-*", body=query)
        
        seen_ips = set()
        logs = []
        for hit in res['hits']['hits']:
            src = hit['_source']
            ip = src.get('src_ip', src.get('ip', ''))
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                logs.append(src)
                if len(logs) >= limit:
                    break
        
        stix = get_stix_formatter()
        bundle = stix.logs_to_bundle(logs)
        
        from flask import current_app
        response = current_app.response_class(
            response=json.dumps(bundle, indent=2),
            status=200,
            mimetype='application/stix+json;version=2.1'
        )
        return response
        
    except Exception as e:
        logging.error(f"Error generating STIX indicators: {e}")
        return jsonify({'error': str(e)}), 500


@stix_bp.route('/stix/ip/<ip_address>')
def get_stix_for_ip(ip_address):
    """Get STIX 2.1 Bundle for a specific IP address"""
    es_client = get_es_client()
    ES_PREFIX = get_es_prefix()
    
    if not use_elasticsearch() or not es_client:
        return jsonify({'error': 'Elasticsearch not available'}), 503
    
    if not is_stix_available():
        return jsonify({'error': 'STIX formatter not available on this server'}), 503
    
    try:
        query = {
            "size": 1,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "should": [
                        {"term": {"src_ip": ip_address}},
                        {"term": {"ip": ip_address}}
                    ],
                    "minimum_should_match": 1
                }
            }
        }
        
        res = es_client.search(index=f"{ES_PREFIX}-*", body=query)
        
        if res['hits']['total']['value'] == 0:
            return jsonify({
                'error': 'IP not found',
                'message': f'No attack logs found for IP {ip_address}'
            }), 404
        
        log = res['hits']['hits'][0]['_source']
        stix = get_stix_formatter()
        bundle = stix.ip_to_stix_object(ip_address, log)
        
        from flask import current_app
        response = current_app.response_class(
            response=json.dumps(bundle, indent=2),
            status=200,
            mimetype='application/stix+json;version=2.1'
        )
        return response
        
    except Exception as e:
        logging.error(f"Error generating STIX for IP {ip_address}: {e}")
        return jsonify({'error': str(e)}), 500
