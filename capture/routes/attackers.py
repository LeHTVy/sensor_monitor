"""
Attackers Routes - Attacker List and Reconnaissance
"""

from flask import Blueprint, request, jsonify, current_app, send_file
from datetime import datetime
import logging

attackers_bp = Blueprint('attackers', __name__, url_prefix='/api')


def get_es_client():
    """Get Elasticsearch client from app context"""
    return current_app.config.get('es_client')


def get_es_prefix():
    """Get Elasticsearch index prefix"""
    return current_app.config.get('ES_PREFIX', 'sensor-logs')


def use_elasticsearch():
    """Check if Elasticsearch is enabled"""
    return current_app.config.get('USE_ELASTICSEARCH', False)


@attackers_bp.route('/attackers')
def get_attackers():
    """Get unique attacker IPs aggregated from Elasticsearch with metadata"""
    try:
        limit = int(request.args.get('limit', 50))
        page = int(request.args.get('page', 1))
        sort_by = request.args.get('sort_by', 'total_attacks')
        sort_order = request.args.get('order', 'desc')
        
        es_client = get_es_client()
        ES_PREFIX = get_es_prefix()
        
        if not use_elasticsearch() or not es_client:
            return jsonify({'error': 'Elasticsearch not configured'}), 503
        
        query = {
            "size": 0,
            "aggs": {
                "unique_ips": {
                    "terms": {
                        "field": "ip.keyword",
                        "size": 500,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "first_seen": {"min": {"field": "timestamp"}},
                        "last_seen": {"max": {"field": "timestamp"}},
                        "avg_threat_score": {"avg": {"field": "threat_score"}},
                        "max_threat_score": {"max": {"field": "threat_score"}},
                        "country": {"terms": {"field": "geoip.country", "size": 1, "missing": "Unknown"}},
                        "city": {"terms": {"field": "geoip.city", "size": 1, "missing": "Unknown"}},
                        "isp": {"terms": {"field": "geoip.isp", "size": 1, "missing": "Unknown"}},
                        "attack_tools": {"terms": {"field": "attack_tool.keyword", "size": 5}}
                    }
                }
            }
        }

        # Try different field names
        candidates = ["ip.keyword", "src_ip.keyword", "ip", "src_ip"]
        res = {}
        
        for field in candidates:
            query["aggs"]["unique_ips"]["terms"]["field"] = field
            try:
                res = es_client.search(index=f"{ES_PREFIX}-*", body=query)
                if 'aggregations' in res and 'unique_ips' in res['aggregations']:
                    buckets = res['aggregations']['unique_ips'].get('buckets', [])
                    if len(buckets) > 0:
                        break
            except Exception:
                continue

        attackers = []
        if 'aggregations' in res and 'unique_ips' in res['aggregations']:
            buckets = res['aggregations']['unique_ips'].get('buckets', [])
            
            for bucket in buckets:
                ip = bucket['key']
                total_attacks = bucket['doc_count']
                
                first_seen = bucket.get('first_seen', {}).get('value_as_string', '')
                last_seen = bucket.get('last_seen', {}).get('value_as_string', '')
                avg_threat = bucket.get('avg_threat_score', {}).get('value', 0)
                max_threat = bucket.get('max_threat_score', {}).get('value', 0)
                
                country_buckets = bucket.get('country', {}).get('buckets', [])
                country = country_buckets[0]['key'] if country_buckets else 'Unknown'
                
                city_buckets = bucket.get('city', {}).get('buckets', [])
                city = city_buckets[0]['key'] if city_buckets else 'Unknown'
                
                isp_buckets = bucket.get('isp', {}).get('buckets', [])
                isp = isp_buckets[0]['key'] if isp_buckets else 'Unknown'
                
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
        
        # Sort
        if sort_by == 'total_attacks':
            attackers.sort(key=lambda x: x['total_attacks'], reverse=(sort_order == 'desc'))
        elif sort_by == 'threat_score':
            attackers.sort(key=lambda x: x['max_threat_score'], reverse=(sort_order == 'desc'))
        elif sort_by == 'last_seen':
            attackers.sort(key=lambda x: x['last_seen'], reverse=(sort_order == 'desc'))
        
        # Pagination
        total_attackers = len(attackers)
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_attackers = attackers[start_idx:end_idx]
        
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
        return jsonify({'error': str(e)}), 500


# =============================================================================
# RECONNAISSANCE ENDPOINTS
# =============================================================================

@attackers_bp.route('/recon/start', methods=['POST'])
def start_reconnaissance():
    """Start black box reconnaissance on a target IP"""
    from recon.recon_service import create_recon_job
    
    data = request.get_json()
    target_ip = data.get('target_ip')
    scan_type = data.get('scan_type', 'basic')
    
    if not target_ip:
        return jsonify({'error': 'target_ip is required'}), 400
    
    # Validate scan_type
    valid_types = ['basic', 'full', 'stealth', 'passive']
    if scan_type not in valid_types:
        return jsonify({
            'error': f'Invalid scan_type. Must be one of: {valid_types}'
        }), 400
    
    try:
        job = create_recon_job(target_ip, scan_type)
        return jsonify({
            'recon_id': job['id'],
            'target_ip': target_ip,
            'scan_type': scan_type,
            'status': 'started',
            'message': f'Reconnaissance job started for {target_ip}'
        }), 202
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@attackers_bp.route('/recon/stats')
def get_recon_stats():
    """Get recon job statistics from Elasticsearch"""
    es_client = get_es_client()
    
    if not es_client:
        from recon.recon_service import active_recon_jobs
        return jsonify({
            'active_jobs': len(active_recon_jobs),
            'message': 'ES not available, showing in-memory stats only'
        })
    
    try:
        query = {
            "size": 0,
            "aggs": {
                "by_status": {"terms": {"field": "status.keyword"}},
                "by_target": {"terms": {"field": "target_ip.keyword", "size": 10}},
                "total_jobs": {"value_count": {"field": "recon_id.keyword"}}
            }
        }
        
        res = es_client.search(index="recon-*", body=query)
        
        stats = {
            'total_jobs': 0,
            'by_status': {},
            'by_target': []
        }
        
        if 'aggregations' in res:
            aggs = res['aggregations']
            stats['total_jobs'] = int(aggs.get('total_jobs', {}).get('value', 0))
            
            for bucket in aggs.get('by_status', {}).get('buckets', []):
                stats['by_status'][bucket['key']] = bucket['doc_count']
            
            for bucket in aggs.get('by_target', {}).get('buckets', []):
                stats['by_target'].append({
                    'target': bucket['key'],
                    'count': bucket['doc_count']
                })
        
        return jsonify(stats)
        
    except Exception as e:
        logging.error(f"Recon stats error: {e}")
        return jsonify({'error': str(e)}), 500


@attackers_bp.route('/recon/<recon_id>/status')
def get_reconnaissance_status(recon_id):
    """Get status of a reconnaissance job"""
    from recon.recon_service import get_recon_status
    
    status = get_recon_status(recon_id)
    if status:
        return jsonify(status)
    return jsonify({'error': 'Reconnaissance job not found'}), 404


@attackers_bp.route('/recon/<recon_id>/results')
def get_reconnaissance_results(recon_id):
    """Get full results of a reconnaissance job"""
    from recon.recon_service import get_recon_results
    
    results = get_recon_results(recon_id)
    if results:
        return jsonify(results)
    return jsonify({'error': 'Reconnaissance job not found'}), 404


@attackers_bp.route('/recon/<recon_id>/report')
def download_reconnaissance_report(recon_id):
    """Download reconnaissance report in DOCX or PDF format"""
    from recon.recon_service import get_recon_results
    from recon.report_generator import generate_report
    
    format_type = request.args.get('format', 'docx')
    
    results = get_recon_results(recon_id)
    if not results:
        return jsonify({'error': 'Reconnaissance job not found'}), 404
    
    if results.get('status') != 'completed':
        return jsonify({
            'error': 'Report not ready',
            'status': results.get('status')
        }), 400
    
    try:
        report_path = generate_report(results, format_type)
        return send_file(
            report_path,
            as_attachment=True,
            download_name=f"recon_report_{recon_id}.{format_type}"
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500
