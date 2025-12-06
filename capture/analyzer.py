#!/usr/bin/env python3
"""
Attack Analyzer - Elasticsearch Version
Analyzes attack data from Elasticsearch and generates reports
"""

import os
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Optional
from elasticsearch import Elasticsearch
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AttackAnalyzer:
    """
    Analyzes attack data stored in Elasticsearch
    Generates threat reports, identifies top attackers, and provides recommendations
    """
    
    def __init__(self, es_url: str = None, index_prefix: str = "sensor-logs"):
        """
        Initialize the analyzer
        
        Args:
            es_url: Elasticsearch URL (default: from environment or localhost)
            index_prefix: Elasticsearch index prefix
        """
        self.es_url = es_url or os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')
        self.index_prefix = index_prefix
        self.es = None
        
        # Report directory
        self.report_dir = os.getenv('REPORT_DIR', '/app/logs/reports')
        os.makedirs(self.report_dir, exist_ok=True)
        
        # IP scores for tracking
        self.ip_scores = defaultdict(int)
        
        logger.info(f"AttackAnalyzer initialized - ES: {self.es_url}, Index: {self.index_prefix}")
        
    def connect(self) -> bool:
        """Connect to Elasticsearch"""
        try:
            self.es = Elasticsearch([self.es_url])
            if self.es.ping():
                logger.info("✅ Connected to Elasticsearch")
                return True
            else:
                logger.error("❌ Elasticsearch ping failed")
                return False
        except Exception as e:
            logger.error(f"❌ Failed to connect to Elasticsearch: {e}")
            return False
            
    def analyze_attacks(self, hours: int = 24) -> Dict:
        """
        Analyze attacks from the last N hours
        
        Args:
            hours: Number of hours to analyze
            
        Returns:
            Analysis report dictionary
        """
        if not self.es:
            if not self.connect():
                return {"error": "Cannot connect to Elasticsearch"}
        
        logger.info(f"📊 Analyzing attacks from last {hours} hours...")
        
        # Query Elasticsearch
        time_filter = datetime.now() - timedelta(hours=hours)
        
        query = {
            "size": 10000,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": time_filter.isoformat()}}}
                    ]
                }
            },
            "sort": [{"timestamp": "desc"}]
        }
        
        try:
            # Search across all indices with prefix
            response = self.es.search(index=f"{self.index_prefix}-*", body=query)
            hits = response.get('hits', {}).get('hits', [])
            logger.info(f"📥 Retrieved {len(hits)} log entries")
            
            # Analyze the data
            analysis = self._analyze_logs(hits)
            
            # Generate report
            report = self._generate_report(analysis, hours)
            
            return report
            
        except Exception as e:
            logger.error(f"❌ Error querying Elasticsearch: {e}")
            return {"error": str(e)}
            
    def _analyze_logs(self, hits: List) -> Dict:
        """Analyze log entries"""
        analysis = {
            'total_events': len(hits),
            'attack_tools': defaultdict(int),
            'attack_techniques': defaultdict(int),
            'threat_levels': defaultdict(int),
            'source_ips': defaultdict(lambda: {'count': 0, 'tools': set(), 'techniques': set()}),
            'countries': defaultdict(int),
            'time_range': {'start': None, 'end': None},
            'high_threat_events': [],
            'protocols': defaultdict(int),
            'ports_targeted': defaultdict(int)
        }
        
        for hit in hits:
            source = hit.get('_source', {})
            
            # Track time range
            timestamp = source.get('timestamp', source.get('enriched_at', ''))
            if timestamp:
                if not analysis['time_range']['start'] or timestamp < analysis['time_range']['start']:
                    analysis['time_range']['start'] = timestamp
                if not analysis['time_range']['end'] or timestamp > analysis['time_range']['end']:
                    analysis['time_range']['end'] = timestamp
            
            # Track attack tools
            tool = source.get('attack_tool', 'unknown')
            if tool and tool != 'unknown':
                analysis['attack_tools'][tool] += 1
            
            # Track techniques
            techniques = source.get('attack_techniques', source.get('attack_technique', []))
            if isinstance(techniques, str):
                techniques = [techniques]
            for technique in techniques:
                if technique and technique != 'unknown':
                    analysis['attack_techniques'][technique] += 1
            
            # Track threat levels
            threat_level = source.get('threat_level', 'unknown')
            analysis['threat_levels'][threat_level] += 1
            
            # Track source IPs
            src_ip = source.get('ip', source.get('src_ip', 'unknown'))
            if src_ip and src_ip != 'unknown':
                analysis['source_ips'][src_ip]['count'] += 1
                if tool:
                    analysis['source_ips'][src_ip]['tools'].add(tool)
                for tech in techniques:
                    analysis['source_ips'][src_ip]['techniques'].add(tech)
                self.ip_scores[src_ip] += 1
            
            # Track GeoIP
            geoip = source.get('geoip', {})
            country = geoip.get('country', 'Unknown')
            if country:
                analysis['countries'][country] += 1
                
            # Track protocols and ports
            protocol = source.get('protocol', '')
            if protocol:
                analysis['protocols'][protocol] += 1
                
            dst_port = source.get('dst_port')
            if dst_port:
                analysis['ports_targeted'][dst_port] += 1
            
            # Collect high-threat events
            if threat_level in ['high', 'critical']:
                analysis['high_threat_events'].append({
                    'timestamp': timestamp,
                    'ip': src_ip,
                    'tool': tool,
                    'techniques': techniques,
                    'threat_level': threat_level,
                    'country': country
                })
        
        return analysis
        
    def _generate_report(self, analysis: Dict, hours: int) -> Dict:
        """Generate a comprehensive report"""
        
        # Calculate overall threat level
        threat_score = self._calculate_threat_score(analysis)
        overall_threat = self._get_threat_level(threat_score)
        
        # Get top attackers
        top_attackers = sorted(
            [(ip, data) for ip, data in analysis['source_ips'].items()],
            key=lambda x: x[1]['count'],
            reverse=True
        )[:10]
        
        # Format top attackers
        top_attackers_formatted = []
        for ip, data in top_attackers:
            top_attackers_formatted.append({
                'ip': ip,
                'event_count': data['count'],
                'tools_used': list(data['tools']),
                'techniques': list(data['techniques'])
            })
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'analysis_period': f'Last {hours} hours',
            'time_range': analysis['time_range'],
            
            'summary': {
                'total_events': analysis['total_events'],
                'unique_attackers': len(analysis['source_ips']),
                'unique_tools_detected': len(analysis['attack_tools']),
                'unique_techniques': len(analysis['attack_techniques']),
                'high_threat_events': len(analysis['high_threat_events']),
                'threat_score': threat_score,
                'overall_threat_level': overall_threat
            },
            
            'attack_tools': dict(Counter(analysis['attack_tools']).most_common(20)),
            'attack_techniques': dict(Counter(analysis['attack_techniques']).most_common(20)),
            'threat_level_distribution': dict(analysis['threat_levels']),
            'top_source_countries': dict(Counter(analysis['countries']).most_common(10)),
            'top_targeted_ports': dict(Counter(analysis['ports_targeted']).most_common(10)),
            'protocol_distribution': dict(analysis['protocols']),
            
            'top_attackers': top_attackers_formatted,
            'high_threat_events': analysis['high_threat_events'][:50],  # Limit to 50
            
            'recommendations': self._generate_recommendations(analysis, overall_threat)
        }
        
        return report
        
    def _calculate_threat_score(self, analysis: Dict) -> int:
        """Calculate overall threat score (0-100)"""
        score = 0
        
        # Event volume (0-20 points)
        total = analysis['total_events']
        if total > 1000:
            score += 20
        elif total > 500:
            score += 15
        elif total > 100:
            score += 10
        elif total > 50:
            score += 5
            
        # High threat events (0-30 points)
        high_threats = len(analysis['high_threat_events'])
        if high_threats > 50:
            score += 30
        elif high_threats > 20:
            score += 25
        elif high_threats > 10:
            score += 20
        elif high_threats > 5:
            score += 10
        elif high_threats > 0:
            score += 5
            
        # Dangerous tools (0-25 points)
        dangerous_tools = ['metasploit', 'cobaltstrike', 'sqlmap', 'hydra', 'beef']
        for tool in dangerous_tools:
            if tool in analysis['attack_tools']:
                score += 5
                
        # Dangerous techniques (0-25 points)
        dangerous_techniques = ['command_injection', 'sql_injection', 'file_upload', 'rce']
        for tech in dangerous_techniques:
            if tech in analysis['attack_techniques']:
                score += 6
                
        return min(100, score)
        
    def _get_threat_level(self, score: int) -> str:
        """Convert score to threat level"""
        if score >= 70:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
            
    def _generate_recommendations(self, analysis: Dict, threat_level: str) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Based on attack tools detected
        tools = analysis['attack_tools']
        if 'sqlmap' in tools:
            recommendations.append("🛡️ Implement SQL injection protection (parameterized queries, WAF rules)")
        if 'nmap' in tools or 'masscan' in tools:
            recommendations.append("🔒 Review firewall rules, consider hiding service banners")
        if 'hydra' in tools:
            recommendations.append("🔑 Implement account lockout policies and strong authentication")
        if 'nikto' in tools or 'nuclei' in tools:
            recommendations.append("🔧 Update all software and apply security patches")
        if 'metasploit' in tools or 'cobaltstrike' in tools:
            recommendations.append("🚨 HIGH PRIORITY: Deploy advanced endpoint protection")
            
        # Based on techniques
        techniques = analysis['attack_techniques']
        if 'command_injection' in techniques:
            recommendations.append("⚠️ Audit all user input handling for command injection vulnerabilities")
        if 'path_traversal' in techniques:
            recommendations.append("📁 Implement strict file path validation")
        if 'brute_force' in techniques:
            recommendations.append("🔐 Enable rate limiting on authentication endpoints")
            
        # Based on threat level
        if threat_level == 'CRITICAL':
            recommendations.insert(0, "🚨 IMMEDIATE ACTION REQUIRED: Review all high-threat events manually")
        elif threat_level == 'HIGH':
            recommendations.insert(0, "⚠️ Schedule urgent security review within 24 hours")
            
        # Default recommendation
        if not recommendations:
            recommendations.append("✅ Continue monitoring, no immediate threats detected")
            
        return recommendations
        
    def save_report(self, report: Dict, filename: str = None) -> str:
        """Save report to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"attack_report_{timestamp}.json"
            
        filepath = os.path.join(self.report_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            logger.info(f"📄 Report saved: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"❌ Error saving report: {e}")
            return None
            
    def get_top_attackers(self, limit: int = 10) -> List[tuple]:
        """Get top attackers by event count"""
        return Counter(self.ip_scores).most_common(limit)
        
    def print_summary(self, report: Dict):
        """Print a formatted summary of the report"""
        print("\n" + "="*70)
        print("🔍 ATTACK ANALYSIS REPORT")
        print("="*70)
        
        summary = report.get('summary', {})
        print(f"\n📅 Period: {report.get('analysis_period', 'Unknown')}")
        print(f"🕐 Time Range: {report.get('time_range', {}).get('start', 'N/A')} to {report.get('time_range', {}).get('end', 'N/A')}")
        
        print(f"\n📊 SUMMARY")
        print(f"   Total Events: {summary.get('total_events', 0)}")
        print(f"   Unique Attackers: {summary.get('unique_attackers', 0)}")
        print(f"   Tools Detected: {summary.get('unique_tools_detected', 0)}")
        print(f"   High Threat Events: {summary.get('high_threat_events', 0)}")
        print(f"   Threat Score: {summary.get('threat_score', 0)}/100")
        print(f"   Threat Level: {summary.get('overall_threat_level', 'Unknown')}")
        
        print(f"\n🛠️ TOP ATTACK TOOLS")
        for tool, count in list(report.get('attack_tools', {}).items())[:5]:
            print(f"   • {tool}: {count} events")
            
        print(f"\n🌍 TOP SOURCE COUNTRIES")
        for country, count in list(report.get('top_source_countries', {}).items())[:5]:
            print(f"   • {country}: {count} events")
            
        print(f"\n👤 TOP ATTACKERS")
        for attacker in report.get('top_attackers', [])[:5]:
            print(f"   • {attacker['ip']}: {attacker['event_count']} events ({', '.join(attacker['tools_used'][:3])})")
            
        print(f"\n📋 RECOMMENDATIONS")
        for i, rec in enumerate(report.get('recommendations', [])[:5], 1):
            print(f"   {i}. {rec}")
            
        print("\n" + "="*70)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Attack Analyzer - Elasticsearch Version')
    parser.add_argument('--hours', '-t', type=int, default=24,
                        help='Hours to analyze (default: 24)')
    parser.add_argument('--es-url', '-e', default=None,
                        help='Elasticsearch URL (default: from env or localhost:9200)')
    parser.add_argument('--index', '-i', default='sensor-logs',
                        help='Elasticsearch index prefix (default: sensor-logs)')
    parser.add_argument('--output', '-o', default=None,
                        help='Output file path (default: auto-generated)')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Only output JSON, no summary')
    
    args = parser.parse_args()
    
    # Create analyzer
    analyzer = AttackAnalyzer(es_url=args.es_url, index_prefix=args.index)
    
    # Run analysis
    report = analyzer.analyze_attacks(hours=args.hours)
    
    if 'error' in report:
        print(f"❌ Error: {report['error']}")
        return 1
        
    # Save report
    filepath = analyzer.save_report(report, args.output)
    
    # Print summary unless quiet
    if not args.quiet:
        analyzer.print_summary(report)
        if filepath:
            print(f"\n📄 Full report saved to: {filepath}")
    else:
        print(json.dumps(report, indent=2, default=str))
        
    return 0


if __name__ == "__main__":
    exit(main())
