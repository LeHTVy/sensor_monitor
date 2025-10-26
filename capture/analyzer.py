#!/usr/bin/env python3
"""
Attack Analyzer
Analyzes captured data and logs to identify attack patterns
"""

import os
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter

class AttackAnalyzer:
    def __init__(self, log_dir="/app/logs"):
        self.log_dir = log_dir
        self.analysis_dir = os.path.join(log_dir, "analysis")
        self.report_dir = os.path.join(log_dir, "reports")
        
        # Create directories
        os.makedirs(self.analysis_dir, exist_ok=True)
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Analysis patterns
        self.sql_patterns = [
            r"union\s+select", r"drop\s+table", r"delete\s+from",
            r"insert\s+into", r"update\s+set", r"or\s+1\s*=\s*1",
            r"'\s*or\s*'", r"\"\s*or\s*\"", r"admin'\s*--",
            r"'\s*;\s*drop\s+table", r"'\s*;\s*delete\s+from"
        ]
        
        self.command_patterns = [
            r"rm\s+-rf", r"cat\s+/etc/passwd", r"whoami",
            r"id", r"uname\s+-a", r"ps\s+aux", r"netstat",
            r"wget\s+", r"curl\s+", r"nc\s+", r"ncat\s+",
            r"python\s+-c", r"perl\s+-e", r"bash\s+-c"
        ]
        
        self.file_patterns = [
            r"\.php$", r"\.sh$", r"\.py$", r"\.exe$",
            r"\.bat$", r"\.cmd$", r"\.scr$", r"\.pif$"
        ]
        
        # IP reputation scoring
        self.ip_scores = defaultdict(int)
        self.attack_counts = defaultdict(int)
    
    def analyze_all_logs(self):
        """Analyze all available logs"""
        print("Starting comprehensive log analysis...")
        
        # Analyze honeypot logs
        honeypot_analysis = self.analyze_honeypot_logs()
        
        # Analyze packet capture logs
        packet_analysis = self.analyze_packet_logs()
        
        # Generate combined report
        combined_report = self.generate_combined_report(honeypot_analysis, packet_analysis)
        
        # Save report
        self.save_report(combined_report)
        
        return combined_report
    
    def analyze_honeypot_logs(self):
        """Analyze logs from honeypot server"""
        analysis = {
            'total_requests': 0,
            'attack_types': defaultdict(int),
            'suspicious_ips': set(),
            'sql_injections': [],
            'command_injections': [],
            'file_uploads': [],
            'auth_attempts': [],
            'time_range': {'start': None, 'end': None}
        }
        
        honeypot_log = os.path.join(self.log_dir, "honeypot", "honeypot_logs.log")
        
        if not os.path.exists(honeypot_log):
            print("No honeypot logs found")
            return analysis
        
        try:
            with open(honeypot_log, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_data = json.loads(line.strip())
                        self._analyze_honeypot_log(log_data, analysis)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error analyzing honeypot logs: {str(e)}")
        
        # Convert sets to lists for JSON serialization
        analysis['suspicious_ips'] = list(analysis['suspicious_ips'])
        analysis['attack_types'] = dict(analysis['attack_types'])
        
        return analysis
    
    def _analyze_honeypot_log(self, log_data, analysis):
        """Analyze individual honeypot log entry"""
        analysis['total_requests'] += 1
        
        # Extract basic info
        log_type = log_data.get('type', 'unknown')
        src_ip = log_data.get('ip', 'unknown')
        timestamp = log_data.get('timestamp', '')
        
        # Update time range
        if timestamp:
            if not analysis['time_range']['start'] or timestamp < analysis['time_range']['start']:
                analysis['time_range']['start'] = timestamp
            if not analysis['time_range']['end'] or timestamp > analysis['time_range']['end']:
                analysis['time_range']['end'] = timestamp
        
        # Track attack types
        analysis['attack_types'][log_type] += 1
        
        # Track suspicious IPs
        if src_ip != 'unknown':
            analysis['suspicious_ips'].add(src_ip)
            self.ip_scores[src_ip] += 1
        
        # Analyze specific attack types
        if 'sql_injection' in log_type:
            self._analyze_sql_injection(log_data, analysis)
        elif 'command_injection' in log_type:
            self._analyze_command_injection(log_data, analysis)
        elif 'file_upload' in log_type:
            self._analyze_file_upload(log_data, analysis)
        elif 'authentication_attempt' in log_type:
            self._analyze_auth_attempt(log_data, analysis)
    
    def _analyze_sql_injection(self, log_data, analysis):
        """Analyze SQL injection attempt"""
        query = log_data.get('query', '')
        username = log_data.get('username', '')
        
        # Check for SQL patterns
        sql_detected = False
        for pattern in self.sql_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                sql_detected = True
                break
        
        injection_data = {
            'timestamp': log_data.get('timestamp'),
            'ip': log_data.get('ip'),
            'username': username,
            'query': query,
            'sql_detected': sql_detected,
            'severity': 'high' if sql_detected else 'medium'
        }
        
        analysis['sql_injections'].append(injection_data)
    
    def _analyze_command_injection(self, log_data, analysis):
        """Analyze command injection attempt"""
        command = log_data.get('command', '')
        
        # Check for command patterns
        cmd_detected = False
        for pattern in self.command_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                cmd_detected = True
                break
        
        injection_data = {
            'timestamp': log_data.get('timestamp'),
            'ip': log_data.get('ip'),
            'command': command,
            'cmd_detected': cmd_detected,
            'severity': 'critical' if cmd_detected else 'high'
        }
        
        analysis['command_injections'].append(injection_data)
    
    def _analyze_file_upload(self, log_data, analysis):
        """Analyze file upload attempt"""
        filename = log_data.get('filename', '')
        filepath = log_data.get('filepath', '')
        
        # Check for suspicious file patterns
        suspicious_file = False
        for pattern in self.file_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                suspicious_file = True
                break
        
        upload_data = {
            'timestamp': log_data.get('timestamp'),
            'ip': log_data.get('ip'),
            'filename': filename,
            'filepath': filepath,
            'suspicious_file': suspicious_file,
            'severity': 'high' if suspicious_file else 'medium'
        }
        
        analysis['file_uploads'].append(upload_data)
    
    def _analyze_auth_attempt(self, log_data, analysis):
        """Analyze authentication attempt"""
        username = log_data.get('username', '')
        password = log_data.get('password', '')
        success = log_data.get('success', False)
        
        auth_data = {
            'timestamp': log_data.get('timestamp'),
            'ip': log_data.get('ip'),
            'username': username,
            'password': password,
            'success': success,
            'severity': 'medium'
        }
        
        analysis['auth_attempts'].append(auth_data)
    
    def analyze_packet_logs(self):
        """Analyze packet capture logs"""
        analysis = {
            'total_packets': 0,
            'attack_types': defaultdict(int),
            'suspicious_ips': set(),
            'port_scans': [],
            'nmap_detections': [],
            'telnet_attempts': [],
            'metasploit_payloads': [],
            'time_range': {'start': None, 'end': None}
        }
        
        packet_log = os.path.join(self.log_dir, "packets", "captured_packets.log")
        attack_log = os.path.join(self.log_dir, "analysis", "attack_analysis.log")
        
        # Analyze packet logs
        if os.path.exists(packet_log):
            self._analyze_packet_file(packet_log, analysis)
        
        # Analyze attack logs
        if os.path.exists(attack_log):
            self._analyze_attack_file(attack_log, analysis)
        
        # Convert sets to lists
        analysis['suspicious_ips'] = list(analysis['suspicious_ips'])
        analysis['attack_types'] = dict(analysis['attack_types'])
        
        return analysis
    
    def _analyze_packet_file(self, packet_log, analysis):
        """Analyze packet capture file"""
        try:
            with open(packet_log, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        packet_data = json.loads(line.strip())
                        self._analyze_packet(packet_data, analysis)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error analyzing packet file: {str(e)}")
    
    def _analyze_packet(self, packet_data, analysis):
        """Analyze individual packet"""
        analysis['total_packets'] += 1
        
        src_ip = packet_data.get('src_ip')
        timestamp = packet_data.get('timestamp')
        
        if src_ip:
            analysis['suspicious_ips'].add(src_ip)
        
        if timestamp:
            if not analysis['time_range']['start'] or timestamp < analysis['time_range']['start']:
                analysis['time_range']['start'] = timestamp
            if not analysis['time_range']['end'] or timestamp > analysis['time_range']['end']:
                analysis['time_range']['end'] = timestamp
    
    def _analyze_attack_file(self, attack_log, analysis):
        """Analyze attack analysis file"""
        try:
            with open(attack_log, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        attack_data = json.loads(line.strip())
                        self._analyze_attack(attack_data, analysis)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error analyzing attack file: {str(e)}")
    
    def _analyze_attack(self, attack_data, analysis):
        """Analyze individual attack"""
        attack_type = attack_data.get('attack_type', 'unknown')
        src_ip = attack_data.get('src_ip')
        
        analysis['attack_types'][attack_type] += 1
        
        if src_ip:
            analysis['suspicious_ips'].add(src_ip)
            self.attack_counts[src_ip] += 1
        
        # Categorize attacks
        if attack_type == 'nmap_scan':
            analysis['nmap_detections'].append(attack_data)
        elif attack_type == 'telnet_attempt':
            analysis['telnet_attempts'].append(attack_data)
        elif attack_type == 'metasploit_payload':
            analysis['metasploit_payloads'].append(attack_data)
        elif attack_type == 'port_scan':
            analysis['port_scans'].append(attack_data)
    
    def generate_combined_report(self, honeypot_analysis, packet_analysis):
        """Generate combined analysis report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'honeypot': honeypot_analysis,
            'packet_capture': packet_analysis,
            'summary': self._generate_summary(honeypot_analysis, packet_analysis),
            'threat_level': self._calculate_threat_level(honeypot_analysis, packet_analysis),
            'recommendations': self._generate_recommendations(honeypot_analysis, packet_analysis)
        }
        
        return report
    
    def _generate_summary(self, honeypot_analysis, packet_analysis):
        """Generate summary statistics"""
        total_attacks = sum(honeypot_analysis['attack_types'].values()) + sum(packet_analysis['attack_types'].values())
        unique_ips = len(set(honeypot_analysis['suspicious_ips'] + packet_analysis['suspicious_ips']))
        
        return {
            'total_attacks': total_attacks,
            'unique_attacker_ips': unique_ips,
            'honeypot_requests': honeypot_analysis['total_requests'],
            'packets_captured': packet_analysis['total_packets'],
            'sql_injections': len(honeypot_analysis['sql_injections']),
            'command_injections': len(honeypot_analysis['command_injections']),
            'file_uploads': len(honeypot_analysis['file_uploads']),
            'nmap_scans': len(packet_analysis['nmap_detections']),
            'telnet_attempts': len(packet_analysis['telnet_attempts']),
            'metasploit_payloads': len(packet_analysis['metasploit_payloads'])
        }
    
    def _calculate_threat_level(self, honeypot_analysis, packet_analysis):
        """Calculate overall threat level"""
        threat_score = 0
        
        # SQL injections
        threat_score += len(honeypot_analysis['sql_injections']) * 3
        
        # Command injections
        threat_score += len(honeypot_analysis['command_injections']) * 5
        
        # File uploads
        threat_score += len(honeypot_analysis['file_uploads']) * 2
        
        # Nmap scans
        threat_score += len(packet_analysis['nmap_detections']) * 2
        
        # Telnet attempts
        threat_score += len(packet_analysis['telnet_attempts']) * 4
        
        # Metasploit payloads
        threat_score += len(packet_analysis['metasploit_payloads']) * 10
        
        # Determine threat level
        if threat_score >= 50:
            return 'CRITICAL'
        elif threat_score >= 20:
            return 'HIGH'
        elif threat_score >= 10:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_recommendations(self, honeypot_analysis, packet_analysis):
        """Generate security recommendations"""
        recommendations = []
        
        if honeypot_analysis['sql_injections']:
            recommendations.append("Implement proper SQL injection protection and parameterized queries")
        
        if honeypot_analysis['command_injections']:
            recommendations.append("Implement command injection protection and input validation")
        
        if honeypot_analysis['file_uploads']:
            recommendations.append("Implement file upload restrictions and malware scanning")
        
        if packet_analysis['nmap_detections']:
            recommendations.append("Implement network monitoring and intrusion detection")
        
        if packet_analysis['telnet_attempts']:
            recommendations.append("Disable telnet and use SSH with key-based authentication")
        
        if packet_analysis['metasploit_payloads']:
            recommendations.append("Implement advanced threat detection and response")
        
        if not recommendations:
            recommendations.append("Continue monitoring for new threats")
        
        return recommendations
    
    def save_report(self, report):
        """Save analysis report to file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = os.path.join(self.report_dir, f"analysis_report_{timestamp}.json")
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            print(f"Analysis report saved to: {report_file}")
            
        except Exception as e:
            print(f"Error saving report: {str(e)}")
    
    def get_top_attackers(self, limit=10):
        """Get top attacking IPs"""
        return Counter(self.ip_scores).most_common(limit)
    
    def get_attack_timeline(self, hours=24):
        """Get attack timeline for last N hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        timeline = defaultdict(int)
        
        # Analyze honeypot logs
        honeypot_log = os.path.join(self.log_dir, "honeypot", "honeypot_logs.log")
        if os.path.exists(honeypot_log):
            with open(honeypot_log, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_data = json.loads(line.strip())
                        timestamp = log_data.get('timestamp', '')
                        if timestamp:
                            log_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                            if log_time > cutoff_time:
                                hour_key = log_time.strftime('%Y-%m-%d %H:00')
                                timeline[hour_key] += 1
                    except:
                        continue
        
        return dict(timeline)

def main():
    """Main function"""
    print("Starting Attack Analyzer...")
    
    analyzer = AttackAnalyzer()
    
    try:
        # Run analysis
        report = analyzer.analyze_all_logs()
        
        # Print summary
        print("\n=== ANALYSIS SUMMARY ===")
        print(f"Threat Level: {report['threat_level']}")
        print(f"Total Attacks: {report['summary']['total_attacks']}")
        print(f"Unique Attacker IPs: {report['summary']['unique_attacker_ips']}")
        print(f"SQL Injections: {report['summary']['sql_injections']}")
        print(f"Command Injections: {report['summary']['command_injections']}")
        print(f"Nmap Scans: {report['summary']['nmap_scans']}")
        print(f"Metasploit Payloads: {report['summary']['metasploit_payloads']}")
        
        print("\n=== TOP ATTACKERS ===")
        for ip, count in analyzer.get_top_attackers(5):
            print(f"{ip}: {count} attacks")
        
        print("\n=== RECOMMENDATIONS ===")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"{i}. {rec}")
        
    except Exception as e:
        print(f"Error in analysis: {str(e)}")

if __name__ == "__main__":
    main()
