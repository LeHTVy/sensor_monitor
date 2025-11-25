#!/usr/bin/env python3
"""
LLM-Enhanced Attack Analyzer
Uses Local LLM (Ollama) to analyze attacker behavior and provide intelligent recommendations
"""

import os
import json
import requests
from datetime import datetime
from typing import Dict, List, Optional


class LLMAttackAnalyzer:
    """
    Analyzes attack patterns using Local LLM (Ollama)
    Provides behavioral analysis, intent prediction, and defense recommendations
    """

    def __init__(self, ollama_url='http://localhost:11434', model='llama3.2'):
        self.ollama_url = ollama_url
        self.model = model

        # Attack pattern templates for LLM
        self.attack_patterns = {
            'reconnaissance': [
                'port_scan', 'directory_enumeration', 'service_discovery',
                'vulnerability_scanning', 'banner_grabbing'
            ],
            'initial_access': [
                'brute_force', 'credential_stuffing', 'sql_injection',
                'command_injection', 'file_upload', 'default_credentials'
            ],
            'persistence': [
                'backdoor_installation', 'webshell_upload', 'cron_job',
                'startup_script', 'registry_modification'
            ],
            'privilege_escalation': [
                'exploit_vulnerability', 'sudo_abuse', 'kernel_exploit',
                'dll_hijacking', 'token_manipulation'
            ],
            'data_exfiltration': [
                'database_dump', 'file_download', 'api_abuse',
                'dns_tunneling', 'http_exfiltration'
            ]
        }

        print(f"✅ LLM Attack Analyzer initialized")
        print(f"   Ollama URL: {self.ollama_url}")
        print(f"   Model: {self.model}")

    def analyze_attack_intent(self, llm_context: Dict) -> Dict:
        """
        Analyze attacker's intent using LLM

        Args:
            llm_context: Structured data from honeypot (enriched with threat intel)

        Returns:
            Analysis result with intent prediction and recommendations
        """
        print(f"\n🤖 Analyzing attack from {llm_context['attacker_profile']['ip_address']}...")

        # Build prompt for LLM
        prompt = self._build_analysis_prompt(llm_context)

        # Query LLM
        llm_response = self._query_ollama(prompt)

        if not llm_response:
            # Fallback to rule-based analysis
            return self._fallback_analysis(llm_context)

        # Parse LLM response
        analysis = self._parse_llm_response(llm_response, llm_context)

        return analysis

    def _build_analysis_prompt(self, llm_context: Dict) -> str:
        """
        Build detailed prompt for LLM analysis

        The prompt includes:
        - Attacker profile (IP, location, reputation, infrastructure)
        - Attack details (tool, technique, payload)
        - Technical intelligence (ports, services, vulnerabilities)
        - Behavioral indicators (rate, patterns, etc.)
        """
        attacker = llm_context['attacker_profile']
        attack = llm_context['attack_details']
        tech_intel = llm_context['technical_intelligence']
        behavior = llm_context['behavioral_indicators']

        prompt = f"""You are a cybersecurity expert analyzing a cyber attack on our honeypot system.

# ATTACKER PROFILE
- IP Address: {attacker['ip_address']}
- Reputation Score: {attacker['reputation_score']}/100 (higher = more malicious)
- Threat Level: {attacker['threat_level']}
- Location: {attacker['location'].get('city', 'Unknown')}, {attacker['location'].get('country', 'Unknown')}
- ISP/Organization: {attacker['location'].get('isp', 'Unknown')} / {attacker['location'].get('organization', 'Unknown')}

# INFRASTRUCTURE
- Known Scanner: {attacker['infrastructure'].get('is_known_scanner', 'Unknown')}
- VPN/Proxy: {attacker['infrastructure'].get('is_vpn_proxy', 'Unknown')}
- Tor Exit Node: {attacker['infrastructure'].get('is_tor_exit', 'Unknown')}
- Cloud Infrastructure: {attacker['infrastructure'].get('is_cloud', 'Unknown')}
- ASN: {attacker['infrastructure'].get('asn', 'Unknown')}

# ATTACK HISTORY
- Abuse Reports: {attacker['attack_history']['abuse_reports']}
- Last Reported: {attacker['attack_history']['last_reported'] or 'Never'}
- Confidence Score: {attacker['attack_history']['confidence_score']}/100

# CURRENT ATTACK
- Timestamp: {attack['timestamp']}
- Attack Tool: {attack['attack_tool']}
- Attack Techniques: {', '.join(attack['attack_technique'])}
- Target Path: {attack['target_path']}
- HTTP Method: {attack['http_method']}
- User Agent: {attack['user_agent'][:100]}...

# PAYLOAD ANALYSIS
- Query String: {json.dumps(attack['payload']['query_string']) if attack['payload']['query_string'] else 'None'}
- Form Data: {json.dumps(attack['payload']['form_data']) if attack['payload']['form_data'] else 'None'}
- Files Uploaded: {', '.join(attack['payload']['files']) if attack['payload']['files'] else 'None'}

# TECHNICAL INTELLIGENCE (from Shodan)
- Open Ports: {', '.join(map(str, tech_intel['open_ports'][:10])) if tech_intel['open_ports'] else 'Unknown'}
- Operating System: {tech_intel['operating_system']}
- Vulnerabilities (CVEs): {', '.join(tech_intel['vulnerabilities'][:5]) if tech_intel['vulnerabilities'] else 'None'}
- Shodan Tags: {', '.join(tech_intel['tags'][:5]) if tech_intel['tags'] else 'None'}

# BEHAVIORAL INDICATORS
- Request Rate: {behavior['request_rate']} req/sec
- Failed Auth Attempts: {behavior['failed_auth_attempts']}
- Unique Paths Accessed: {behavior['unique_paths_accessed']}
- Scan Detected: {behavior['scan_detected']}
- Malicious Payload: {behavior['malicious_payload_detected']}
- IDS Blocked: {behavior['ids_blocked']}

# TASK
Based on this comprehensive intelligence, please provide:

1. **ATTACKER INTENT** (1-2 sentences)
   What is the attacker trying to achieve? What is their likely goal?

2. **ATTACK STAGE** (Pick one: Reconnaissance, Initial Access, Persistence, Privilege Escalation, Data Exfiltration)
   Which stage of the cyber kill chain is this attack in?

3. **SOPHISTICATION LEVEL** (Pick one: Script Kiddie, Intermediate, Advanced, APT-level)
   How sophisticated is this attacker?

4. **THREAT ASSESSMENT** (2-3 sentences)
   How dangerous is this attack? What could happen if this was a real production system?

5. **LIKELY NEXT STEPS** (3-4 bullet points)
   What will the attacker likely try next?

6. **DEFENSE RECOMMENDATIONS** (5-7 bullet points)
   Specific, actionable recommendations to defend against this type of attack.

7. **IOCs (Indicators of Compromise)** (3-5 items)
   What should we monitor/block to detect similar attacks?

IMPORTANT: You must return ONLY valid JSON. Do not include any introductory text, markdown formatting, or explanations outside the JSON object.

Format your response as JSON with these exact keys:
{{
  "intent": "...",
  "attack_stage": "...",
  "sophistication": "...",
  "threat_assessment": "...",
  "next_steps": ["...", "..."],
  "recommendations": ["...", "..."],
  "iocs": ["...", "..."]
}}

Be concise, technical, and actionable. Focus on practical defense strategies.
"""

        return prompt

    def _query_ollama(self, prompt: str, temperature: float = 0.3) -> Optional[str]:
        """
        Query Ollama LLM

        Args:
            prompt: Analysis prompt
            temperature: LLM temperature (0.0-1.0, lower = more focused)

        Returns:
            LLM response text or None if error
        """
        try:
            url = f"{self.ollama_url}/api/generate"
            payload = {
                'model': self.model,
                'prompt': prompt,
                'stream': False,
                'options': {
                    'temperature': temperature,
                    'num_ctx': 8192,  # Large context window
                    'top_p': 0.9,
                    'top_k': 40
                }
            }

            print(f"🤖 Querying LLM ({self.model})...")
            response = requests.post(url, json=payload, timeout=120)

            if response.status_code == 200:
                data = response.json()
                llm_text = data.get('response', '')
                print(f"✅ LLM analysis complete ({len(llm_text)} chars)")
                return llm_text
            else:
                print(f"❌ LLM error: HTTP {response.status_code}")
                return None

        except Exception as e:
            print(f"❌ Error querying LLM: {e}")
            return None

    def _parse_llm_response(self, llm_response: str, llm_context: Dict) -> Dict:
        """
        Parse LLM response and structure it

        Tries to extract JSON from LLM response, falls back to text parsing
        """
        try:
            # Try to extract JSON from response
            json_start = llm_response.find('{')
            json_end = llm_response.rfind('}') + 1

            if json_start != -1 and json_end > json_start:
                json_str = llm_response[json_start:json_end]
                analysis = json.loads(json_str)
            else:
                # Fallback: parse as text
                analysis = self._parse_text_response(llm_response)

            # Add metadata
            analysis['timestamp'] = datetime.now().isoformat()
            analysis['llm_model'] = self.model
            analysis['attacker_ip'] = llm_context['attacker_profile']['ip_address']
            analysis['raw_llm_response'] = llm_response[:500]  # First 500 chars

            return analysis

        except Exception as e:
            print(f"⚠️  Error parsing LLM response: {e}")
            return self._fallback_analysis(llm_context)

    def _parse_text_response(self, text: str) -> Dict:
        """
        Parse non-JSON LLM response

        Extracts information from freeform text
        """
        analysis = {
            'intent': 'Unknown',
            'attack_stage': 'Unknown',
            'sophistication': 'Unknown',
            'threat_assessment': text[:200],  # First 200 chars
            'next_steps': [],
            'recommendations': [],
            'iocs': []
        }

        # Try to extract sections
        lines = text.split('\n')
        current_section = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Detect sections
            if 'INTENT' in line.upper() or 'GOAL' in line.upper():
                current_section = 'intent'
            elif 'STAGE' in line.upper():
                current_section = 'attack_stage'
            elif 'SOPHISTICATION' in line.upper():
                current_section = 'sophistication'
            elif 'ASSESSMENT' in line.upper():
                current_section = 'threat_assessment'
            elif 'NEXT STEPS' in line.upper():
                current_section = 'next_steps'
            elif 'RECOMMENDATION' in line.upper() or 'DEFENSE' in line.upper():
                current_section = 'recommendations'
            elif 'IOC' in line.upper() or 'INDICATOR' in line.upper():
                current_section = 'iocs'
            elif current_section:
                # Add content to current section
                if current_section in ['next_steps', 'recommendations', 'iocs']:
                    if line.startswith(('-', '*', '•', '1.', '2.', '3.')):
                        analysis[current_section].append(line.lstrip('-*•123456789. '))
                elif isinstance(analysis[current_section], str):
                    analysis[current_section] = line

        return analysis

    def _fallback_analysis(self, llm_context: Dict) -> Dict:
        """
        Fallback rule-based analysis when LLM is unavailable
        """
        attacker = llm_context['attacker_profile']
        attack = llm_context['attack_details']
        behavior = llm_context['behavioral_indicators']

        # Determine attack stage
        techniques = attack['attack_technique']
        attack_stage = 'Unknown'
        for stage, patterns in self.attack_patterns.items():
            if any(t in patterns for t in techniques):
                attack_stage = stage.replace('_', ' ').title()
                break

        # Determine sophistication
        reputation = attacker['reputation_score']
        if reputation >= 80:
            sophistication = 'Advanced'
        elif reputation >= 60:
            sophistication = 'Intermediate'
        else:
            sophistication = 'Script Kiddie'

        # Build analysis
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'llm_model': 'rule_based_fallback',
            'attacker_ip': attacker['ip_address'],
            'intent': f"Attacker using {attack['attack_tool']} to perform {', '.join(techniques)}",
            'attack_stage': attack_stage,
            'sophistication': sophistication,
            'threat_assessment': f"Threat level: {attacker['threat_level']}. Reputation score: {reputation}/100.",
            'next_steps': [
                'Continue reconnaissance',
                'Attempt exploitation',
                'Establish persistence'
            ],
            'recommendations': [
                'Block attacker IP',
                'Update firewall rules',
                'Monitor for similar patterns',
                'Review access logs',
                'Implement rate limiting'
            ],
            'iocs': [
                f"IP: {attacker['ip_address']}",
                f"User-Agent: {attack['user_agent'][:50]}",
                f"Attack Tool: {attack['attack_tool']}"
            ]
        }

        return analysis

    def generate_defense_playbook(self, llm_context: Dict, analysis: Dict) -> Dict:
        """
        Generate detailed defense playbook based on LLM analysis

        Creates actionable steps for:
        - Immediate response
        - Short-term mitigation
        - Long-term prevention
        """
        playbook = {
            'timestamp': datetime.now().isoformat(),
            'attacker_ip': llm_context['attacker_profile']['ip_address'],
            'threat_level': llm_context['attacker_profile']['threat_level'],
            'immediate_actions': [],
            'short_term_mitigation': [],
            'long_term_prevention': [],
            'monitoring_requirements': []
        }

        # Immediate actions based on threat level
        threat_level = llm_context['attacker_profile']['threat_level']
        if threat_level in ['critical', 'high']:
            playbook['immediate_actions'].extend([
                f"🚨 BLOCK IP: {llm_context['attacker_profile']['ip_address']} immediately",
                "🔒 Enable rate limiting on affected endpoints",
                "📊 Review all logs from this IP for compromise indicators",
                "🔍 Check for successful exploitation attempts",
                "📧 Alert security team immediately"
            ])
        elif threat_level == 'medium':
            playbook['immediate_actions'].extend([
                f"⚠️  Monitor IP: {llm_context['attacker_profile']['ip_address']}",
                "📊 Increase logging verbosity for this IP",
                "🔍 Review recent activity for escalation"
            ])

        # Short-term mitigation
        playbook['short_term_mitigation'].extend(analysis.get('recommendations', []))

        # Add specific mitigations based on attack type
        attack_tool = llm_context['attack_details']['attack_tool']
        if attack_tool in ['nmap', 'masscan']:
            playbook['short_term_mitigation'].append("Implement port scan detection and blocking")
        elif attack_tool in ['sqlmap', 'sql_injection']:
            playbook['short_term_mitigation'].append("Deploy WAF with SQL injection rules")
        elif attack_tool in ['hydra', 'medusa', 'brute_force']:
            playbook['short_term_mitigation'].append("Implement account lockout policies")

        # Long-term prevention
        playbook['long_term_prevention'] = [
            "Conduct regular vulnerability assessments",
            "Implement zero-trust architecture",
            "Deploy advanced threat detection (SIEM/EDR)",
            "Regular security awareness training",
            "Maintain updated threat intelligence feeds",
            "Implement defense-in-depth strategy"
        ]

        # Monitoring requirements
        playbook['monitoring_requirements'] = [
            f"Monitor all traffic from ASN: {llm_context['attacker_profile']['infrastructure']['asn']}",
            f"Watch for User-Agent: {llm_context['attack_details']['user_agent'][:50]}...",
            f"Alert on attack techniques: {', '.join(llm_context['attack_details']['attack_technique'])}",
            "Track similar behavior patterns from other IPs"
        ]

        # Add IOCs
        playbook['iocs'] = analysis.get('iocs', [])

        return playbook

    def test_connection(self) -> bool:
        """Test Ollama connection"""
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                print(f"✅ Ollama connected. Available models: {len(models)}")
                return True
            return False
        except Exception as e:
            print(f"❌ Ollama connection failed: {e}")
            return False


def main():
    """Test LLM analyzer"""
    print("Testing LLM Attack Analyzer...")

    analyzer = LLMAttackAnalyzer()

    # Test connection
    if not analyzer.test_connection():
        print("⚠️  Ollama not available, will use rule-based fallback")

    # Example context (simulated)
    test_context = {
        'attacker_profile': {
            'ip_address': '45.67.89.10',
            'reputation_score': 85,
            'threat_level': 'high',
            'location': {
                'country': 'Russia',
                'city': 'Moscow',
                'isp': 'Unknown',
                'organization': 'Digital Ocean'
            },
            'infrastructure': {
                'is_known_scanner': True,
                'is_vpn_proxy': False,
                'is_tor_exit': False,
                'is_cloud': True,
                'asn': 'AS14061'
            },
            'attack_history': {
                'abuse_reports': 47,
                'last_reported': '2025-11-15',
                'confidence_score': 90
            }
        },
        'attack_details': {
            'timestamp': datetime.now().isoformat(),
            'attack_tool': 'sqlmap',
            'attack_technique': ['sql_injection', 'database_enumeration'],
            'target_path': '/api/users',
            'http_method': 'GET',
            'user_agent': 'sqlmap/1.8#stable',
            'payload': {
                'query_string': {'search': "admin' OR 1=1--"},
                'form_data': {},
                'files': []
            }
        },
        'technical_intelligence': {
            'open_ports': [22, 80, 443, 3306],
            'operating_system': 'Linux',
            'vulnerabilities': ['CVE-2023-12345'],
            'tags': ['scanner', 'malicious']
        },
        'behavioral_indicators': {
            'request_rate': 15.5,
            'failed_auth_attempts': 0,
            'unique_paths_accessed': 12,
            'scan_detected': True,
            'malicious_payload_detected': True,
            'ids_blocked': False
        }
    }

    # Run analysis
    analysis = analyzer.analyze_attack_intent(test_context)

    print("\n" + "="*60)
    print("ANALYSIS RESULT")
    print("="*60)
    print(json.dumps(analysis, indent=2))

    # Generate playbook
    playbook = analyzer.generate_defense_playbook(test_context, analysis)

    print("\n" + "="*60)
    print("DEFENSE PLAYBOOK")
    print("="*60)
    print(json.dumps(playbook, indent=2))


if __name__ == "__main__":
    main()
