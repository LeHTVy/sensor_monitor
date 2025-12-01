import re

class ToolDetector:
    def __init__(self):
        self.signatures = {
            # SQL Injection Tools
            'sqlmap': [
                r'sqlmap',
                r'union.*select',
                r'AND 1=1',
                r'information_schema'
            ],
            
            # Network Scanners
            'nmap': [
                r'\bnmap\b',  # Word boundary - must be standalone word
                r'Nmap Scripting Engine',
                r'nmap/\d'  # nmap with version number
            ],
            'masscan': [
                r'masscan'
            ],
            'shodan': [
                r'Shodan',
                r'shodan'
            ],
            'censys': [
                r'Censys',
                r'censys'
            ],
            
            # Web Vulnerability Scanners
            'nikto': [
                r'Nikto',
                r'nikto'
            ],
            'nuclei': [
                r'Nuclei',
                r'nuclei',
                r'projectdiscovery'
            ],
            'acunetix': [
                r'Acunetix',
                r'acunetix',
                r'Acunetix-Aspect',
                r'acunetix_wvs_security_test'
            ],
            'skipfish': [
                r'skipfish',
                r'Skipfish'
            ],
            'w3af': [
                r'w3af',
                r'w3af.org'
            ],
            
            # Directory/File Brute Force
            'gobuster': [
                r'gobuster'
            ],
            'dirbuster': [
                r'DirBuster'
            ],
            'dirb': [
                r'\bdirb\b',
                r'DIRB'
            ],
            'ffuf': [
                r'ffuf',
                r'Fuzz Faster U Fool'
            ],
            
            # Password Cracking
            'hydra': [
                r'hydra',
                r'THC-Hydra'
            ],
            
            # Web Proxies
            'burpsuite': [
                r'burp suite',
                r'BurpSuite',
                r'Burp'
            ],
            'zaproxy': [
                r'zaproxy',
                r'OWASP ZAP',
                r'ZAP/'
            ],
            
            # Exploitation Frameworks
            'metasploit': [
                r'metasploit',
                r'meterpreter',
                r'Metasploit'
            ],
            'beef': [
                r'BeEF',
                r'beef',
                r'Browser Exploitation Framework'
            ],
            'cobaltstrike': [
                r'Cobalt Strike',
                r'cobaltstrike',
                r'beacon'
            ],
            
            # Fuzzing Tools
            'wfuzz': [
                r'Wfuzz',
                r'wfuzz'
            ],
            
            # Command Injection
            'commix': [
                r'commix',
                r'Commix'
            ],
            
            # XSS Tools
            'xsstrike': [
                r'XSStrike',
                r'xsstrike'
            ],
            
            # Command-Line Tools
            'curl': [
                r'curl/'
            ],
            'wget': [
                r'wget/'
            ],
            'python-requests': [
                r'python-requests',
                r'requests/'
            ],
            
            # Web Browsers (for filtering)
            'web browser': [
                r'Mozilla/.*Chrome/',
                r'Mozilla/.*Firefox/',
                r'Mozilla/.*Safari/',
                r'Mozilla/.*Edge/',
                r'Mozilla/.*Edg/',
                r'Opera/',
                r'Chrome/',
                r'Safari/',
                r'Firefox/'
            ]
        }
        
        # Compile regexes for performance
        self.compiled_signatures = {
            tool: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
            for tool, patterns in self.signatures.items()
        }

    def detect(self, log_data):
        """
        Detect tool from log data
        Returns: tool_name (str) or 'unknown'
        """
        user_agent = log_data.get('user_agent', '')
        
        # First, check if it's a legitimate browser (before checking attack tools)
        # This prevents browsers from being misidentified as attack tools
        if user_agent:
            # Check for web browsers specifically
            if 'web browser' in self.compiled_signatures:
                for pattern in self.compiled_signatures['web browser']:
                    if pattern.search(user_agent):
                        # Make sure it's not also curl/wget/python disguised as browser
                        if not any(x in user_agent.lower() for x in ['curl', 'wget', 'python-requests', 'scanner', 'bot']):
                            return 'web browser'
        
        # Check User-Agent for attack tools
        if user_agent:
            for tool, patterns in self.compiled_signatures.items():
                if tool == 'web browser':  # Skip browser check, already done
                    continue
                for pattern in patterns:
                    if pattern.search(user_agent):
                        return tool

        # Check Payload/Message
        payload = log_data.get('payload', '') or log_data.get('message', '')
        if isinstance(payload, dict):
            payload = str(payload)
            
        if payload:
            for tool, patterns in self.compiled_signatures.items():
                if tool == 'web browser':  # Don't check payload for browsers
                    continue
                for pattern in patterns:
                    if pattern.search(payload):
                        return tool
                        
        # Check URL/Path
        path = log_data.get('path', '') or log_data.get('url', '')
        if path:
            for tool, patterns in self.compiled_signatures.items():
                if tool == 'web browser':  # Don't check path for browsers
                    continue
                for pattern in patterns:
                    if pattern.search(path):
                        return tool

        return 'unknown'
