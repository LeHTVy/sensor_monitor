import re

class ToolDetector:
    def __init__(self):
        self.signatures = {
            'sqlmap': [
                r'sqlmap',
                r'union.*select',
                r'AND 1=1',
                r'information_schema'
            ],
            'nmap': [
                r'nmap',
                r'Nmap Scripting Engine'
            ],
            'nikto': [
                r'Nikto',
                r'nikto'
            ],
            'gobuster': [
                r'gobuster'
            ],
            'dirbuster': [
                r'DirBuster'
            ],
            'hydra': [
                r'hydra'
            ],
            'metasploit': [
                r'metasploit',
                r'meterpreter'
            ],
            'burpsuite': [
                r'burp suite',
                r'BurpSuite'
            ],
            'zaproxy': [
                r'zaproxy',
                r'OWASP ZAP'
            ],
            'masscan': [
                r'masscan'
            ],
            'curl': [
                r'curl/'
            ],
            'wget': [
                r'wget/'
            ],
            'python-requests': [
                r'python-requests'
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
        # Check User-Agent
        user_agent = log_data.get('user_agent', '')
        if user_agent:
            for tool, patterns in self.compiled_signatures.items():
                for pattern in patterns:
                    if pattern.search(user_agent):
                        return tool

        # Check Payload/Message
        payload = log_data.get('payload', '') or log_data.get('message', '')
        if isinstance(payload, dict):
            payload = str(payload)
            
        if payload:
            for tool, patterns in self.compiled_signatures.items():
                for pattern in patterns:
                    if pattern.search(payload):
                        return tool
                        
        # Check URL/Path
        path = log_data.get('path', '') or log_data.get('url', '')
        if path:
            for tool, patterns in self.compiled_signatures.items():
                for pattern in patterns:
                    if pattern.search(path):
                        return tool

        return 'unknown'
