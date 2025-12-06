"""
YARA Pattern Matching Analyzer
Scans packet payloads against YARA rules for malware/exploit detection
"""

import os
import time
import threading
import queue
from typing import Optional, Dict, Any, List
from pathlib import Path

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("WARNING: yara-python not installed. Pattern matching disabled.")


class YaraAnalyzer:
    """
    YARA-based pattern matching for payload analysis
    
    Features:
    - Load rules from directory
    - Real-time payload scanning
    - Match caching for performance
    - Custom rule support
    """
    
    def __init__(self, rules_dir: str = None, enabled: bool = True):
        """
        Initialize YARA analyzer
        
        Args:
            rules_dir: Directory containing YARA rule files
            enabled: Whether analyzer is enabled
        """
        self.enabled = enabled and YARA_AVAILABLE
        
        # Default rules directory
        if rules_dir is None:
            self.rules_dir = Path(__file__).parent.parent / 'rules'
        else:
            self.rules_dir = Path(rules_dir)
            
        self.compiled_rules = None
        self.match_cache = {}  # Cache matches by payload hash
        self.cache_max_size = 10000
        self._lock = threading.Lock()
        
        # Stats
        self.stats = {
            'scans': 0,
            'matches': 0,
            'cache_hits': 0,
            'errors': 0
        }
        
        if self.enabled:
            self._load_rules()
            
    def _load_rules(self):
        """Load and compile all YARA rules from rules directory"""
        if not self.rules_dir.exists():
            print(f"Creating YARA rules directory: {self.rules_dir}")
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            self._create_default_rules()
            
        rule_files = {}
        
        # Find all .yar files
        for yar_file in self.rules_dir.glob('*.yar'):
            try:
                rule_files[yar_file.stem] = str(yar_file)
            except Exception as e:
                print(f"Error loading rule file {yar_file}: {e}")
                
        if not rule_files:
            print("No YARA rules found, creating defaults...")
            self._create_default_rules()
            # Retry loading
            for yar_file in self.rules_dir.glob('*.yar'):
                rule_files[yar_file.stem] = str(yar_file)
                
        try:
            if rule_files:
                self.compiled_rules = yara.compile(filepaths=rule_files)
                print(f"Loaded {len(rule_files)} YARA rule files")
            else:
                print("WARNING: No YARA rules available")
        except yara.Error as e:
            print(f"YARA compile error: {e}")
            self.enabled = False
            
    def _create_default_rules(self):
        """Create default YARA rules"""
        
        # Malware/Suspicious patterns
        malware_rules = '''
rule Suspicious_Shell_Commands {
    meta:
        description = "Detects shell command injection attempts"
        threat_level = 7
    strings:
        $cmd1 = "/bin/sh" nocase
        $cmd2 = "/bin/bash" nocase
        $cmd3 = "cmd.exe" nocase
        $cmd4 = "powershell" nocase
        $cmd5 = "wget " nocase
        $cmd6 = "curl " nocase
        $cmd7 = "nc -e" nocase
        $cmd8 = "netcat" nocase
    condition:
        any of them
}

rule Webshell_Indicators {
    meta:
        description = "Detects common webshell patterns"
        threat_level = 9
    strings:
        $php1 = "<?php eval(" nocase
        $php2 = "base64_decode($_" nocase
        $php3 = "system($_GET" nocase
        $php4 = "passthru(" nocase
        $php5 = "shell_exec(" nocase
        $asp1 = "<%eval" nocase
        $asp2 = "execute(" nocase
    condition:
        any of them
}

rule SQL_Injection_Attempt {
    meta:
        description = "Detects SQL injection patterns"
        threat_level = 6
    strings:
        $sqli1 = "' OR '1'='1" nocase
        $sqli2 = "' OR 1=1" nocase
        $sqli3 = "UNION SELECT" nocase
        $sqli4 = "'; DROP TABLE" nocase
        $sqli5 = "1; DROP" nocase
        $sqli6 = "' AND '1'='1" nocase
    condition:
        any of them
}

rule XSS_Attempt {
    meta:
        description = "Detects XSS attack patterns"
        threat_level = 5
    strings:
        $xss1 = "<script>" nocase
        $xss2 = "javascript:" nocase
        $xss3 = "onerror=" nocase
        $xss4 = "onload=" nocase
        $xss5 = "onclick=" nocase
    condition:
        any of them
}
'''

        # Exploit patterns
        exploit_rules = '''
rule Log4Shell_Attempt {
    meta:
        description = "Detects Log4j/Log4Shell exploitation attempts"
        threat_level = 10
        cve = "CVE-2021-44228"
    strings:
        $jndi1 = "${jndi:" nocase
        $jndi2 = "${jndi:ldap:" nocase
        $jndi3 = "${jndi:rmi:" nocase
        $jndi4 = "${jndi:dns:" nocase
        $obfuscated1 = "${${lower:" nocase
        $obfuscated2 = "${${upper:" nocase
    condition:
        any of them
}

rule Path_Traversal {
    meta:
        description = "Detects path traversal attempts"
        threat_level = 7
    strings:
        $path1 = "../../../" nocase
        $path2 = "..\\\\..\\\\..\\\\"\
        $path3 = "%2e%2e%2f" nocase
        $path4 = "....//....//"\
        $path5 = "/etc/passwd"
        $path6 = "\\\\windows\\\\system32"
    condition:
        any of them
}

rule Remote_Code_Execution {
    meta:
        description = "Detects RCE attempt patterns"
        threat_level = 10
    strings:
        $rce1 = ";cat /etc/passwd"
        $rce2 = "|cat /etc"
        $rce3 = "`id`"
        $rce4 = "$(id)"
        $rce5 = "| whoami"
        $rce6 = "; whoami"
    condition:
        any of them
}
'''

        # Reconnaissance patterns
        recon_rules = '''
rule Scanner_User_Agent {
    meta:
        description = "Detects known scanner user agents"
        threat_level = 4
    strings:
        $ua1 = "Nmap" nocase
        $ua2 = "Nikto" nocase
        $ua3 = "sqlmap" nocase
        $ua4 = "gobuster" nocase
        $ua5 = "dirbuster" nocase
        $ua6 = "wfuzz" nocase
        $ua7 = "masscan" nocase
        $ua8 = "zgrab" nocase
        $ua9 = "nuclei" nocase
    condition:
        any of them
}

rule Credential_Theft {
    meta:
        description = "Detects credential harvesting attempts"
        threat_level = 8
    strings:
        $cred1 = "password=" nocase
        $cred2 = "passwd=" nocase
        $cred3 = "credentials" nocase
        $cred4 = "authorization:" nocase
        $cred5 = "apikey=" nocase
        $cred6 = "api_key=" nocase
        $cred7 = "secret=" nocase
    condition:
        2 of them
}
'''

        # Write rule files
        (self.rules_dir / 'malware.yar').write_text(malware_rules)
        (self.rules_dir / 'exploits.yar').write_text(exploit_rules)
        (self.rules_dir / 'recon.yar').write_text(recon_rules)
        
        print(f"Created default YARA rules in {self.rules_dir}")
        
    def scan(self, data: bytes, src_ip: str = None) -> List[Dict[str, Any]]:
        """
        Scan data against YARA rules
        
        Args:
            data: Bytes to scan
            src_ip: Source IP for logging
            
        Returns:
            List of matches with rule info
        """
        if not self.enabled or not self.compiled_rules:
            return []
            
        self.stats['scans'] += 1
        
        # Check cache first
        data_hash = hash(data)
        with self._lock:
            if data_hash in self.match_cache:
                self.stats['cache_hits'] += 1
                return self.match_cache[data_hash]
                
        matches = []
        try:
            yara_matches = self.compiled_rules.match(data=data)
            
            for match in yara_matches:
                match_info = {
                    'rule': match.rule,
                    'meta': dict(match.meta) if match.meta else {},
                    'strings': [(s.offset, s.identifier, s.instances) 
                               for s in match.strings] if match.strings else [],
                    'tags': list(match.tags) if match.tags else [],
                    'timestamp': time.time(),
                    'src_ip': src_ip
                }
                matches.append(match_info)
                
            if matches:
                self.stats['matches'] += len(matches)
                
            # Cache result
            with self._lock:
                if len(self.match_cache) >= self.cache_max_size:
                    # Clear oldest entries
                    keys = list(self.match_cache.keys())[:1000]
                    for k in keys:
                        del self.match_cache[k]
                self.match_cache[data_hash] = matches
                
        except yara.Error as e:
            self.stats['errors'] += 1
            print(f"YARA scan error: {e}")
            
        return matches
        
    def scan_packet(self, packet) -> List[Dict[str, Any]]:
        """
        Scan a scapy packet's payload
        
        Args:
            packet: Scapy packet object
            
        Returns:
            List of YARA matches
        """
        if not self.enabled:
            return []
            
        try:
            # Extract payload
            if packet.haslayer('Raw'):
                payload = bytes(packet['Raw'].load)
                src_ip = packet['IP'].src if packet.haslayer('IP') else None
                return self.scan(payload, src_ip)
        except Exception as e:
            self.stats['errors'] += 1
            
        return []
        
    def reload_rules(self):
        """Reload YARA rules from disk"""
        self.match_cache.clear()
        self._load_rules()
        
    def get_stats(self) -> Dict[str, int]:
        """Get scanning statistics"""
        return dict(self.stats)
        
    def add_rule(self, name: str, content: str) -> bool:
        """
        Add a new YARA rule
        
        Args:
            name: Rule file name (without .yar extension)
            content: YARA rule content
            
        Returns:
            True if successful
        """
        try:
            # Validate rule syntax first
            yara.compile(source=content)
            
            # Write to file
            rule_path = self.rules_dir / f'{name}.yar'
            rule_path.write_text(content)
            
            # Reload all rules
            self.reload_rules()
            return True
            
        except yara.Error as e:
            print(f"Invalid YARA rule: {e}")
            return False
