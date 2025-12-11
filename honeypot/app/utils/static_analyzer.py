#!/usr/bin/env python3
"""
Simple Static File Analyzer for Honeypot
Performs basic static analysis on uploaded files.
Results sent via Kafka to capture server.
"""

import os
import subprocess
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SimpleStaticAnalyzer:
    """
    Lightweight static file analysis for honeypot.
    Uses: file (magic bytes), strings, basic pattern detection.
    """
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Perform static analysis on a file."""
        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {file_path}"}
        
        logger.info(f"🔍 Analyzing: {path.name}")
        
        analysis = {
            "filename": path.name,
            "filepath": str(path),
            "analyzed_at": datetime.now().isoformat(),
            "file_size": path.stat().st_size,
        }
        
        # 1. Calculate hashes
        analysis["hashes"] = self._calculate_hashes(path)
        
        # 2. Detect file type
        analysis["file_type"] = self._detect_file_type(path)
        
        # 3. Extract suspicious patterns
        analysis["suspicious_patterns"] = self._find_suspicious_patterns(path)
        
        # 4. Calculate risk score
        analysis["risk_score"] = self._calculate_risk_score(analysis)
        analysis["risk_level"] = self._get_risk_level(analysis["risk_score"])
        
        logger.info(f"✅ Analysis complete: {path.name} - Risk: {analysis['risk_level']}")
        return analysis
    
    def _calculate_hashes(self, path: Path) -> Dict[str, str]:
        """Calculate file hashes."""
        try:
            data = path.read_bytes()
            return {
                "md5": hashlib.md5(data).hexdigest(),
                "sha1": hashlib.sha1(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest()
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _detect_file_type(self, path: Path) -> Dict[str, str]:
        """Detect file type using magic bytes."""
        result = {
            "extension": path.suffix.lower(),
            "magic": "",
            "mime": ""
        }
        
        try:
            # Use file command if available
            magic_result = subprocess.run(
                ["file", "-b", str(path)],
                capture_output=True, text=True, timeout=5
            )
            result["magic"] = magic_result.stdout.strip()
            
            mime_result = subprocess.run(
                ["file", "-b", "--mime-type", str(path)],
                capture_output=True, text=True, timeout=5
            )
            result["mime"] = mime_result.stdout.strip()
        except:
            # Fallback: check magic bytes manually
            try:
                with open(path, 'rb') as f:
                    header = f.read(16)
                    
                if header.startswith(b'%PDF'):
                    result["magic"] = "PDF document"
                    result["mime"] = "application/pdf"
                elif header.startswith(b'PK'):
                    result["magic"] = "ZIP archive"
                    result["mime"] = "application/zip"
                elif header.startswith(b'\x89PNG'):
                    result["magic"] = "PNG image"
                    result["mime"] = "image/png"
                elif header.startswith(b'MZ'):
                    result["magic"] = "Windows executable"
                    result["mime"] = "application/x-dosexec"
                elif header.startswith(b'\x7fELF'):
                    result["magic"] = "ELF executable"
                    result["mime"] = "application/x-executable"
                else:
                    result["magic"] = "Unknown"
                    result["mime"] = "application/octet-stream"
            except:
                pass
        
        # Check for extension mismatch
        result["extension_mismatch"] = self._check_extension_mismatch(
            result["extension"], result["mime"]
        )
        
        return result
    
    def _check_extension_mismatch(self, ext: str, mime: str) -> bool:
        """Check if extension matches MIME type."""
        expected = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".pdf": "application/pdf",
            ".txt": "text/plain",
            ".php": "text/",
            ".exe": "application/x-",
            ".sh": "text/",
        }
        if ext in expected and expected[ext] not in mime:
            return True
        return False
    
    def _find_suspicious_patterns(self, path: Path) -> Dict[str, List[str]]:
        """Find suspicious patterns in file content."""
        patterns = {
            "shell_commands": [],
            "php_functions": [],
            "urls": [],
            "ip_addresses": [],
            "base64_blocks": []
        }
        
        try:
            # Read file as text (limit to 100KB)
            try:
                content = path.read_text(encoding='utf-8', errors='ignore')[:100000]
            except:
                content = path.read_bytes()[:100000].decode('utf-8', errors='ignore')
            
            # Shell commands
            shell_patterns = re.findall(
                r'(eval|exec|system|passthru|shell_exec|popen|proc_open|'
                r'`.*`|wget|curl|chmod|bash|/bin/sh)',
                content, re.IGNORECASE
            )
            patterns["shell_commands"] = list(set(shell_patterns))[:10]
            
            # PHP dangerous functions
            php_patterns = re.findall(
                r'(\$_(?:GET|POST|REQUEST|FILES|COOKIE)\s*\[|'
                r'base64_decode|gzuncompress|gzinflate|str_rot13)',
                content, re.IGNORECASE
            )
            patterns["php_functions"] = list(set(php_patterns))[:10]
            
            # URLs
            urls = re.findall(r'https?://[^\s<>"\']+', content)
            patterns["urls"] = list(set(urls))[:5]
            
            # IP addresses
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content)
            patterns["ip_addresses"] = list(set(ips))[:5]
            
            # Base64 blocks (potential encoded payloads)
            b64 = re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', content)
            patterns["base64_blocks"] = [b[:20] + "..." for b in b64[:3]]
            
        except Exception as e:
            logger.warning(f"Pattern extraction error: {e}")
        
        # Remove empty entries
        return {k: v for k, v in patterns.items() if v}
    
    def _calculate_risk_score(self, analysis: Dict) -> int:
        """Calculate risk score 0-100."""
        score = 0
        
        # Extension mismatch (suspicious)
        if analysis.get("file_type", {}).get("extension_mismatch"):
            score += 25
        
        # Suspicious patterns
        patterns = analysis.get("suspicious_patterns", {})
        if patterns.get("shell_commands"):
            score += len(patterns["shell_commands"]) * 10
        if patterns.get("php_functions"):
            score += len(patterns["php_functions"]) * 15
        if patterns.get("base64_blocks"):
            score += len(patterns["base64_blocks"]) * 5
        if patterns.get("urls"):
            score += len(patterns["urls"]) * 3
        
        # File type specific
        ext = analysis.get("file_type", {}).get("extension", "")
        if ext in [".php", ".sh", ".py", ".exe"]:
            score += 10  # Executable types are inherently riskier
        
        return min(score, 100)
    
    def _get_risk_level(self, score: int) -> str:
        """Convert score to risk level."""
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "CLEAN"
