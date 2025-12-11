#!/usr/bin/env python3
"""
Static Malware Analyzer
Performs safe, read-only analysis of uploaded files without execution.
Uses: file, exiftool, strings, binwalk, yara, oletools, pdfid
"""

import os
import subprocess
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class StaticAnalyzer:
    """
    Safe static file analysis - NO EXECUTION
    All tools only read file bytes, never execute.
    """
    
    def __init__(self, yara_rules_path: str = '/app/yara_rules'):
        self.yara_rules_path = yara_rules_path
        self.yara_rules = None
        self._load_yara_rules()
    
    def _load_yara_rules(self):
        """Load YARA rules from directory"""
        try:
            import yara
            rules_dir = Path(self.yara_rules_path)
            if rules_dir.exists():
                yar_files = list(rules_dir.glob('**/*.yar')) + list(rules_dir.glob('**/*.yara'))
                if yar_files:
                    filepaths = {f.stem: str(f) for f in yar_files}
                    self.yara_rules = yara.compile(filepaths=filepaths)
                    logger.info(f"✅ Loaded {len(yar_files)} YARA rule files")
        except Exception as e:
            logger.warning(f"⚠️ Could not load YARA rules: {e}")
    
    def _run_cmd(self, cmd: List[str], timeout: int = 30) -> str:
        """Run command safely with timeout"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return f"[timeout after {timeout}s]"
        except Exception as e:
            return f"[error: {e}]"
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive static analysis on a file.
        Returns analysis results as dictionary.
        """
        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {file_path}"}
        
        logger.info(f"🔍 Analyzing file: {path.name}")
        
        analysis = {
            "filename": path.name,
            "filepath": str(path),
            "analyzed_at": datetime.now().isoformat(),
            "file_size": path.stat().st_size,
        }
        
        # 1. Calculate hashes
        analysis["hashes"] = self._calculate_hashes(path)
        
        # 2. Detect file type (magic bytes)
        analysis["file_type"] = self._detect_file_type(path)
        
        # 3. Extract metadata
        analysis["metadata"] = self._extract_metadata(path)
        
        # 4. Extract strings
        analysis["strings"] = self._extract_strings(path)
        
        # 5. Analyze with binwalk
        analysis["binwalk"] = self._analyze_binwalk(path)
        
        # 6. YARA scan
        analysis["yara_matches"] = self._scan_yara(path)
        
        # 7. Office document analysis (if applicable)
        if self._is_office_doc(path):
            analysis["oletools"] = self._analyze_office(path)
        
        # 8. PDF analysis (if applicable)
        if self._is_pdf(path):
            analysis["pdf_analysis"] = self._analyze_pdf(path)
        
        # 9. Calculate risk score
        analysis["risk_score"] = self._calculate_risk_score(analysis)
        analysis["risk_level"] = self._get_risk_level(analysis["risk_score"])
        
        logger.info(f"✅ Analysis complete: {path.name} - Risk: {analysis['risk_level']} ({analysis['risk_score']}/100)")
        
        return analysis
    
    def _calculate_hashes(self, path: Path) -> Dict[str, str]:
        """Calculate MD5, SHA1, SHA256 hashes"""
        data = path.read_bytes()
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()
        }
    
    def _detect_file_type(self, path: Path) -> Dict[str, str]:
        """Detect file type using magic bytes"""
        result = {
            "extension": path.suffix.lower(),
            "magic": self._run_cmd(["file", "-b", str(path)]),
            "mime": self._run_cmd(["file", "-b", "--mime-type", str(path)])
        }
        
        # Check for extension mismatch (suspicious!)
        mime = result["mime"]
        ext = result["extension"]
        result["extension_mismatch"] = self._check_extension_mismatch(ext, mime)
        
        return result
    
    def _check_extension_mismatch(self, ext: str, mime: str) -> bool:
        """Check if file extension matches MIME type"""
        expected = {
            ".jpg": ["image/jpeg"],
            ".jpeg": ["image/jpeg"],
            ".png": ["image/png"],
            ".gif": ["image/gif"],
            ".pdf": ["application/pdf"],
            ".txt": ["text/plain"],
            ".php": ["text/x-php", "text/plain"],
            ".exe": ["application/x-dosexec", "application/x-executable"],
            ".sh": ["text/x-shellscript", "text/plain"],
            ".py": ["text/x-python", "text/plain"],
        }
        
        if ext in expected:
            return not any(m in mime for m in expected[ext])
        return False
    
    def _extract_metadata(self, path: Path) -> Dict[str, Any]:
        """Extract metadata using exiftool"""
        output = self._run_cmd(["exiftool", "-j", str(path)])
        try:
            data = json.loads(output)
            return data[0] if data else {}
        except:
            return {"raw": output}
    
    def _extract_strings(self, path: Path) -> Dict[str, Any]:
        """Extract readable strings and find suspicious patterns"""
        output = self._run_cmd(["strings", "-a", str(path)])
        lines = output.split('\n')[:500]  # Limit to 500 lines
        
        suspicious_patterns = {
            "urls": r'https?://[^\s<>"]+',
            "ip_addresses": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            "emails": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "shell_commands": r'(wget|curl|chmod|bash|sh\s|eval|exec|system|popen)',
            "suspicious_apis": r'(VirtualAlloc|WinExec|CreateProcess|ShellExecute|LoadLibrary)',
            "base64_blocks": r'[A-Za-z0-9+/]{50,}={0,2}',
            "registry_keys": r'HKEY_[A-Z_]+\\',
        }
        
        found = {}
        for name, pattern in suspicious_patterns.items():
            matches = list(set(re.findall(pattern, output, re.IGNORECASE)))[:20]
            if matches:
                found[name] = matches
        
        return {
            "total_strings": len(lines),
            "suspicious_patterns": found,
            "sample": lines[:50]  # First 50 strings
        }
    
    def _analyze_binwalk(self, path: Path) -> Dict[str, Any]:
        """Analyze file with binwalk for embedded content"""
        output = self._run_cmd(["binwalk", str(path)])
        lines = [l for l in output.split('\n') if l.strip()]
        
        return {
            "embedded_files": len(lines) - 1 if lines else 0,  # Subtract header line
            "details": lines[:20]
        }
    
    def _scan_yara(self, path: Path) -> List[Dict[str, str]]:
        """Scan file with YARA rules"""
        if not self.yara_rules:
            return []
        
        try:
            matches = self.yara_rules.match(str(path))
            return [
                {
                    "rule": match.rule,
                    "tags": list(match.tags),
                    "meta": dict(match.meta) if match.meta else {}
                }
                for match in matches
            ]
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            return []
    
    def _is_office_doc(self, path: Path) -> bool:
        """Check if file is an Office document"""
        ext = path.suffix.lower()
        return ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf']
    
    def _analyze_office(self, path: Path) -> Dict[str, Any]:
        """Analyze Office documents for macros"""
        result = {
            "has_macros": False,
            "vba_code": [],
            "auto_exec": [],
            "suspicious_keywords": []
        }
        
        try:
            # Use oletools
            output = self._run_cmd(["python", "-m", "oletools.mraptor", str(path)])
            result["mraptor"] = output
            
            # Check for VBA
            vba_output = self._run_cmd(["python", "-m", "oletools.olevba", str(path)])
            if "VBA" in vba_output or "Macro" in vba_output:
                result["has_macros"] = True
                result["vba_summary"] = vba_output[:2000]
                
                # Check for auto-execute
                if any(x in vba_output for x in ['AutoOpen', 'AutoExec', 'Auto_Open', 'Workbook_Open']):
                    result["auto_exec"] = ["Auto-execute macro detected!"]
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _is_pdf(self, path: Path) -> bool:
        """Check if file is a PDF"""
        return path.suffix.lower() == '.pdf'
    
    def _analyze_pdf(self, path: Path) -> Dict[str, Any]:
        """Analyze PDF for malicious content"""
        result = {
            "has_javascript": False,
            "has_embedded": False,
            "suspicious_elements": []
        }
        
        try:
            output = self._run_cmd(["python", "-m", "pdfid.pdfid", str(path)])
            result["pdfid_output"] = output
            
            # Parse suspicious elements
            suspicious = ['/JavaScript', '/JS', '/OpenAction', '/AA', '/Launch', '/EmbeddedFile']
            for element in suspicious:
                if element in output:
                    count_match = re.search(f'{element}\\s+(\\d+)', output)
                    if count_match and int(count_match.group(1)) > 0:
                        result["suspicious_elements"].append(element)
                        if element in ['/JavaScript', '/JS']:
                            result["has_javascript"] = True
                        if element == '/EmbeddedFile':
                            result["has_embedded"] = True
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _calculate_risk_score(self, analysis: Dict) -> int:
        """Calculate risk score from 0-100"""
        score = 0
        
        # YARA matches (high risk)
        yara_matches = analysis.get("yara_matches", [])
        score += min(len(yara_matches) * 25, 50)
        
        # Extension mismatch (suspicious)
        if analysis.get("file_type", {}).get("extension_mismatch"):
            score += 20
        
        # Suspicious strings
        suspicious = analysis.get("strings", {}).get("suspicious_patterns", {})
        if suspicious.get("shell_commands"):
            score += 15
        if suspicious.get("suspicious_apis"):
            score += 15
        if suspicious.get("urls"):
            score += 5
        if suspicious.get("base64_blocks"):
            score += 10
        
        # Office macros
        oletools = analysis.get("oletools", {})
        if oletools.get("has_macros"):
            score += 20
        if oletools.get("auto_exec"):
            score += 30
        
        # PDF threats
        pdf = analysis.get("pdf_analysis", {})
        if pdf.get("has_javascript"):
            score += 25
        if pdf.get("suspicious_elements"):
            score += len(pdf["suspicious_elements"]) * 5
        
        # Embedded files
        binwalk = analysis.get("binwalk", {})
        if binwalk.get("embedded_files", 0) > 3:
            score += 10
        
        return min(score, 100)
    
    def _get_risk_level(self, score: int) -> str:
        """Convert score to risk level"""
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "CLEAN"


# Test
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyzer = StaticAnalyzer()
        result = analyzer.analyze(sys.argv[1])
        print(json.dumps(result, indent=2, default=str))
