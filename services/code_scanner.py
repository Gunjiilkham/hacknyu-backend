import ast
import aiohttp
from bs4 import BeautifulSoup
from typing import List, Dict, Optional, Tuple, Any
from schemas.security import SecurityScanResult, SecurityRating, RiskLevel
from utils.constants import SUSPICIOUS_FUNCTIONS
import ssl
from urllib.parse import urlparse
from difflib import SequenceMatcher
from enum import Enum
from pydantic import BaseModel
import re
import tld
import hashlib
import requests
import json
import math
import traceback

class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    def __lt__(self, other):
        levels = ["safe", "low", "medium", "high", "critical"]
        return levels.index(self.value) < levels.index(other.value)

class SecurityRating(BaseModel):
    score: int
    risk_level: RiskLevel
    confidence: int

class SecurityScanResult(BaseModel):
    trustScore: int = 0
    alerts: List[str] = []
    isSuspicious: bool = False
    details: Dict[str, Any] = {}

class Rating(BaseModel):
    score: int
    risk_level: RiskLevel
    confidence: int = 90

class ScanResponse(BaseModel):
    is_suspicious: bool
    risk_level: RiskLevel
    rating: Rating
    warnings: List[str]
    details: Dict[str, str]

class CodeScanner:
    def __init__(self):
        print("Initializing CodeScanner")
        self.suspicious_functions = SUSPICIOUS_FUNCTIONS
        self.trusted_domains = {
            "python.org": "Python Official",
            "pypi.org": "PyPI Official",
            "npmjs.com": "npm Official",
            "github.com": "GitHub",
            "aws.amazon.com": "AWS Official",
            "amazonaws.com": "AWS Services",
            "awsstatic.com": "AWS Static Content",
            "amazon.com": "Amazon",
            "docs.python.org": "Python Docs",
            "packaging.python.org": "Python Packaging",
            "azure.microsoft.com": "Azure Official",
            "cloudflare.com": "Cloudflare",
            "gitlab.com": "GitLab",
            "bitbucket.org": "Bitbucket",
            "developer.mozilla.org": "MDN Web Docs",
            "learn.microsoft.com": "Microsoft Docs",
            "docs.github.com": "GitHub Docs",
            "stackoverflow.com": "Stack Overflow",
            "reactjs.org": "React Docs",
            "vuejs.org": "Vue.js Docs",
            "cdn.jsdelivr.net": "jsDelivr CDN",
            "unpkg.com": "UNPKG CDN",
            "cdnjs.cloudflare.com": "Cloudflare CDN",
            "googleapis.com": "Google APIs",
            "gstatic.com": "Google Static"
        }
        self.suspicious_tlds = ['.xyz', '.tk', '.pw', '.cc', '.su']

        # Define safe code patterns
        self.safe_code_patterns = {
            # Common CDN and framework imports
            'react.js': 'React Framework',
            'vue.js': 'Vue Framework',
            'angular.js': 'Angular Framework',
            'jquery.min.js': 'jQuery Library',
            'bootstrap.min.js': 'Bootstrap Framework',
            'analytics.js': 'Analytics Script',
            'gtag.js': 'Google Analytics',
            'ga.js': 'Google Analytics',
            'fbevents.js': 'Facebook Pixel',
            'pixel.js': 'Marketing Pixel',
        }

        # Common legitimate script patterns
        self.common_scripts = {
            'GoogleAnalytics': True,
            'gtag': True,
            'fbq': True,
            'dataLayer': True,
            'addEventListener': True,
            'querySelector': True,
            'getElementById': True,
        }

        # AI/Code Generation Sites (Medium Trust)
        self.ai_domains = {
            "v0.dev": "Vercel AI",
            "deepseek.com": "Deepseek",
            "chat.openai.com": "ChatGPT",
            "bard.google.com": "Google Bard",
            "copilot.github.com": "GitHub Copilot",
            "replit.com": "Replit",
            "colab.google.com": "Google Colab"
        }

        # Dangerous Python builtins
        self.dangerous_builtins = {
            'eval': {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Arbitrary code execution"},
            'exec': {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Code execution"},
            'globals': {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Global namespace access"},
            'locals': {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Local namespace access"},
            'getattr': {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Dynamic attribute access"},
            'setattr': {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Dynamic attribute modification"},
            'delattr': {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Dynamic attribute deletion"},
            '__import__': {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Dynamic module import"},
            'compile': {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Code compilation"},
            'input': {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: User input"}
        }

        # Dangerous modules and their risks
        self.dangerous_modules = {
            'os': {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: System access"},
            'sys': {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: System access"},
            'subprocess': {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Command execution"},
            'pickle': {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Unsafe deserialization"},
            'marshal': {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Unsafe deserialization"},
            'tempfile': {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Temporary file operations"},
            'shutil': {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: File operations"},
            'platform': {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: System information"},
            'ctypes': {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Native code execution"}
        }

        # Network-related modules
        self.network_modules = {
            'socket': {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Raw network access"},
            'ssl': {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: SSL/TLS operations"},
            'requests': {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: HTTP requests"},
            'urllib': {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: URL handling"},
            'ftplib': {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: FTP operations"},
            'telnetlib': {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Telnet operations"},
            'smtplib': {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: SMTP operations"},
            'paramiko': {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: SSH operations"}
        }

        # Dangerous shell commands
        self.dangerous_commands = {
            'rm': 'File deletion',
            'dd': 'Disk operations',
            'mkfs': 'Filesystem operations',
            'mount': 'Filesystem mounting',
            'chmod': 'Permission modification',
            'chown': 'Ownership modification',
            'sudo': 'Privileged execution',
            'su': 'User switching',
            'wget': 'File download',
            'curl': 'File download',
            'nc': 'Network operations',
            'nmap': 'Network scanning',
        }

        # Cryptocurrency-related patterns
        self.crypto_patterns = [
            r'bitcoin',
            r'ethereum',
            r'wallet\.dat',
            r'\.crypto',
            r'mining pool',
            r'miner\.exe',
            r'cryptonight',
            r'monero',
        ]

        # Data exfiltration patterns
        self.exfiltration_patterns = [
            r'\.upload\(',
            r'\.post\(',
            r'\.send\(',
            r'\.connect\(',
            r'ftp\.',
            r'\.encode\(',
            r'\.b64encode',
            r'\.hex\(',
        ]

        # Malware-related patterns
        self.malware_patterns = {
            r'\.exe': 'Executable file',
            r'\.dll': 'Dynamic library',
            r'\.sh': 'Shell script',
            r'\.bat': 'Batch file',
            r'\.ps1': 'PowerShell script',
            r'\.vbs': 'Visual Basic script',
            r'\.jar': 'Java archive',
            r'\.apk': 'Android package',
        }

        # JavaScript dangerous patterns
        self.js_dangerous_patterns = {
            "eval(": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: eval() - Arbitrary code execution"},
            "new Function(": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Function constructor - Arbitrary code execution"},
            "document.write(": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: document.write() - XSS risk"},
            "innerHTML": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: innerHTML - XSS risk"},
            "outerHTML": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: outerHTML - XSS risk"},
            "setTimeout(": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: setTimeout with string"},
            "setInterval(": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: setInterval with string"},
            "localStorage": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: localStorage access"},
            "sessionStorage": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: sessionStorage access"},
            "WebSocket(": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: WebSocket connection"},
            "document.cookie": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Cookie manipulation"}
        }

        # Shell script dangerous patterns
        self.shell_dangerous_patterns = {
            "rm -rf": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Recursive deletion"},
            "chmod 777": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Unsafe permissions"},
            "> /dev/": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Device file manipulation"},
            "dd if=": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Disk operations"},
            "mkfs": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Filesystem operations"},
            "sudo": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Privileged execution"},
            "curl": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Network download"},
            "wget": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Network download"}
        }

        # Convert suspicious_strings from set to dictionary
        self.suspicious_strings = {
            "hack": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Hacking-related term"},
            "crack": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Cracking-related term"},
            "exploit": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Exploit-related term"},
            "payload": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Payload-related term"},
            "virus": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Virus-related term"},
            "trojan": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Trojan-related term"},
            "malware": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Malware-related term"},
            "ransomware": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Ransomware-related term"},
            "keylog": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Keylogging detected"},
            "screenshot": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Screenshot functionality"},
            "webcam": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Webcam access"},
            "microphone": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Microphone access"}
        }

        # Convert malicious_payloads from set to dictionary
        self.malicious_payloads = {
            "<script>": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: XSS script tag"},
            "javascript:": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: JavaScript protocol"},
            "data:text/html": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Data URL HTML"},
            "base64": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Base64 encoding"},
            "alert(": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Alert function"},
            "UNION SELECT": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: SQL UNION injection"},
            "OR '1'='1": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: SQL injection"},
            "DROP TABLE": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: SQL DROP statement"},
            "|": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Command pipe"},
            ";": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Command chain"},
            "&&": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Command chain"}
        }

        # Risk patterns for developer-specific concerns
        self.risk_patterns = {
            # Dangerous functions
            "eval(": {"level": "CRITICAL", "message": "⚠️ Dangerous: Dynamic code execution"},
            "exec(": {"level": "CRITICAL", "message": "⚠️ Dangerous: Code execution"},
            "os.system": {"level": "HIGH", "message": "⚠️ Warning: System command execution"},
            "subprocess.run": {"level": "HIGH", "message": "⚠️ Warning: Subprocess execution"},
            
            # Suspicious imports
            "import os": {"level": "MEDIUM", "message": "⚠️ Warning: OS module imported"},
            "import subprocess": {"level": "MEDIUM", "message": "⚠️ Warning: Subprocess module imported"},
            "import requests": {"level": "LOW", "message": "⚠️ Note: Network requests enabled"},
            
            # API keys and secrets
            "api_key": {"level": "HIGH", "message": "⚠️ Warning: API key detected"},
            "secret_key": {"level": "HIGH", "message": "⚠️ Warning: Secret key detected"},
            "password": {"level": "HIGH", "message": "⚠️ Warning: Password detected"},
            
            # Suspicious URLs
            "http://": {"level": "MEDIUM", "message": "⚠️ Warning: Insecure HTTP URL detected"},
            ".tk": {"level": "HIGH", "message": "⚠️ Warning: Suspicious TLD detected"},
            "free-download": {"level": "HIGH", "message": "⚠️ Warning: Sketchy download source"},
        }

        # Add these new pattern collections:
        
        # Obfuscation techniques
        self.obfuscation_patterns = {
            # JavaScript obfuscation
            "\\x": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Hex encoded characters detected"},
            "\\u": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Unicode escape detected"},
            "atob(": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Base64 decode detected"},
            "btoa(": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Base64 encode detected"},
            "fromCharCode": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Character code conversion detected"},
            "unescape(": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: URL decode detected"},
            
            # Python obfuscation
            "encode(": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Encoding operation detected"},
            "decode(": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Decoding operation detected"},
            "chr(": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Character conversion detected"},
            "ord(": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Ordinal conversion detected"},
        }

        # Data exfiltration and collection
        self.data_theft_patterns = {
            # Browser data
            "document.cookie": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Cookie access"},
            "navigator.": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Browser info collection"},
            "screen.": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Screen info collection"},
            "geolocation": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Location access"},
            
            # System data
            "systeminfo": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: System information collection"},
            "cpuinfo": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: CPU information collection"},
            "meminfo": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Memory information collection"},
        }

        # Suspicious strings and patterns
        self.suspicious_strings = {
            # Hacking related
            "hack": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Hacking-related term"},
            "crack": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Cracking-related term"},
            "exploit": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Exploit-related term"},
            "payload": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Payload-related term"},
            
            # Malware related
            "virus": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Virus-related term"},
            "trojan": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Trojan-related term"},
            "malware": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Malware-related term"},
            "ransomware": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Ransomware-related term"},
            
            # Suspicious activities
            "keylog": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Keylogging detected"},
            "screenshot": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Screenshot functionality"},
            "webcam": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Webcam access"},
            "microphone": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Microphone access"},
        }

        # File operations
        self.file_patterns = {
            ".txt": {"level": RiskLevel.LOW, "score": -20, "message": "Low Risk: Text file operation"},
            ".log": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Log file operation"},
            ".dat": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Data file operation"},
            ".db": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Database file operation"},
            ".sql": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: SQL file operation"},
            ".conf": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Config file operation"},
            ".env": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Environment file operation"},
            "password": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Password-related operation"},
            "credential": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Credential-related operation"},
        }

        # Network and protocol patterns
        self.network_patterns = {
            "ftp://": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: FTP protocol usage"},
            "telnet://": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Telnet protocol usage"},
            "ws://": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: WebSocket usage"},
            "wss://": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Secure WebSocket usage"},
            "ssh://": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: SSH protocol usage"},
            "sftp://": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: SFTP protocol usage"},
        }

        # Add new web content patterns
        
        # Phishing indicators
        self.phishing_patterns = {
            # Login forms
            "password": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Password field detected"},
            "login": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Login form detected"},
            "signin": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Sign-in form detected"},
            
            # Payment info
            "credit card": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Credit card field detected"},
            "cvv": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: CVV field detected"},
            "expiry": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Card expiry field detected"},
            
            # Personal info
            "ssn": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: SSN field detected"},
            "social security": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Social Security field detected"},
            "passport": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Passport field detected"},
        }

        # Scam indicators
        self.scam_patterns = {
            # Financial scams
            "lottery": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Lottery scam detected"},
            "won": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Prize scam detected"},
            "prize": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Prize scam detected"},
            "million": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Financial scam detected"},
            "bank details": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Request for bank details"},
            
            # Urgency indicators
            "urgent": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Urgency indicator"},
            "act now": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Pressure tactic"},
            "limited time": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Time pressure tactic"},
            "offer expires": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Time pressure tactic"},
            
            # Common scam phrases
            "claim": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Claim-related content"},
            "send details": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Request for personal details"},
            "send money": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Request for money transfer"},
            "western union": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Money transfer service"},
            "wire transfer": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Wire transfer request"}
        }

        # Adult content indicators
        self.adult_patterns = {
            "xxx": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Adult content"},
            "porn": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Adult content"},
            "adult": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Possible adult content"},
            "18+": {"level": RiskLevel.MEDIUM, "score": -30, "message": "Medium Risk: Age-restricted content"},
        }

        # Malware distribution indicators
        self.malware_distribution = {
            "cracked": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Software crack"},
            "keygen": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Key generator"},
            "nulled": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Nulled software"},
            "warez": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Warez content"},
            "patch download": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Patch download"},
        }

        # Suspicious domains
        self.suspicious_domains = {
            # Typosquatting
            "goggle": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Possible typosquatting"},
            "faceboook": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Possible typosquatting"},
            "paypaI": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Possible typosquatting"},
            
            # Suspicious TLDs
            ".tk": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Suspicious TLD"},
            ".ml": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Suspicious TLD"},
            ".ga": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Suspicious TLD"},
        }

    def _detect_language(self, code: str) -> str:
        # JavaScript indicators
        if any(pattern in code for pattern in [
            "function", "var ", "let ", "const ", "document.", "window.",
            "addEventListener", "querySelector", "getElementById"
        ]):
            return "javascript"
        
        # Python indicators
        elif any(pattern in code for pattern in [
            "def ", "class ", "import ", "print(", "if __name__",
            "async def", "await ", "raise ", "except "
        ]):
            return "python"
        
        # Shell script indicators
        elif any(pattern in code for pattern in [
            "#!/bin/", "#!/usr/bin", "export ", "echo ", "$PATH",
            "chmod ", "chown ", "sudo ", "apt-get"
        ]):
            return "shell"
        
        # HTML indicators
        elif any(pattern in code for pattern in [
            "<!DOCTYPE", "<html", "<script", "<body", "<head"
        ]):
            return "html"
        
        return "unknown"

    async def analyze_code(self, code: str) -> SecurityScanResult:
        if not code.strip():
            return SecurityScanResult(
                trustScore=100,
                isSuspicious=False,
                alerts=[],
                details={"code_length": 0}
            )

        # Initialize score and alerts
        trust_score = 100
        alerts = {}  # Use dict to track unique alerts
        is_suspicious = False
        found_patterns = set()

        try:
            # Detect language
            language = self._detect_language(code)
            
            # JavaScript checks
            if language == "javascript":
                js_alerts = self._check_javascript(code)
                if js_alerts:
                    for alert in js_alerts:
                        # Use the alert message itself as the key to prevent duplicates
                        alerts[alert] = alert
                    trust_score -= min(len(js_alerts) * 10, 50)
                    is_suspicious = True
            
            elif language == "python":
                # Python analysis
                try:
                    tree = ast.parse(code)
                    python_alerts = self._check_python_code(tree)
                    if python_alerts:
                        for alert in python_alerts:
                            key = alert.split(":")[1].strip() if ":" in alert else alert
                            alerts[key] = alert
                        trust_score -= min(len(python_alerts) * 10, 50)  # Cap the penalty
                        is_suspicious = True
                except SyntaxError:
                    alerts["Invalid Syntax"] = "⚠️ Warning: Invalid Python syntax"
                    trust_score -= 20
                    is_suspicious = True

            # Check for obfuscation only if suspicious patterns are found
            if is_suspicious and self._detect_obfuscation(code):
                alerts["Obfuscation"] = "🚨 Critical: Obfuscated code detected"
                trust_score -= 40

            # Check for suspicious strings
            for pattern, info in self.suspicious_strings.items():
                if pattern.lower() in code.lower() and pattern not in found_patterns:
                    # Use the full message as the key to prevent duplicates
                    alerts[info["message"]] = info["message"]
                    trust_score -= min(abs(info["score"]), 30)
                    found_patterns.add(pattern)
                    is_suspicious = True

            # Check for malicious payloads
            for pattern, info in self.malicious_payloads.items():
                if pattern in code and pattern not in found_patterns:
                    key = info["message"].split(":")[1].strip() if ":" in info["message"] else info["message"]
                    alerts[key] = info["message"]
                    trust_score -= min(abs(info["score"]), 40)  # Cap individual penalties
                    found_patterns.add(pattern)
                    is_suspicious = True

            # Language-specific checks
            if language == "javascript":
                for pattern, info in self.js_dangerous_patterns.items():
                    if pattern in code and pattern not in found_patterns:
                        key = info["message"].split(":")[1].strip() if ":" in info["message"] else info["message"]
                        alerts[key] = info["message"]
                        trust_score -= min(abs(info["score"]), 30)  # Cap individual penalties
                        found_patterns.add(pattern)
                        is_suspicious = True
            elif language == "shell":
                for pattern, info in self.shell_dangerous_patterns.items():
                    if pattern in code and pattern not in found_patterns:
                        key = info["message"].split(":")[1].strip() if ":" in info["message"] else info["message"]
                        alerts[key] = info["message"]
                        trust_score -= min(abs(info["score"]), 30)  # Cap individual penalties
                        found_patterns.add(pattern)
                        is_suspicious = True

            # Ensure trust score stays within bounds
            trust_score = max(0, min(100, trust_score))

            # Convert alerts dict to sorted list
            sorted_alerts = sorted(alerts.values(), key=lambda x: (
                "Critical" in x,
                "High Risk" in x,
                "Medium Risk" in x,
                "Low Risk" in x,
                x
            ), reverse=True)

            # If no alerts but code exists, add a safe message
            if not sorted_alerts and code.strip():
                sorted_alerts = ["✅ Code appears to be safe"]
                trust_score = 100
                is_suspicious = False

            return SecurityScanResult(
                trustScore=trust_score,
                isSuspicious=is_suspicious,
                alerts=sorted_alerts,
                details={
                    "language": language,
                    "code_length": len(code),
                    "analysis_complete": True
                }
            )

        except Exception as e:
            print(f"Error in analyze_code: {str(e)}")
            return SecurityScanResult(
                trustScore=0,
                isSuspicious=True,
                alerts=[f"⚠️ Error analyzing code: {str(e)}"],
                details={"error": str(e)}
            )

    def _looks_like_code(self, content: str) -> bool:
        """Check if content looks like actual code"""
        code_indicators = [
            'function', 'var ', 'let ', 'const ',
            'class ', 'import ', 'export ',
            'def ', 'class:', 'import ',
            'return ', 'async ', 'await '
        ]
        return any(indicator in content for indicator in code_indicators)

    def _is_javascript(self, code: str) -> bool:
        """Check if code is JavaScript"""
        js_indicators = [
            'function', 'var ', 'let ', 'const ',
            'document.', 'window.', 'addEventListener',
            'querySelector', 'getElementById'
        ]
        return any(indicator in code for indicator in js_indicators)

    def _is_safe_script(self, code: str) -> bool:
        """Check if this is a known safe script"""
        code_lower = code.lower()
        # Check for common CDN scripts
        for safe_pattern in self.safe_code_patterns:
            if safe_pattern.lower() in code_lower:
                return True
        # Check for common legitimate script patterns
        return any(pattern in code for pattern in self.common_scripts)

    def _determine_code_type(self, code: str) -> str:
        """Determine the type of code more accurately"""
        if self._is_javascript(code):
            if any(cdn in code.lower() for cdn in self.safe_code_patterns):
                return "cdn_script"
            if any(pattern in code for pattern in self.common_scripts):
                return "analytics_script"
            return "javascript"
        return "unknown"

    def _check_javascript(self, code: str) -> List[str]:
        """Check JavaScript-specific security issues"""
        alerts = []
        for pattern, info in self.js_dangerous_patterns.items():
            if pattern in code:
                alerts.append(info["message"])
        return alerts

    def _is_in_comment_or_string(self, code: str, pattern: str) -> bool:
        """Check if pattern is in a comment or string"""
        lines = code.split('\n')
        for line in lines:
            if pattern in line:
                # Skip if in comment
                if '//' in line[:line.find(pattern)]:
                    return True
                # Skip if in string (basic check)
                if line.count('"') % 2 == 0 or line.count("'") % 2 == 0:
                    return True
        return False

    def _check_dangerous_functions(self, tree: ast.AST) -> List[str]:
        alerts = []
        dangerous_patterns = {
            'eval': {'risk': 'CRITICAL', 'desc': 'Code execution'},
            'exec': {'risk': 'CRITICAL', 'desc': 'Code execution'},
            'os.system': {'risk': 'HIGH', 'desc': 'System command'},
            'subprocess.run': {'risk': 'HIGH', 'desc': 'System command'},
            'subprocess.Popen': {'risk': 'HIGH', 'desc': 'System command'},
            'shell': {'risk': 'HIGH', 'desc': 'Shell command'}
        }
        
        for node in ast.walk(tree):
            # Check function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in dangerous_patterns:
                        pattern = dangerous_patterns[node.func.id]
                        alerts.append(f"⚠️ {pattern['risk']}: {pattern['desc']} ({node.func.id})")
                elif isinstance(node.func, ast.Attribute):
                    try:
                        full_name = f"{node.func.value.id}.{node.func.attr}"
                        if full_name in dangerous_patterns:
                            pattern = dangerous_patterns[full_name]
                            alerts.append(f"⚠️ {pattern['risk']}: {pattern['desc']} ({full_name})")
                    except AttributeError:
                        pass

            # Check string literals for dangerous commands
            if isinstance(node, ast.Str):
                dangerous_commands = {
                    'rm -rf': 'CRITICAL',
                    'sudo': 'HIGH',
                    'chmod 777': 'HIGH',
                    'dd if': 'HIGH'
                }
                for cmd, risk in dangerous_commands.items():
                    if cmd in node.s:
                        alerts.append(f"⚠️ {risk}: Dangerous command detected: {cmd}")

        return alerts

    def _check_suspicious_imports(self, tree: ast.AST) -> List[str]:
        alerts = []
        suspicious_modules = {'subprocess', 'os', 'sys', 'requests', 'urllib'}
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    if name.name.split('.')[0] in suspicious_modules:
                        alerts.append(f"Suspicious import: {name.name}")
        return alerts

    def _check_network_access(self, tree: ast.AST) -> List[str]:
        alerts = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Str):
                url = node.s
                if url.startswith(('http://', 'https://')):
                    # Skip warning if domain is trusted
                    domain = urlparse(url).netloc.lower()
                    if any(trusted in domain for trusted in self.trusted_domains.keys()):
                        continue
                    alerts.append(f"Network access detected: {url}")
        return alerts 

    async def scan_webpage(self, url: str) -> SecurityScanResult:
        """Scan a webpage URL for security risks."""
        try:
            if not url:
                return SecurityScanResult(
                    trustScore=0,
                    isSuspicious=True,
                    risk_level=RiskLevel.CRITICAL,
                    alerts=["⚠️ Empty URL provided"],
                    details={
                        "message": "❌ No URL provided"
                    }
                )

            alerts = []
            risk_level = RiskLevel.SAFE
            trust_score = 100  # Start with a perfect score

            # Check for HTTPS
            if not url.startswith("https://"):
                alerts.append("⚠️ Insecure connection (no HTTPS)")
                risk_level = RiskLevel.MEDIUM
                trust_score -= 20

            # Check for suspicious keywords in the URL
            suspicious_keywords = ["phishing", "scam", "fraud", "hack", "crack", "malware"]
            found_keywords = [keyword for keyword in suspicious_keywords if keyword in url.lower()]
            if found_keywords:
                alerts.append(f"⚠️ Suspicious keywords in URL: {', '.join(found_keywords)}")
                risk_level = RiskLevel.HIGH
                trust_score -= 30

            # Check for known sketchy domains
            sketchy_domains = ["goggle", "faceboook", "paypaI", "free-download", "cracked-software"]
            if any(domain in url.lower() for domain in sketchy_domains):
                alerts.append("⚠️ Known sketchy domain detected")
                risk_level = RiskLevel.CRITICAL
                trust_score -= 50

            # Check for suspicious TLDs (e.g., .tk, .ml, .ga)
            suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".xyz"]
            if any(tld in url.lower() for tld in suspicious_tlds):
                alerts.append("⚠️ Suspicious TLD detected")
                risk_level = RiskLevel.HIGH
                trust_score -= 30

            # Check for long URLs (potential obfuscation)
            if len(url) > 200:
                alerts.append("⚠️ URL is unusually long (potential obfuscation)")
                risk_level = RiskLevel.MEDIUM
                trust_score -= 20

            # Ensure trust score is within bounds
            trust_score = max(0, min(100, trust_score))

            # Determine if suspicious
            is_suspicious = len(alerts) > 0

            return SecurityScanResult(
                trustScore=trust_score,
                isSuspicious=is_suspicious,
                risk_level=risk_level,
                alerts=alerts,
                details={
                    "message": "🔍 Scan complete",
                    "url_length": len(url),
                    "found_risks": alerts
                }
            )

        except Exception as e:
            return SecurityScanResult(
                trustScore=50,
                isSuspicious=True,
                risk_level=RiskLevel.CRITICAL,
                alerts=[f"⚠️ Error: {str(e)}"],
                details={
                    "message": "❌ An error occurred during scanning"
                }
            )

    async def scan_code(self, code: str) -> SecurityScanResult:
        """Scan code for security risks specific to developers."""
        try:
            if not code:
                return SecurityScanResult(
                    trustScore=100,
                    isSuspicious=False,
                    risk_level=RiskLevel.SAFE,
                    alerts=[],
                    details={"message": "✅ No code provided"}
                )

            alerts = []
            risk_level = RiskLevel.SAFE
            trust_score = 100  # Start with perfect score

            # Check for risky patterns
            for pattern, details in self.risk_patterns.items():
                if pattern in code:
                    alerts.append(details["message"])
                    risk_level = RiskLevel(details["level"].lower())  # Convert to enum
                    trust_score -= 20  # Reduce score for each risk found

            # Check for suspicious package installs
            if "pip install" in code:
                alerts.append("⚠️ Note: Package installation detected")
                risk_level = RiskLevel.MEDIUM
                trust_score -= 10

            # Check for API calls
            if "requests.get(" in code or "requests.post(" in code:
                alerts.append("⚠️ Note: API call detected")
                risk_level = RiskLevel.MEDIUM
                trust_score -= 10

            # Ensure trust score stays within bounds
            trust_score = max(0, min(100, trust_score))

            # Determine if suspicious
            is_suspicious = len(alerts) > 0

            return SecurityScanResult(
                trustScore=trust_score,
                isSuspicious=is_suspicious,
                risk_level=risk_level,
                alerts=alerts,
                details={
                    "message": "🔍 Scan complete",
                    "code_length": len(code),
                    "found_risks": alerts
                }
            )

        except Exception as e:
            return SecurityScanResult(
                trustScore=0,
                isSuspicious=True,
                risk_level=RiskLevel.CRITICAL,
                alerts=[f"⚠️ Error: {str(e)}"],
                details={"message": "❌ An error occurred during scanning"}
            )

    def _scan_webpage(self, content: str) -> List[str]:
        """Scan webpage content"""
        alerts = []
        content_lower = content.lower()
        
        print("Scanning webpage content...")
        
        # Check for piracy indicators
        piracy_terms = ['torrent', 'piratebay', 'warez', 'crack', 'hide your ip']
        found_terms = [term for term in piracy_terms if term in content_lower]
        if found_terms:
            print(f"Found piracy terms: {found_terms}")
            alerts.extend([
                "⚠️ Warning: Potential illegal content detected",
                "⚠️ Caution: Site may distribute copyrighted material",
                "⚠️ Alert: IP address exposure risk"
            ])
        
        # Check for dangerous web content
        if '<iframe' in content_lower:
            alerts.append("⚠️ Dangerous: Contains iframes")
        if 'eval(' in content_lower:
            alerts.append("⚠️ Dangerous: Dynamic code execution")
        if '<script' in content_lower:
            alerts.append("⚠️ Dangerous: Script injection risk")
        
        print(f"Found {len(alerts)} alerts in webpage")
        return alerts if alerts else ["✅ No suspicious content detected"]

    def _scan_code_content(self, content: str) -> List[str]:
        """Scan code content"""
        alerts = []
        content_lower = content.lower()
        
        print("Scanning code content...")
        
        # Check for dangerous code patterns
        if 'eval(' in content_lower:
            alerts.append("⚠️ Dangerous: Dynamic code execution")
        if 'require(' in content_lower and ('http://' in content_lower or 'https://' in content_lower):
            alerts.append("⚠️ Warning: Remote code inclusion")
        if 'crypto' in content_lower or 'miner' in content_lower:
            alerts.append("⚠️ Critical: Potential crypto mining code")
        
        print(f"Found {len(alerts)} alerts in code")
        return alerts if alerts else ["✅ No suspicious content detected"]

    def _is_piracy_site(self, code: str) -> bool:
        """Enhanced detection of piracy-related content"""
        piracy_patterns = [
            r'torrent',
            r'download.*free',
            r'pirate.*bay', 
            r'hide.*ip',
            r'vpn.*download',
            r'proxy.*bay',
            r'magnet.*link',
            r'peer.*to.*peer'
        ]
        
        code_lower = code.lower()
        return any(re.search(pattern, code_lower) for pattern in piracy_patterns)

    def _calculate_code_quality(self, code: str) -> int:
        """Calculate code quality score"""
        quality = 100
        
        # Check for bad practices
        if 'eval(' in code:
            quality -= 30
        if 'with(' in code:
            quality -= 20
        if '== null' in code:
            quality -= 10
        
        # Check for good practices
        if 'try {' in code:
            quality += 10
        if 'const ' in code:
            quality += 5
        if 'async ' in code:
            quality += 5
        
        return max(0, min(100, quality))

    def _analyze_code_structure(self, code: str) -> dict:
        """Deep analysis of code structure"""
        structure = {
            "is_obfuscated": False,
            "has_suspicious_patterns": False,
            "entropy_score": 0.0,
            "malicious_probability": 0.0,
            "illegal_probability": 0.0
        }
        
        # Calculate entropy score
        entropy = self._calculate_entropy(code)
        structure["entropy_score"] = entropy
        
        # Check for obfuscation
        if entropy > 5.0 or re.search(r'eval\(\w+\)', code) or len(re.findall(r'\\x[0-9a-f]{2}', code)) > 5:
            structure["is_obfuscated"] = True
        
        # Calculate malicious probability
        malicious_indicators = [
            (r'eval\(', 0.4),
            (r'document\.write\(', 0.3),
            (r'\\x[0-9a-f]{2}', 0.2),
            (r'fromCharCode', 0.3),
            (r'crypto\.minergate', 0.8),
            (r'coinhive', 0.8)
        ]
        
        structure["malicious_probability"] = sum(
            weight for pattern, weight in malicious_indicators
            if re.search(pattern, code, re.IGNORECASE)
        )
        
        # Calculate illegal probability
        illegal_indicators = [
            (r'torrent', 0.6),
            (r'warez', 0.8),
            (r'cracked?', 0.7),
            (r'keygen', 0.8),
            (r'nulled', 0.7),
            (r'patch(ed)?', 0.5)
        ]
        
        structure["illegal_probability"] = sum(
            weight for pattern, weight in illegal_indicators
            if re.search(pattern, code, re.IGNORECASE)
        )
        
        return structure

    def _calculate_confidence(self, alerts: set, structure: dict) -> int:
        """Calculate confidence score based on multiple factors"""
        confidence = 90  # Base confidence
        
        # Adjust based on code structure
        if structure["entropy_score"] > 5.0:
            confidence -= 10
        if structure["is_obfuscated"]:
            confidence -= 20
        
        # Adjust based on alert count
        if len(alerts) > 10:
            confidence -= 15
        elif len(alerts) > 5:
            confidence -= 10
        
        # Adjust based on probabilities
        if structure["malicious_probability"] > 0.7:
            confidence += 10
        if structure["illegal_probability"] > 0.7:
            confidence += 10
        
        return max(0, min(100, confidence))

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of the code"""
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(chr(x)))/len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def _calculate_trust_score(self, code: str) -> int:
        """Calculate trust score based on multiple factors"""
        trust_score = 100
        
        # Check for suspicious patterns
        if re.search(r'eval\(', code):
            trust_score -= 30
        if re.search(r'document\.write\(', code):
            trust_score -= 20
        if re.search(r'\\x[0-9a-f]{2}', code):
            trust_score -= 15
        
        # Check for secure practices
        if 'https://' in code:
            trust_score += 10
        if re.search(r'npm audit|yarn audit', code):
            trust_score += 15
        
        return max(0, min(100, trust_score))

    def _check_illegal_content(self, code: str) -> dict:
        """Check for illegal and piracy-related content"""
        illegal_patterns = {
            # Piracy Indicators
            "torrent": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Torrent reference detected"},
            "warez": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Warez content detected"},
            "cracked": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Cracked software reference"},
            "keygen": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Key generator reference"},
            "nulled": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Nulled software reference"},
            "activation key": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Software activation reference"},
            
            # Streaming/Download
            "free stream": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Potential illegal streaming"},
            "watch online free": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Potential illegal streaming"},
            "download movie": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Potential illegal download"},
            
            # Software Piracy
            "crack download": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Software crack reference"},
            "patch download": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Software patch reference"},
            "license bypass": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: License bypass reference"},
        }
        
        return self._check_patterns(code, illegal_patterns)

    def _check_suspicious_content(self, code: str) -> dict:
        """Check for suspicious and potentially malicious content"""
        alerts = set()
        score_impact = 0
        risk_factors = set()
        highest_risk = RiskLevel.SAFE
        
        # Malware Indicators
        suspicious_patterns = {
            # Malware Indicators
            "malware": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Malware reference"},
            "virus": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Virus reference"},
            "trojan": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Trojan reference"},
            "botnet": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Botnet reference"},
            
            # Suspicious Behavior
            "keylogger": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Keylogger reference"},
            "screencapture": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Screen capture reference"},
            "clipboard": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Clipboard access"},
            
            # Data Theft
            "steal": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Data theft reference"},
            "exfiltrate": {"level": RiskLevel.CRITICAL, "score": -50, "message": "Critical: Data exfiltration"},
            "harvest": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Data harvesting"},
        }
        
        # Check for suspicious patterns
        pattern_result = self._check_patterns(code, suspicious_patterns)
        alerts.update(pattern_result["alerts"])
        score_impact += pattern_result["score_impact"]
        risk_factors.update(pattern_result["risk_factors"])
        highest_risk = max(highest_risk, pattern_result["risk_level"])
        
        # Check for dangerous code patterns
        code_lower = code.lower()
        if 'eval(' in code_lower:
            alerts.add("⚠️ Dangerous: Dynamic code execution")
            score_impact -= 50
            risk_factors.add("eval")
            highest_risk = max(highest_risk, RiskLevel.CRITICAL)
        
        if 'require(' in code_lower and ('http://' in code_lower or 'https://' in code_lower):
            alerts.add("⚠️ Warning: Remote code inclusion")
            score_impact -= 40
            risk_factors.add("remote_include")
            highest_risk = max(highest_risk, RiskLevel.HIGH)
        
        if 'crypto' in code_lower or 'miner' in code_lower:
            alerts.add("⚠️ Critical: Potential crypto mining code")
            score_impact -= 50
            risk_factors.add("crypto_mining")
            highest_risk = max(highest_risk, RiskLevel.CRITICAL)
        
        return {
            "alerts": alerts,
            "score_impact": score_impact,
            "risk_factors": risk_factors,
            "risk_level": highest_risk
        }

    def _calculate_category_score(self, code: str, category: str) -> int:
        """Calculate security score for a specific category"""
        base_score = 100
        
        if category == "package":
            if self._check_typosquatting(code):
                base_score -= 40
            if "npm install" in code or "pip install" in code:
                if not re.search(r'@\d+\.\d+\.\d+', code):
                    base_score -= 30
        
        elif category == "api":
            if re.search(r'api[_-]?key', code, re.IGNORECASE):
                base_score -= 50
            if "http://" in code:
                base_score -= 40
        
        elif category == "code":
            if self._detect_obfuscation(code):
                base_score -= 50
            if self._detect_crypto_mining(code):
                base_score -= 50
            if "eval(" in code or "exec(" in code:
                base_score -= 40
        
        return max(0, min(100, base_score))

    def _check_package_security(self, code: str) -> dict:
        # Implementation of _check_package_security method
        pass

    def _check_api_security(self, code: str) -> dict:
        # Implementation of _check_api_security method
        pass

    def _check_code_security(self, code: str) -> dict:
        # Implementation of _check_code_security method
        pass

    def _check_privacy_issues(self, code: str) -> dict:
        alerts = set()
        score_impact = 0
        risk_factors = set()
        highest_risk = RiskLevel.SAFE
        
        # Privacy patterns
        privacy_patterns = {
            # Data collection
            "localStorage": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Local storage usage"},
            "sessionStorage": {"level": RiskLevel.HIGH, "score": -40, "message": "High Risk: Session storage usage"},
            # ... (previous privacy patterns)
        }
        
        for pattern, risk_info in privacy_patterns.items():
            if pattern in code:
                alerts.add(risk_info["message"])
                score_impact += risk_info["score"]
                risk_factors.add(pattern)
                if risk_info["level"].value > highest_risk.value:
                    highest_risk = risk_info["level"]
        
        return {
            "alerts": alerts,
            "score_impact": score_impact,
            "risk_factors": risk_factors,
            "risk_level": highest_risk
        }

    def _detect_crypto_mining(self, code: str) -> bool:
        # Implementation of _detect_crypto_mining method
        pass

    def _check_typosquatting(self, code: str) -> bool:
        # Implementation of _check_typosquatting method
        pass

    def _analyze_ast(self, code: str) -> List[str]:
        alerts = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                # Check for dangerous function calls
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in self.dangerous_builtins:
                            alerts.append(f"Dangerous builtin used: {node.func.id} - {self.dangerous_builtins[node.func.id]}")
                
                # Check for dangerous imports
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        module = alias.name.split('.')[0]
                        if module in self.dangerous_modules:
                            alerts.append(f"Dangerous module imported: {module} - {self.dangerous_modules[module]}")
                        elif module in self.network_modules:
                            alerts.append(f"Network module imported: {module} - {self.network_modules[module]}")
                
                # Check for shell commands in strings
                elif isinstance(node, ast.Str):
                    for cmd, risk in self.dangerous_commands.items():
                        if cmd in node.s:
                            alerts.append(f"Dangerous shell command detected: {cmd} - {risk}")
        except:
            alerts.append("Could not parse code for detailed analysis")
        return alerts

    def _check_patterns(self, code: str, patterns: dict) -> dict:
        alerts = set()
        score_impact = 0
        risk_factors = set()
        highest_risk = RiskLevel.SAFE
        
        for pattern, info in patterns.items():
            if re.search(pattern, code, re.IGNORECASE):
                alerts.add(info["message"])
                score_impact += info["score"]
                risk_factors.add(pattern)
                if info["level"].value > highest_risk.value:
                    highest_risk = info["level"]
        
        return {
            "alerts": alerts,
            "score_impact": score_impact,
            "risk_factors": risk_factors,
            "risk_level": highest_risk
        }

    def _is_suspicious_domain(self, url: str) -> bool:
        """Check if a domain looks suspicious"""
        try:
            domain = urlparse(url).netloc.lower()
            
            # If it's a trusted domain, return False
            if any(trusted in domain for trusted in self.trusted_domains.keys()):
                return False
                
            # If it's an AI site, return False (not suspicious, just needs caution)
            if any(ai_domain in domain for ai_domain in self.ai_domains.keys()):
                return False

            # Check for suspicious TLDs
            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                return True
            
            # Check for typosquatting of trusted domains
            for trusted_domain in self.trusted_domains:
                if trusted_domain != domain:
                    ratio = SequenceMatcher(None, domain, trusted_domain).ratio()
                    if ratio > 0.8:  # Domain looks similar but isn't exact
                        return True
            
            return False
        except Exception:
            return True  # If we can't parse the URL, consider it suspicious

    def _find_similar_domain(self, url: str) -> str:
        """Find similar trusted domain names to detect phishing"""
        try:
            domain = urlparse(url).netloc.lower()
            
            for trusted_domain, org_name in self.trusted_domains.items():
                if trusted_domain != domain:
                    ratio = SequenceMatcher(None, domain, trusted_domain).ratio()
                    if ratio > 0.8:  # Domain looks similar but isn't exact
                        return f"{org_name} ({trusted_domain})"
            
            return ""
        except Exception:
            return ""

    def _analyze_python_code(self, code: str) -> list:
        alerts = []
        try:
            if "eval(" in code:
                alerts.append("Dangerous: eval() detected")
            if "exec(" in code:
                alerts.append("Dangerous: exec() detected")
            if "os.system(" in code:
                alerts.append("Dangerous: os.system() detected")
            if "__import__(" in code:
                alerts.append("Suspicious: dynamic import detected")
        except Exception as e:
            alerts.append(f"Error analyzing code: {str(e)}")
        return alerts

    def _detect_obfuscation(self, code: str) -> bool:
        # Check for common obfuscation techniques
        obfuscation_indicators = [
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'\\u[0-9a-fA-F]{4}',  # Unicode encoding
            r'String\.fromCharCode',  # Character code conversion
            r'unescape\(',  # URL encoding
            r'atob\(',  # Base64 encoding
            r'eval\(',  # eval usage
            r'decode\(',  # encoding usage
            r'base64',  # base64 mentions
        ]
        
        return any(re.search(pattern, code) for pattern in obfuscation_indicators)

    def _high_entropy_detected(self, text: str) -> bool:
        import math
        
        # Calculate Shannon entropy
        entropy = 0
        if len(text) < 2:
            return False
            
        # Count character frequencies
        char_count = {}
        for char in text:
            char_count[char] = char_count.get(char, 0) + 1
            
        # Calculate entropy
        for count in char_count.values():
            freq = count / len(text)
            entropy -= freq * math.log2(freq)
            
        # High entropy threshold (typical for encrypted/encoded content)
        return entropy > 5.0

    async def scan_content(self, content: str, content_type: str = None) -> SecurityScanResult:
        alerts = []
        score = 100
        risk_factors = []
        highest_risk = RiskLevel.SAFE

        # Determine content type if not provided
        if not content_type:
            content_type = self._detect_content_type(content)

        # HTML content analysis
        if content_type == "html":
            html_alerts = self._analyze_html(content)
            alerts.extend(html_alerts)
            score -= len(html_alerts) * 10

        # Check all pattern collections
        pattern_collections = [
            self.phishing_patterns,
            self.scam_patterns,
            self.adult_patterns,
            self.malware_distribution,
            self.suspicious_domains,
        ]

        for collection in pattern_collections:
            for pattern, risk_info in collection.items():
                if pattern.lower() in content.lower():
                    alerts.append(risk_info["message"])
                    score += risk_info["score"]
                    risk_factors.append(f"detected_{pattern.replace(' ', '_')}")
                    if risk_info["level"].value > highest_risk.value:
                        highest_risk = risk_info["level"]

        # Check for suspicious URLs
        urls = self._extract_urls(content)
        for url in urls:
            url_alerts = self._analyze_url(url)
            alerts.extend(url_alerts)
            if url_alerts:
                score -= 20
                highest_risk = max(highest_risk, RiskLevel.HIGH)

        # Check for hidden content
        if self._detect_hidden_content(content):
            alerts.append("High Risk: Hidden content detected")
            score -= 30
            highest_risk = max(highest_risk, RiskLevel.HIGH)

        # Ensure score stays within 0-100
        score = max(0, min(100, score))

        return SecurityScanResult(
            trustScore=score,
            isSuspicious=len(alerts) > 0,
            risk_level=highest_risk,
            alerts=alerts,
            details={
                "content_type": content_type,
                "content_length": str(len(content)),
                "risk_factors": ", ".join(risk_factors),
                "warning_count": str(len(alerts)),
                "urls_found": str(len(urls)),
                "has_hidden_content": str(self._detect_hidden_content(content))
            }
        )

    def _detect_content_type(self, content: str) -> str:
        # Try to detect if it's HTML
        if content.strip().startswith(("<!", "<html", "<?xml")):
            return "html"
        # Try to detect if it's JavaScript
        elif any(js_indicator in content for js_indicator in ["function", "var ", "let ", "const "]):
            return "javascript"
        # Try to detect if it's JSON
        elif content.strip().startswith(("{", "[")):
            try:
                json.loads(content)
                return "json"
            except:
                pass
        return "text"

    def _analyze_html(self, content: str) -> List[str]:
        alerts = []
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check for hidden elements
            hidden_elements = soup.find_all(style=lambda x: x and "display:none" in x.replace(" ", ""))
            if hidden_elements:
                alerts.append("Suspicious: Hidden elements detected")

            # Check for suspicious forms
            forms = soup.find_all("form")
            for form in forms:
                action = form.get("action", "").lower()
                if action and not action.startswith(("https://", "/")):
                    alerts.append(f"High Risk: Form submitting to suspicious URL: {action}")

            # Check for external scripts
            scripts = soup.find_all("script", src=True)
            for script in scripts:
                src = script["src"]
                if not src.startswith(("https://", "/")):
                    alerts.append(f"Medium Risk: External script from suspicious source: {src}")

            # Check for suspicious iframes
            iframes = soup.find_all("iframe")
            for iframe in iframes:
                src = iframe.get("src", "")
                if src and not src.startswith(("https://", "/")):
                    alerts.append(f"High Risk: Suspicious iframe source: {src}")

        except Exception as e:
            alerts.append(f"Error analyzing HTML: {str(e)}")

        return alerts

    def _detect_hidden_content(self, content: str) -> bool:
        # Check for CSS hiding techniques
        css_hiding = any(pattern in content.lower() for pattern in [
            "display:none",
            "visibility:hidden",
            "opacity:0",
            "height:0",
            "width:0",
            "position:absolute;left:-",
            "text-indent:-9999"
        ])

        # Check for HTML comments
        html_comments = "<!--" in content and "-->" in content

        # Check for invisible text (same color as background)
        color_tricks = re.search(r'color:\s*#?[Ff]{6}|color:\s*white|color:\s*#?[Ff]{3}', content) is not None

        return css_hiding or html_comments or color_tricks

    def _extract_urls(self, content: str) -> List[str]:
        # Extract URLs from content
        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s\'\"<>]*', content)
        return urls

    def _analyze_url(self, url: str) -> List[str]:
        alerts = []
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Check for suspicious TLDs
            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                alerts.append(f"High Risk: Suspicious TLD in URL: {domain}")

            # Check for typosquatting
            for legitimate_domain in self.trusted_domains:
                if domain != legitimate_domain:
                    similarity = SequenceMatcher(None, domain, legitimate_domain).ratio()
                    if similarity > 0.8 and similarity < 1.0:
                        alerts.append(f"High Risk: Possible typosquatting of {legitimate_domain}")

            # Check for suspicious URL patterns
            if any(pattern in url.lower() for pattern in ["download", "free", "crack", "hack", "keygen"]):
                alerts.append(f"High Risk: Suspicious keywords in URL: {url}")

        except Exception as e:
            alerts.append(f"Error analyzing URL {url}: {str(e)}")

        return alerts

    def _is_suspicious_url(self, url: str) -> Tuple[bool, str]:
        """
        Check if a URL is suspicious.
        Returns: (is_suspicious: bool, reason: str)
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Check for suspicious TLDs
            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                return True, f"Suspicious TLD in domain: {domain}"

            # Check for typosquatting of trusted domains
            for trusted_domain in self.trusted_domains:
                if domain != trusted_domain:
                    similarity = SequenceMatcher(None, domain, trusted_domain).ratio()
                    if similarity > 0.8 and similarity < 1.0:
                        return True, f"Possible typosquatting of {trusted_domain}"

            # Check for suspicious keywords in URL
            suspicious_keywords = ['free', 'crack', 'hack', 'keygen', 'warez', 'torrent', 'nulled']
            if any(keyword in url.lower() for keyword in suspicious_keywords):
                return True, "Suspicious keywords in URL"

            # Check for IP address instead of domain
            if re.match(r'^http://\d+\.\d+\.\d+\.\d+', url):
                return True, "IP address used instead of domain name"

            # Check for non-HTTPS
            if url.startswith('http://'):
                return True, "Non-secure HTTP protocol"

            return False, ""

        except Exception as e:
            return True, f"Invalid URL format: {str(e)}"