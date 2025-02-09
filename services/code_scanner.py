import ast
import aiohttp
from bs4 import BeautifulSoup
from typing import List, Dict, Optional
from schemas.security import SecurityScanResult, SecurityRating, RiskLevel
from utils.constants import SUSPICIOUS_FUNCTIONS
import ssl
from urllib.parse import urlparse
from difflib import SequenceMatcher

class CodeScanner:
    def __init__(self):
        self.suspicious_functions = SUSPICIOUS_FUNCTIONS
        self.trusted_domains = {
            "python.org": "Python",
            "pypi.org": "PyPI",
            "npmjs.com": "npm",
            "github.com": "GitHub"
        }
        self.suspicious_tlds = ['.xyz', '.tk', '.pw', '.cc', '.su']

    async def analyze_code(self, code: str) -> SecurityScanResult:
        if not code.strip():  # Add validation for empty code
            return SecurityScanResult(
                is_suspicious=False,
                risk_level=RiskLevel.SAFE,
                warnings=[],
                details={"code_length": 0}
            )

        warnings = []
        risk_level = RiskLevel.LOW

        try:
            tree = ast.parse(code)
            warnings.extend(self._check_dangerous_functions(tree))
            warnings.extend(self._check_suspicious_imports(tree))
            warnings.extend(self._check_network_access(tree))
            
            if warnings:
                risk_level = RiskLevel.HIGH if any("critical" in w.lower() for w in warnings) else RiskLevel.MEDIUM

        except SyntaxError:
            warnings.append("Code contains syntax errors - could be obfuscated")
            risk_level = RiskLevel.HIGH
        except Exception as e:
            warnings.append(f"Error analyzing code: {str(e)}")
            risk_level = RiskLevel.MEDIUM

        return SecurityScanResult(
            is_suspicious=len(warnings) > 0,
            risk_level=risk_level,
            warnings=warnings,
            details={"code_length": len(code)}
        )

    def _check_dangerous_functions(self, tree: ast.AST) -> List[str]:
        warnings = []
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
                        warnings.append(f"⚠️ {pattern['risk']}: {pattern['desc']} ({node.func.id})")
                elif isinstance(node.func, ast.Attribute):
                    try:
                        full_name = f"{node.func.value.id}.{node.func.attr}"
                        if full_name in dangerous_patterns:
                            pattern = dangerous_patterns[full_name]
                            warnings.append(f"⚠️ {pattern['risk']}: {pattern['desc']} ({full_name})")
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
                        warnings.append(f"⚠️ {risk}: Dangerous command detected: {cmd}")

        return warnings

    def _check_suspicious_imports(self, tree: ast.AST) -> List[str]:
        warnings = []
        suspicious_modules = {'subprocess', 'os', 'sys', 'requests', 'urllib'}
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    if name.name.split('.')[0] in suspicious_modules:
                        warnings.append(f"Suspicious import: {name.name}")
        return warnings

    def _check_network_access(self, tree: ast.AST) -> List[str]:
        warnings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Str):
                if node.s.startswith(('http://', 'https://', 'ftp://')):
                    warnings.append(f"Network access detected: {node.s}")
        return warnings 

    async def scan_webpage(self, url: str) -> SecurityScanResult:
        """Scan code from a webpage"""
        try:
            # Create a session with SSL verification disabled
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(verify_ssl=False)
            ) as session:
                try:
                    async with session.get(url, ssl=False) as response:
                        if response.status == 404:
                            return SecurityScanResult(
                                is_suspicious=True,
                                risk_level=RiskLevel.HIGH,
                                warnings=[f"⚠️ URL not found: {url}"],
                                details={"url": url}
                            )

                        # Check domain before fetching content
                        if self._is_suspicious_domain(url):
                            return SecurityScanResult(
                                is_suspicious=True,
                                risk_level=RiskLevel.HIGH,
                                warnings=[
                                    f"⚠️ Suspicious domain detected",
                                    "This might be a phishing attempt"
                                ],
                                details={
                                    "url": url,
                                    "type": "phishing",
                                    "similar_to": self._find_similar_domain(url)
                                }
                            )

                    html = await response.text()

                    # Parse HTML
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Find all code elements
                    suspicious_elements = []
                    
                    # Check <script> tags
                    for script in soup.find_all('script'):
                        if script.string:  # If script has content
                            result = await self.analyze_code(script.string)
                            if result.is_suspicious:
                                suspicious_elements.append({
                                    'type': 'script',
                                    'content': script.string,
                                    'warnings': result.warnings
                                })

                    # Check inline event handlers
                    for tag in soup.find_all(lambda t: any(attr.startswith('on') for attr in t.attrs)):
                        for attr, value in tag.attrs.items():
                            if attr.startswith('on'):  # onclick, onload, etc.
                                result = await self.analyze_code(value)
                                if result.is_suspicious:
                                    suspicious_elements.append({
                                        'type': 'event_handler',
                                        'content': value,
                                        'warnings': result.warnings
                                    })

                    return SecurityScanResult(
                        is_suspicious=len(suspicious_elements) > 0,
                        risk_level=RiskLevel.HIGH if suspicious_elements else RiskLevel.SAFE,
                        rating=SecurityRating(
                            score=80 if suspicious_elements else 0,
                            risk_level=RiskLevel.HIGH if suspicious_elements else RiskLevel.SAFE,
                            confidence=90
                        ),
                        warnings=[f"Suspicious {elem['type']}: {', '.join(elem['warnings'])}" 
                                 for elem in suspicious_elements],
                        details={
                            'url': url,
                            'suspicious_elements': suspicious_elements
                        }
                    )
                
                except aiohttp.ClientError as e:
                    return SecurityScanResult(
                        is_suspicious=True,
                        risk_level=RiskLevel.HIGH,
                        warnings=[f"⚠️ Error accessing URL: {str(e)}"],
                        details={"url": url, "error": str(e)}
                    )

        except Exception as e:
            return SecurityScanResult(
                is_suspicious=True,
                risk_level=RiskLevel.HIGH,
                rating=SecurityRating(
                    score=70,
                    risk_level=RiskLevel.HIGH,
                    confidence=50
                ),
                warnings=[f"Error scanning webpage: {str(e)}"],
                details={'url': url, 'error': str(e)}
            ) 

    async def scan_code(self, code: str) -> SecurityScanResult:
        result = await self.analyze_code(code)
        return SecurityScanResult(
            is_suspicious=result.is_suspicious,
            risk_level=result.risk_level or RiskLevel.LOW,  # Provide default
            warnings=result.warnings,
            details=result.details or {}  # Provide default
        ) 

    def _is_suspicious_domain(self, url: str) -> bool:
        """Check if a domain looks suspicious"""
        try:
            domain = urlparse(url).netloc.lower()
            
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