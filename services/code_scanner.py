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

    async def analyze_code(self, code: str) -> SecurityScanResult:
        if not code.strip():
            return SecurityScanResult(
                is_suspicious=False,
                risk_level=RiskLevel.SAFE,
                warnings=[],
                details={"code_length": 0}
            )

        # Skip analysis for known safe scripts
        if self._is_safe_script(code):
            return SecurityScanResult(
                is_suspicious=False,
                risk_level=RiskLevel.SAFE,
                warnings=[],
                details={
                    "code_length": len(code),
                    "code_type": "safe_script"
                }
            )

        warnings = []
        risk_level = RiskLevel.LOW

        # Only analyze if it looks like actual code
        if self._looks_like_code(code):
            try:
                if self._is_javascript(code):
                    js_warnings = self._check_javascript(code)
                    if js_warnings:
                        warnings.extend(js_warnings)
                        risk_level = RiskLevel.MEDIUM
                else:
                    # Python analysis
                    tree = ast.parse(code)
                    python_warnings = self._check_python_code(tree)
                    if python_warnings:
                        warnings.extend(python_warnings)
                        risk_level = RiskLevel.MEDIUM

            except Exception:
                # Don't warn about syntax for non-code content
                pass

        return SecurityScanResult(
            is_suspicious=len(warnings) > 0,
            risk_level=risk_level,
            warnings=warnings,
            details={
                "code_length": len(code),
                "code_type": self._determine_code_type(code)
            }
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
        warnings = []
        dangerous_patterns = {
            'eval(': '⚠️ Dangerous: Dynamic code execution',
            'new Function(': '⚠️ Dangerous: Dynamic code execution',
            'document.write(': '⚠️ Dangerous: Direct DOM manipulation',
            '.innerHTML =': '⚠️ Potential XSS risk',
            'window.location =': '⚠️ Suspicious: URL redirection',
        }
        
        # Only warn if pattern is not in a comment or string
        for pattern, warning in dangerous_patterns.items():
            if pattern in code and not self._is_in_comment_or_string(code, pattern):
                warnings.append(warning)
        
        return warnings

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
                url = node.s
                if url.startswith(('http://', 'https://')):
                    # Skip warning if domain is trusted
                    domain = urlparse(url).netloc.lower()
                    if any(trusted in domain for trusted in self.trusted_domains.keys()):
                        continue
                    warnings.append(f"Network access detected: {url}")
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