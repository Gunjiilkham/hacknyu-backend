import ast
from typing import List, Dict
from schemas.security import SecurityScanResult

class CodeScanner:
    def __init__(self):
        self.suspicious_functions = {
            'eval', 'exec', 'os.system', 'subprocess.run', 
            'subprocess.Popen', 'requests.get', 'urllib.request.urlopen'
        }

    async def scan_code(self, code: str) -> SecurityScanResult:
        warnings = []
        risk_level = "low"

        try:
            tree = ast.parse(code)
            warnings.extend(self._check_dangerous_functions(tree))
            warnings.extend(self._check_suspicious_imports(tree))
            warnings.extend(self._check_network_access(tree))
            
            if warnings:
                risk_level = "high" if any("critical" in w.lower() for w in warnings) else "medium"

        except SyntaxError:
            warnings.append("Code contains syntax errors - could be obfuscated")
            risk_level = "high"
        except Exception as e:
            warnings.append(f"Error analyzing code: {str(e)}")
            risk_level = "medium"

        return SecurityScanResult(
            is_suspicious=len(warnings) > 0,
            risk_level=risk_level,
            warnings=warnings,
            details={"code_length": len(code)}
        )

    def _check_dangerous_functions(self, tree: ast.AST) -> List[str]:
        warnings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in self.suspicious_functions:
                    warnings.append(f"Dangerous function call: {node.func.id}")
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