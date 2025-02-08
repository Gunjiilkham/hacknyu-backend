from typing import Dict, List, Set

RISK_WEIGHTS: Dict[str, int] = {
    "no_maintainer": 30,
    "new_package": 20,
    "suspicious_pattern": 25,
    "http_endpoint": 15,
    "obfuscated_code": 40,
    "eval_usage": 35,
    "network_access": 20,
    "typosquatting": 30
}

SUSPICIOUS_PATTERNS: List[str] = [
    "eval(",
    "child_process",
    "exec(",
    "http://",
    "curl",
    "wget",
    "bash -c"
]

SUSPICIOUS_FUNCTIONS: Set[str] = {
    'eval', 'exec', 'os.system', 'subprocess.run', 
    'subprocess.Popen', 'requests.get', 'urllib.request.urlopen'
}

KNOWN_APIS: Dict[str, List[str]] = {
    "google": ["googleapis.com", "google.com"],
    "github": ["api.github.com", "github.com"],
    "aws": ["amazonaws.com"]
} 