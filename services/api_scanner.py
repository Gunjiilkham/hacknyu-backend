from urllib.parse import urlparse
import aiohttp
from schemas.security import SecurityScanResult

class APIScanner:
    def __init__(self):
        self.known_apis = {
            "google": ["googleapis.com", "google.com"],
            "github": ["api.github.com", "github.com"],
            "aws": ["amazonaws.com"],
            "azure": ["azure.com", "microsoftonline.com"]
        }

    async def check_url(self, url: str) -> SecurityScanResult:
        warnings = []
        risk_level = "low"
        
        # Parse URL
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Check for HTTP (non-HTTPS)
        if parsed.scheme != "https":
            warnings.append("API endpoint is not using HTTPS")
            risk_level = "high"
        
        # Check for typosquatting of known APIs
        for api, domains in self.known_apis.items():
            if any(self._similar_domain(domain, known) for known in domains):
                if domain not in domains:
                    warnings.append(f"Domain looks similar to official {api} API")
                    risk_level = "high"
        
        return SecurityScanResult(
            is_suspicious=len(warnings) > 0,
            risk_level=risk_level,
            warnings=warnings,
            details={"url": url, "domain": domain}
        )

    def _similar_domain(self, domain1: str, domain2: str) -> bool:
        # Simple Levenshtein distance check
        from difflib import SequenceMatcher
        return SequenceMatcher(None, domain1, domain2).ratio() > 0.8 