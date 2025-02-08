from urllib.parse import urlparse
import aiohttp
from schemas.security import SecurityScanResult, SecurityRating, RiskLevel
from utils.constants import KNOWN_APIS
import asyncio
from difflib import SequenceMatcher

class APIScanner:
    def __init__(self):
        self.known_apis = KNOWN_APIS  # Use constants

    async def check_url(self, url: str) -> SecurityScanResult:
        warnings = []
        risk_level = "low"
        
        # Parse URL
        try:
            parsed = urlparse(url)
            if not parsed.netloc:  # Add validation for empty domain
                raise ValueError("Invalid URL: no domain found")
            domain = parsed.netloc
        except ValueError as e:
            return SecurityScanResult(
                is_suspicious=True,
                risk_level=RiskLevel.HIGH,
                rating=SecurityRating(score=80, risk_level=RiskLevel.HIGH, confidence=100),
                warnings=[f"Invalid URL: {str(e)}"],
                details={"url": url}
            )
        
        # Check for HTTP (non-HTTPS)
        if parsed.scheme != "https":
            warnings.append("API endpoint is not using HTTPS")
            risk_level = "high"
        
        # Check for typosquatting of known APIs
        for api, domains in self.known_apis.items():
            try:
                if any(await asyncio.wait_for(self._similar_domain(domain, known), timeout=5) for known in domains):
                    if domain not in domains:
                        warnings.append(f"Domain looks similar to official {api} API")
                        risk_level = "high"
            except asyncio.TimeoutError:
                warnings.append(f"Timeout checking domain similarity for {api} API")
                risk_level = "medium"
        
        # Example 3: Someone using fake Google API
        # api-g00gle.com instead of api.google.com
        
        # Without SSL:
        # Attacker could intercept and say "api-g00gle.com is Google's real API!"
        
        # With SSL:
        if self._is_suspicious_domain(url):
            warnings.append("This might be a phishing attempt!")
            risk_level = "high"
        
        return SecurityScanResult(
            is_suspicious=len(warnings) > 0,
            risk_level=risk_level,
            warnings=warnings,
            details={"url": url, "domain": domain}
        )

    async def _similar_domain(self, domain1: str, domain2: str) -> bool:
        # Make method async since it's called with await
        ratio = SequenceMatcher(None, domain1.lower(), domain2.lower()).ratio()
        return ratio > 0.8 

    def _is_suspicious_domain(self, url: str) -> bool:
        # Implementation of _is_suspicious_domain method
        # This is a placeholder and should be implemented based on your specific requirements
        return False  # Placeholder return, actual implementation needed

    async def _similar_domain(self, domain1: str, domain2: str) -> bool:
        # Make method async since it's called with await
        ratio = SequenceMatcher(None, domain1.lower(), domain2.lower()).ratio()
        return ratio > 0.8 