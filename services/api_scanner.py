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
        risk_level = RiskLevel.LOW
        score = 100
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            if parsed.scheme != "https":
                warnings.append("API endpoint is not using HTTPS")
                risk_level = RiskLevel.HIGH
                score -= 30
            
            if self._is_suspicious_domain(url):
                warnings.append("Suspicious domain detected")
                risk_level = RiskLevel.HIGH
                score -= 40
            
            return SecurityScanResult(
                is_suspicious=len(warnings) > 0,
                risk_level=risk_level,
                rating=SecurityRating(
                    score=max(0, score),
                    risk_level=risk_level,
                    confidence=90
                ),
                warnings=warnings,
                details={
                    "url": url,
                    "domain": domain
                }
            )
        except Exception as e:
            return SecurityScanResult(
                is_suspicious=True,
                risk_level=RiskLevel.HIGH,
                rating=SecurityRating(
                    score=0,
                    risk_level=RiskLevel.HIGH,
                    confidence=90
                ),
                warnings=[f"Error analyzing URL: {str(e)}"],
                details={"url": url}
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