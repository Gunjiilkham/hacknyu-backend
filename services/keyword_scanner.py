from typing import List, Dict
from schemas.security import SecurityScanResult, RiskLevel

class KeywordScanner:
    def __init__(self):
        # Keywords to scan for, with their risk levels
        self.suspicious_keywords = {
            # High risk keywords
            'password': RiskLevel.HIGH,
            'credit_card': RiskLevel.HIGH,
            'ssn': RiskLevel.HIGH,
            'social_security': RiskLevel.HIGH,
            'api_key': RiskLevel.HIGH,
            'secret_key': RiskLevel.HIGH,
            
            # Medium risk keywords
            'token': RiskLevel.MEDIUM,
            'auth': RiskLevel.MEDIUM,
            'login': RiskLevel.MEDIUM,
            'credential': RiskLevel.MEDIUM,
            
            # Low risk keywords
            'user': RiskLevel.LOW,
            'account': RiskLevel.LOW,
            'email': RiskLevel.LOW
        }

    async def scan_text(self, text: str) -> SecurityScanResult:
        """Scan text for suspicious keywords"""
        found_keywords = []
        highest_risk = RiskLevel.SAFE

        # Convert text to lowercase for case-insensitive matching
        text_lower = text.lower()
        
        for keyword, risk_level in self.suspicious_keywords.items():
            if keyword in text_lower:
                found_keywords.append({
                    'keyword': keyword,
                    'risk_level': risk_level,
                    'context': self._get_context(text, keyword)
                })
                # Update highest risk level found
                if risk_level.value > highest_risk.value:
                    highest_risk = risk_level

        return SecurityScanResult(
            is_suspicious=len(found_keywords) > 0,
            risk_level=highest_risk,
            warnings=[f"Found sensitive keyword: {k['keyword']} ({k['risk_level']})" 
                     for k in found_keywords],
            details={
                'keywords': found_keywords,
                'text_length': len(text)
            }
        )

    def _get_context(self, text: str, keyword: str, context_length: int = 50) -> str:
        """Get surrounding context for a keyword"""
        try:
            start_idx = text.lower().find(keyword.lower())
            if start_idx == -1:
                return ""
            
            # Get context before and after the keyword
            context_start = max(0, start_idx - context_length)
            context_end = min(len(text), start_idx + len(keyword) + context_length)
            
            context = text[context_start:context_end]
            if context_start > 0:
                context = "..." + context
            if context_end < len(text):
                context = context + "..."
                
            return context
        except Exception:
            return "" 