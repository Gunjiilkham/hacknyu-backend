from enum import Enum
from pydantic import BaseModel
from typing import List, Dict, Optional

class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityRating(BaseModel):
    score: int
    risk_level: RiskLevel
    confidence: int

class SecurityScanResult(BaseModel):
    is_suspicious: bool
    risk_level: RiskLevel
    rating: SecurityRating
    warnings: List[str]
    details: Dict[str, str]

class KeywordScanner:
    def __init__(self):
        # Keywords to scan for, with their risk levels
        self.suspicious_keywords = {
            # High risk keywords only
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
        
        # Documentation/safe contexts
        self.safe_contexts = [
            # Documentation indicators
            'documentation', 'docs', 'reference',
            'example', 'tutorial', 'guide',
            'learn', 'getting-started', 'quickstart',
            
            # API/SDK paths
            'what-is', 'how-to', 'api-reference',
            'sdk', 'developer', 'development',
            
            # Common doc sections
            'overview', 'introduction', 'concepts',
            'best-practices', 'faq', 'troubleshooting',
            
            # Learning paths
            'learn', 'training', 'workshop',
            'course', 'lesson', 'module'
        ]

        # Safe domains that are documentation-focused
        self.doc_domains = [
            # Cloud Documentation
            'docs.aws.amazon.com',
            'aws.amazon.com/what-is',
            'docs.microsoft.com',
            'learn.microsoft.com',
            'cloud.google.com/docs',
            
            # Programming Languages
            'docs.python.org',
            'devdocs.io',
            'go.dev/doc',
            'docs.oracle.com/en/java',
            'php.net/docs.php',
            
            # Web Development
            'developer.mozilla.org',
            'w3schools.com',
            'reactjs.org/docs',
            'vuejs.org/guide',
            'angular.io/docs',
            
            # Development Platforms
            'docs.github.com',
            'gitlab.com/help',
            'docs.docker.com',
            'kubernetes.io/docs'
        ]

        # Documentation file patterns
        self.doc_patterns = [
            'readme', 'changelog', 'contributing',
            'documentation', 'docs', 'wiki',
            'manual', 'guide', 'tutorial'
        ]

    async def scan_text(self, text: str) -> SecurityScanResult:
        warnings = []
        risk_level = RiskLevel.LOW
        
        for keyword, risk in self.suspicious_keywords.items():
            if keyword in text.lower():
                warnings.append(f"Found sensitive keyword: {keyword}")
                if risk.value > risk_level.value:
                    risk_level = risk
        
        return SecurityScanResult(
            is_suspicious=len(warnings) > 0,
            risk_level=risk_level,
            rating=SecurityRating(
                score=70 if warnings else 100,
                risk_level=risk_level,
                confidence=90
            ),
            warnings=warnings,
            details={
                "text_length": str(len(text)),
                "found_keywords": ", ".join(warnings)
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