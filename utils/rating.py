from typing import List, Tuple
from schemas.security import RiskLevel, SecurityRating

class SecurityRater:
    def __init__(self):
        # Risk weights for different types of issues
        self.risk_weights = {
            "no_maintainer": 30,
            "new_package": 20,
            "suspicious_pattern": 25,
            "http_endpoint": 15,
            "obfuscated_code": 40,
            "eval_usage": 35,
            "network_access": 20,
            "typosquatting": 30
        }

    def calculate_rating(self, warnings: List[str], checks_performed: List[str]) -> SecurityRating:
        # Calculate base score
        total_score = 0
        triggered_weights = []
        
        # Check each warning against risk weights
        for warning in warnings:
            for risk_type, weight in self.risk_weights.items():
                if risk_type in warning.lower():
                    triggered_weights.append(weight)
        
        if triggered_weights:
            # Higher weights mean more risk, so higher score is worse
            total_score = min(sum(triggered_weights), 100)
        
        # Determine risk level based on score
        risk_level = self._score_to_risk_level(total_score)
        
        # Calculate confidence based on checks performed
        confidence = min(len(checks_performed) * 20, 100)
        
        return SecurityRating(
            score=total_score,
            risk_level=risk_level,
            confidence=confidence
        )

    def _score_to_risk_level(self, score: int) -> RiskLevel:
        if score < 20:
            return RiskLevel.SAFE
        elif score < 40:
            return RiskLevel.LOW
        elif score < 60:
            return RiskLevel.MEDIUM
        elif score < 80:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL 