from enum import Enum
from pydantic import BaseModel
from typing import List, Optional, Dict

class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityRating(BaseModel):
    score: int  # 0-100
    risk_level: RiskLevel
    confidence: int  # 0-100

class SecurityScanResult(BaseModel):
    is_suspicious: bool
    risk_level: RiskLevel
    warnings: List[str]
    details: Dict = {}  # Provide default empty dict

    # SSL helps ensure:
    # 1. Package data is authentic
    # 2. Security checks aren't tampered with
    # 3. Results aren't modified in transit
