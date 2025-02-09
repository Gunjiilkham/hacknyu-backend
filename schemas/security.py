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
    score: int  # 0-100
    risk_level: RiskLevel
    confidence: int  # 0-100

class SecurityScanResult(BaseModel):
    is_suspicious: bool
    risk_level: RiskLevel
    rating: SecurityRating
    warnings: List[str]
    details: Dict[str, str]

    class Config:
        populate_by_name = True

    # SSL helps ensure:
    # 1. Package data is authentic
    # 2. Security checks aren't tampered with
    # 3. Results aren't modified in transit
