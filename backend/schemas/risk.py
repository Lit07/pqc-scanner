from pydantic import BaseModel
from typing import Optional, List, Dict


class RiskEngineResponse(BaseModel):
    hostname: str
    ip: Optional[str]
    scanned_at: str
    final_score: Optional[int]
    pqc_tier: Optional[str]
    tier_label: Optional[str]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    pqc_impact_count: int
    triggered_rules: List[dict]
    score_breakdown: List[dict]


class EnterpriseScoreResponse(BaseModel):
    enterprise_score: int
    pqc_tier: str
    tier_label: str
    total_assets: int
    elite_count: int
    standard_count: int
    legacy_count: int
    critical_count: int
    average_score: float
