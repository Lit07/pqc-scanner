from pydantic import BaseModel
from typing import Optional, List, Dict


class EndpointClassificationResponse(BaseModel):
    hostname: str
    endpoint_type: Optional[str]
    sensitivity: Optional[str]
    sensitivity_score: Optional[int]
    data_classification: Optional[str]
    regulatory_scope: List[str]
    hndl_multiplier: float
    adjusted_priority: int
    confidence: Optional[str]
    ai_flags: List[str]
    attack_surface: Optional[str]
    exposure_level: Optional[str]
    risk_narrative: Optional[str]


class HNDLAssessmentResponse(BaseModel):
    hostname: str
    hndl_threat_level: str
    hndl_score: int
    adjusted_hndl_score: int
    hndl_color: str
    forward_secrecy: bool
    harvest_window_open: bool
    estimated_decrypt_year: Optional[int]
    exposure_factors: List[dict]
    hndl_narrative: Optional[str]
    recommended_actions: List[dict]
    regulatory_breach_risk: List[str]


class QuantumTimelineResponse(BaseModel):
    hostname: str
    key_type: Optional[str]
    key_size: Optional[int]
    estimated_break_year: Optional[int]
    years_until_break: Optional[int]
    urgency_level: Optional[str]
    countdown_message: Optional[str]
    milestones: List[dict]
    timeline_events: List[dict]
    migration_deadline_message: str


class RecommendationsResponse(BaseModel):
    hostname: str
    recommendations: List[dict]
    quick_wins: List[dict]
    long_term: List[dict]
    total_count: int
    critical_count: int
    estimated_total_effort: Optional[str]


class AnomalyResponse(BaseModel):
    hostname: str
    anomalies: List[dict]
    anomaly_count: int
    critical_anomalies: int
    has_regression: bool
    regression_details: List[str]
    trend: Optional[str]


class RiskExplanationResponse(BaseModel):
    hostname: str
    executive_summary: Optional[str]
    technical_summary: Optional[str]
    risk_story: Optional[str]
    key_findings: List[dict]
    positive_findings: List[dict]
    overall_grade: Optional[str]
    grade_color: Optional[str]
    one_liner: Optional[str]