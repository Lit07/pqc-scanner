from pydantic import BaseModel
from typing import Optional, List, Dict


class PQCClassificationResponse(BaseModel):
    hostname: str
    pqc_score: int
    pqc_classification: str
    classification_description: str
    classification_color: str
    tier_number: int
    pqc_ready: bool
    hybrid_mode_possible: bool
    estimated_quantum_risk_year: Optional[dict]
    overall_verdict: str
    immediate_actions: List[dict]
    nist_replacements: List[dict]
    quantum_attack_vectors: List[dict]


class MigrationPlanResponse(BaseModel):
    hostname: str
    key_type: Optional[str]
    current_posture_summary: Optional[str]
    phases: List[dict]
    immediate_actions: List[dict]
    full_migration_steps: List[dict]
    estimated_total_days: Optional[int]
    nist_standards_applicable: List[str]
    breaking_changes: bool
    priority_score: Optional[int]


class PQCPostureSummary(BaseModel):
    total_assets: int
    elite_count: int
    standard_count: int
    legacy_count: int
    critical_count: int
    pqc_ready_percentage: float
    key_type_distribution: Dict[str, int]
    tls_version_distribution: Dict[str, int]