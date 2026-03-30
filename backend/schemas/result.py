from pydantic import BaseModel
from typing import Optional, List, Dict


class ScanResultResponse(BaseModel):
    id: str
    scan_job_id: str
    hostname: str
    ip: Optional[str]
    tls_version: Optional[str]
    cipher_name: Optional[str]
    cipher_bits: Optional[int]
    key_type: Optional[str]
    key_size: Optional[int]
    curve_name: Optional[str]
    is_expired: bool
    days_to_expiry: Optional[int]
    is_self_signed: bool
    is_wildcard: bool
    forward_secrecy: bool
    final_score: Optional[int]
    pqc_tier: Optional[str]
    pqc_score: Optional[int]
    pqc_classification: Optional[str]
    hndl_threat_level: Optional[str]
    hndl_score: Optional[int]
    endpoint_type: Optional[str]
    sensitivity: Optional[str]
    grade: Optional[str]
    shadow_asset_count: int
    anomaly_count: int
    has_regression: bool
    scanned_at: Optional[str]
    full_result: Optional[dict]


class ScanHistoryItem(BaseModel):
    id: str
    hostname: str
    final_score: Optional[int]
    pqc_tier: Optional[str]
    grade: Optional[str]
    tls_version: Optional[str]
    key_type: Optional[str]
    key_size: Optional[int]
    hndl_threat_level: Optional[str]
    scanned_at: Optional[str]


class ScanHistoryResponse(BaseModel):
    hostname: str
    total_scans: int
    results: List[ScanHistoryItem]


class ReportResponse(BaseModel):
    hostname: str
    generated_at: str
    executive_summary: Optional[str]
    technical_summary: Optional[str]
    risk_score: Optional[int]
    grade: Optional[str]
    pqc_classification: Optional[str]
    recommendations: List[dict]
    full_result: Optional[dict]
