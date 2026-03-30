from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from db.database import get_db
from backend.services.analysis_service import (
    get_result_by_id,
    compute_enterprise_score
)
from utils.logger import get_logger

router = APIRouter(prefix="/risk", tags=["Risk"])
logger = get_logger(__name__)


@router.get("/{scan_id}")
def get_risk_assessment(scan_id: str, db: Session = Depends(get_db)):
    result = get_result_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")

    full = result.full_result or {}
    risk = full.get("risk_engine", {})
    risk_score = risk.get("risk_score", {})

    return {
        "hostname": result.hostname,
        "ip": result.ip,
        "scanned_at": result.scanned_at.isoformat() if result.scanned_at else None,
        "final_score": risk_score.get("final_score"),
        "pqc_tier": risk_score.get("pqc_tier"),
        "tier_label": risk_score.get("tier_label"),
        "critical_count": risk_score.get("critical_count", 0),
        "high_count": risk_score.get("high_count", 0),
        "medium_count": risk_score.get("medium_count", 0),
        "low_count": risk_score.get("low_count", 0),
        "pqc_impact_count": risk_score.get("pqc_impact_count", 0),
        "triggered_rules": risk.get("triggered_rules", []),
        "score_breakdown": risk_score.get("score_breakdown", [])
    }


@router.get("/enterprise/score")
def get_enterprise_score(
    hostnames: str = Query(
        default=None,
        description="Comma-separated list of hostnames to include"
    ),
    db: Session = Depends(get_db)
):
    hostname_list = None
    if hostnames:
        hostname_list = [h.strip() for h in hostnames.split(",") if h.strip()]

    enterprise = compute_enterprise_score(db, hostname_list)
    return enterprise
