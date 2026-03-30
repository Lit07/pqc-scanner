from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from db.database import get_db
from backend.services.analysis_service import get_result_by_id
from utils.logger import get_logger

router = APIRouter(prefix="/ai", tags=["AI Analysis"])
logger = get_logger(__name__)


@router.get("/hndl/{scan_id}")
def get_hndl_assessment(scan_id: str, db: Session = Depends(get_db)):
    result = get_result_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")

    full = result.full_result or {}
    hndl = full.get("hndl_assessment", {})

    return {
        "hostname": result.hostname,
        "hndl_threat_level": hndl.get("hndl_threat_level"),
        "hndl_score": hndl.get("hndl_score"),
        "adjusted_hndl_score": hndl.get("adjusted_hndl_score"),
        "hndl_color": hndl.get("hndl_color"),
        "forward_secrecy": hndl.get("forward_secrecy"),
        "harvest_window_open": hndl.get("harvest_window_open"),
        "estimated_decrypt_year": hndl.get("estimated_decrypt_year"),
        "exposure_factors": hndl.get("exposure_factors", []),
        "hndl_narrative": hndl.get("hndl_narrative"),
        "recommended_actions": hndl.get("recommended_actions", []),
        "regulatory_breach_risk": hndl.get("regulatory_breach_risk", [])
    }


@router.get("/timeline/{scan_id}")
def get_quantum_timeline(scan_id: str, db: Session = Depends(get_db)):
    result = get_result_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")

    full = result.full_result or {}
    timeline = full.get("quantum_timeline", {})

    return {
        "hostname": result.hostname,
        "key_type": timeline.get("key_type"),
        "key_size": timeline.get("key_size"),
        "estimated_break_year": timeline.get("estimated_break_year"),
        "years_until_break": timeline.get("years_until_break"),
        "urgency_level": timeline.get("urgency_level"),
        "countdown_message": timeline.get("countdown_message"),
        "milestones": timeline.get("milestones", []),
        "timeline_events": timeline.get("timeline_events", []),
        "migration_deadline_message": timeline.get(
            "migration_deadline_message", ""
        )
    }


@router.get("/recommendations/{scan_id}")
def get_recommendations(scan_id: str, db: Session = Depends(get_db)):
    result = get_result_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")

    full = result.full_result or {}
    recs = full.get("recommendations", {})

    return {
        "hostname": result.hostname,
        "recommendations": recs.get("recommendations", []),
        "quick_wins": recs.get("quick_wins", []),
        "long_term": recs.get("long_term", []),
        "total_count": recs.get("total_count", 0),
        "critical_count": recs.get("critical_count", 0),
        "estimated_total_effort": recs.get("estimated_total_effort")
    }


@router.get("/anomalies/{scan_id}")
def get_anomalies(scan_id: str, db: Session = Depends(get_db)):
    result = get_result_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")

    full = result.full_result or {}
    anomalies = full.get("anomalies", {})

    return {
        "hostname": result.hostname,
        "anomalies": anomalies.get("anomalies", []),
        "anomaly_count": anomalies.get("anomaly_count", 0),
        "critical_anomalies": anomalies.get("critical_anomalies", 0),
        "has_regression": anomalies.get("has_regression", False),
        "regression_details": anomalies.get("regression_details", []),
        "trend": anomalies.get("trend")
    }


@router.get("/explain/{scan_id}")
def get_risk_explanation(scan_id: str, db: Session = Depends(get_db)):
    result = get_result_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")

    full = result.full_result or {}
    explanation = full.get("risk_explanation", {})

    return {
        "hostname": result.hostname,
        "executive_summary": explanation.get("executive_summary"),
        "technical_summary": explanation.get("technical_summary"),
        "risk_story": explanation.get("risk_story"),
        "key_findings": explanation.get("key_findings", []),
        "positive_findings": explanation.get("positive_findings", []),
        "overall_grade": explanation.get("overall_grade"),
        "grade_color": explanation.get("grade_color"),
        "one_liner": explanation.get("one_liner")
    }
