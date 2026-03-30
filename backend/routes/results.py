from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from db.database import get_db
from backend.services.analysis_service import (
    get_result_by_id,
    get_results_by_hostname,
    get_result_count_by_hostname
)
from backend.services.report_service import (
    generate_json_report,
    generate_executive_summary
)
from utils.logger import get_logger

router = APIRouter(prefix="/results", tags=["Results"])
logger = get_logger(__name__)


@router.get("/{scan_id}")
def get_scan_result(scan_id: str, db: Session = Depends(get_db)):
    result = get_result_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")

    return {
        "id": result.id,
        "scan_job_id": result.scan_job_id,
        "hostname": result.hostname,
        "ip": result.ip,
        "tls_version": result.tls_version,
        "cipher_name": result.cipher_name,
        "cipher_bits": result.cipher_bits,
        "key_type": result.key_type,
        "key_size": result.key_size,
        "curve_name": result.curve_name,
        "is_expired": result.is_expired,
        "days_to_expiry": result.days_to_expiry,
        "is_self_signed": result.is_self_signed,
        "is_wildcard": result.is_wildcard,
        "forward_secrecy": result.forward_secrecy,
        "final_score": result.final_score,
        "pqc_tier": result.pqc_tier,
        "pqc_score": result.pqc_score,
        "pqc_classification": result.pqc_classification,
        "hndl_threat_level": result.hndl_threat_level,
        "hndl_score": result.hndl_score,
        "endpoint_type": result.endpoint_type,
        "sensitivity": result.sensitivity,
        "grade": result.grade,
        "shadow_asset_count": result.shadow_asset_count,
        "anomaly_count": result.anomaly_count,
        "has_regression": result.has_regression,
        "scanned_at": result.scanned_at.isoformat() if result.scanned_at else None,
        "full_result": result.full_result
    }


@router.get("/hostname/{hostname}")
def get_scan_history(
    hostname: str,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db)
):
    results = get_results_by_hostname(db, hostname, limit, offset)
    total = get_result_count_by_hostname(db, hostname)

    items = []
    for r in results:
        items.append({
            "id": r.id,
            "hostname": r.hostname,
            "final_score": r.final_score,
            "pqc_tier": r.pqc_tier,
            "grade": r.grade,
            "tls_version": r.tls_version,
            "key_type": r.key_type,
            "key_size": r.key_size,
            "hndl_threat_level": r.hndl_threat_level,
            "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None
        })

    return {
        "hostname": hostname,
        "total_scans": total,
        "results": items
    }


@router.get("/{scan_id}/report")
def get_scan_report(scan_id: str, db: Session = Depends(get_db)):
    result = get_result_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")

    report = generate_json_report(result)
    return report


@router.get("/{scan_id}/summary")
def get_scan_summary(scan_id: str, db: Session = Depends(get_db)):
    result = get_result_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")

    summary = generate_executive_summary(result)
    return summary
