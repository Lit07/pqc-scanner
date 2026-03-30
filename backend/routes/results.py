from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from db.database import get_db
from db.models import ScanResult, Asset, ScanJob
import datetime
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

@router.get("/rating/enterprise")
def get_enterprise_rating(db: Session = Depends(get_db)):
    # Calculate unique latest scan results per hostname
    subquery = db.query(
        ScanResult.hostname, 
        func.max(ScanResult.scanned_at).label("max_scanned_at")
    ).group_by(ScanResult.hostname).subquery()

    latest_results = db.query(ScanResult).join(
        subquery,
        (ScanResult.hostname == subquery.c.hostname) & 
        (ScanResult.scanned_at == subquery.c.max_scanned_at)
    ).all()

    avg_score = 0
    if latest_results:
        avg_score = int(sum(r.final_score or 0 for r in latest_results) / len(latest_results))
        
    # Determine Tier
    tier_label = "Unrated"
    if avg_score >= 800: tier_label = "Elite (AAA)"
    elif avg_score >= 700: tier_label = "Secure (AA)"
    elif avg_score >= 600: tier_label = "Standard (A)"
    elif avg_score >= 500: tier_label = "Vulnerable (BB+)"
    elif avg_score >= 400: tier_label = "Legacy (B)"
    else: tier_label = "Critical (C-)"

    # Aggregate components
    network_score = 0
    app_score = 0
    crypto_score = 0
    patch_score = 0

    if latest_results:
        network_score = int(sum(r.final_score or 0 for r in latest_results) / len(latest_results))
        
        c_scores = []
        for r in latest_results:
            if r.pqc_tier == "Critical": c_scores.append(200)
            elif r.pqc_tier == "Legacy": c_scores.append(400)
            elif r.pqc_tier == "Standard": c_scores.append(700)
            elif r.pqc_tier == "Elite": c_scores.append(1000)
            else: c_scores.append(500)
        crypto_score = int(sum(c_scores)/len(c_scores))

        app_score = max(0, min(1000, avg_score + 20))
        patch_score = max(0, min(1000, avg_score - 30))

    # Dynamic HNDL Exposure based on global threat level
    hndl = [
      { "date": "2023", "risk": 20 },
      { "date": "2025", "risk": 35 },
      { "date": "2026", "risk": 50 if crypto_score > 500 else 75 },
      { "date": "2028", "risk": 75 if crypto_score > 500 else 90 },
      { "date": "2030 (Q-Day)", "risk": 100 },
    ]

    return {
        "score": avg_score,
        "maxScore": 1000,
        "tier": tier_label,
        "hndlExposureTimeline": hndl,
        "components": [
            { "name": "Network Security", "score": network_score },
            { "name": "Application Security", "score": app_score },
            { "name": "Cryptographic Posture", "score": crypto_score },
            { "name": "Patch Management", "score": patch_score },
        ]
    }

@router.get("/dashboard/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    # 1. Stats
    total_assets = db.query(Asset).count()
    
    # Calculate unique latest scan results per hostname
    subquery = db.query(
        ScanResult.hostname, 
        func.max(ScanResult.scanned_at).label("max_scanned_at")
    ).group_by(ScanResult.hostname).subquery()

    latest_results = db.query(ScanResult).join(
        subquery,
        (ScanResult.hostname == subquery.c.hostname) & 
        (ScanResult.scanned_at == subquery.c.max_scanned_at)
    ).all()

    high_risk_assets = sum(1 for r in latest_results if r.pqc_tier in ["Legacy", "Critical"])
    expiring_certs = sum(1 for r in latest_results if r.days_to_expiry is not None and r.days_to_expiry < 30)
    
    avg_score = 0
    if latest_results:
        avg_score = int(sum(r.final_score or 0 for r in latest_results) / len(latest_results))
        
    critical_findings = sum(1 for r in latest_results if r.grade in ["D", "F"])

    active_scans = db.query(ScanJob).filter(ScanJob.status.in_(["pending", "processing"])).count()
    
    # 2. Charts Data
    # Risk Distribution
    risk_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in latest_results:
        if r.grade in ["F"]: risk_dist["Critical"] += 1
        elif r.grade in ["D"]: risk_dist["High"] += 1
        elif r.grade in ["C"]: risk_dist["Medium"] += 1
        else: risk_dist["Low"] += 1

    # Cipher Usage
    ciphers = {}
    for r in latest_results:
        cname = r.cipher_name or "Unknown"
        ciphers[cname] = ciphers.get(cname, 0) + 1
    
    cipher_usage = [{"name": k, "count": v} for k, v in sorted(ciphers.items(), key=lambda item: item[1], reverse=True)[:5]]

    # Expiry Timeline (simplified dummy projection based on actual counts)
    expiry_timeline = [
        {"month": "Next 30 Days", "expiring": expiring_certs},
        {"month": "30-60 Days", "expiring": sum(1 for r in latest_results if r.days_to_expiry is not None and 30 <= r.days_to_expiry < 60)},
        {"month": "60-90 Days", "expiring": sum(1 for r in latest_results if r.days_to_expiry is not None and 60 <= r.days_to_expiry < 90)},
        {"month": "90+ Days", "expiring": sum(1 for r in latest_results if r.days_to_expiry is not None and r.days_to_expiry >= 90)}
    ]

    # 3. Activity Feed (Last 4 scans)
    recent_scans = db.query(ScanResult).order_by(ScanResult.scanned_at.desc()).limit(4).all()
    activity = []
    for idx, r in enumerate(recent_scans):
        status_label = "Success"
        if r.grade in ["F", "D"]: status_label = "Critical"
        activity.append({
            "id": idx + 1,
            "action": "Scan Completed",
            "target": r.hostname,
            "time": r.scanned_at.strftime("%Y-%m-%d %H:%M") if r.scanned_at else "Just now",
            "status": status_label
        })

    # 4. Geography (Mocked for now since IP geolocation isn't in db natively yet)
    geography = [
        {"region": "Mumbai (ap-south-1)", "count": int(total_assets * 0.6), "status": "Healthy"},
        {"region": "Delhi (Data Center A)", "count": int(total_assets * 0.3), "status": "Warning" if high_risk_assets > total_assets*0.2 else "Healthy"},
        {"region": "Frankfurt (eu-central-1)", "count": int(total_assets * 0.1), "status": "Healthy"},
    ]

    return {
        "stats": {
            "totalAssets": total_assets,
            "highRiskAssets": high_risk_assets,
            "expiringCerts": expiring_certs,
            "pqcScore": avg_score,
            "activeScans": active_scans,
            "criticalFindings": critical_findings,
        },
        "charts": {
            "riskDistribution": [
                {"name": "Critical", "value": risk_dist["Critical"], "fill": "#ef4444"},
                {"name": "High", "value": risk_dist["High"], "fill": "#f97316"},
                {"name": "Medium", "value": risk_dist["Medium"], "fill": "#eab308"},
                {"name": "Low", "value": risk_dist["Low"], "fill": "#22c55e"},
            ],
            "cipherUsage": cipher_usage,
            "expiryTimeline": expiry_timeline
        },
        "activity": activity,
        "geography": geography
    }

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
