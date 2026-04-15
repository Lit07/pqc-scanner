from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from db.database import get_db
from backend.services.analysis_service import get_result_by_id
from backend.services.report_service import (
    generate_cbom_export,
    generate_cbom_summary_export
)
from analysis.cbom.cbom_formatter import format_cbom_download
from utils.logger import get_logger

from db.models import ScanResult
from sqlalchemy import func

router = APIRouter(prefix="/cbom", tags=["CBOM"])
logger = get_logger(__name__)

@router.get("/stats/global")
def get_global_cbom_stats(db: Session = Depends(get_db)):
    subquery = db.query(
        ScanResult.hostname, 
        func.max(ScanResult.scanned_at).label("max_scanned_at")
    ).group_by(ScanResult.hostname).subquery()

    latest_results = db.query(ScanResult).join(
        subquery,
        (ScanResult.hostname == subquery.c.hostname) & 
        (ScanResult.scanned_at == subquery.c.max_scanned_at)
    ).all()
    
    total_apps = len(latest_results)
    weak_crypto = sum(1 for r in latest_results if r.grade in ["D", "F"])
    
    key_lengths = {}
    ciphers = {}
    cas = {}
    
    for r in latest_results:
        kname = f"{r.key_type}-{r.key_size}" if r.key_type else "Unknown"
        key_lengths[kname] = key_lengths.get(kname, 0) + 1
        
        cname = r.cipher_name or "Unknown"
        ciphers[cname] = ciphers.get(cname, 0) + 1
        
        ca = "Unknown"
        if r.full_result:
            cert_data = r.full_result.get("cert_analysis", {})
            ca = cert_data.get("issuer_org") or cert_data.get("issuer_cn") or "Unknown"

        if "Google" in ca or "GTS" in ca: ca = "Google Trust Services"
        elif "Let's Encrypt" in ca: ca = "Let's Encrypt"
        elif "DigiCert" in ca: ca = "DigiCert"

        cas[ca] = cas.get(ca, 0) + 1
        
    records = []
    for r in latest_results:
        ca = "Unknown"
        if r.full_result:
            cert_data = r.full_result.get("cert_analysis", {})
            ca = cert_data.get("issuer_org") or cert_data.get("issuer_cn") or "Unknown"
        if "Google" in ca or "GTS" in ca: ca = "Google Trust Services"
        elif "Let's Encrypt" in ca: ca = "Let's Encrypt"
        elif "DigiCert" in ca: ca = "DigiCert"
                
        pqc_status = "Quantum Resistant" if r.pqc_tier == "Elite" else "Non-Compliant" if r.pqc_tier in ["Legacy", "Critical"] else "At Risk"
        risk_score = 100 - ((r.final_score or 0) // 10)
        
        records.append({
            "id": r.id,
            "asset": r.hostname,
            "keyLength": f"{r.key_size}" if r.key_size else "Unknown",
            "tlsVersion": r.tls_version or "Unknown",
            "pqcStatus": pqc_status,
            "riskScore": min(100, max(0, risk_score)),
            "cipherSuite": r.cipher_name or "Unknown",
            "ca": ca
        })
        
    return {
        "stats": {
            "total_apps": total_apps,
            "sites_surveyed": total_apps,
            "active_certs": total_apps,
            "weak_crypto": weak_crypto,
            "cert_issues": sum(1 for r in latest_results if r.is_expired or r.is_self_signed)
        },
        "key_lengths": [{"name": k, "value": v} for k, v in key_lengths.items()],
        "ciphers": [{"name": k, "value": v} for k, v in ciphers.items()],
        "authorities": [{"name": k, "value": v} for k, v in cas.items()],
        "cbomRecords": records
    }
@router.get("/{scan_id}")
def get_cbom(scan_id: str, db: Session = Depends(get_db)):
    result = get_result_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")

    full = result.full_result or {}
    cbom = full.get("cbom", {})

    if not cbom:
        raise HTTPException(
            status_code=404,
            detail="No CBOM data available for this scan"
        )

    summary = cbom.get("summary", {})
    return {
        "hostname": result.hostname,
        "bom_format": cbom.get("bom_format"),
        "spec_version": cbom.get("spec_version"),
        "total_components": summary.get("total_components", 0),
        "vulnerable_components": summary.get("vulnerable_components", 0),
        "safe_components": summary.get("safe_components", 0),
        "pqc_ready": summary.get("pqc_ready", False),
        "components": cbom.get("components", []),
        "dependencies": cbom.get("dependencies", [])
    }


@router.get("/{scan_id}/summary")
def get_cbom_summary(scan_id: str, db: Session = Depends(get_db)):
    result = get_result_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")

    summary = generate_cbom_summary_export(result)
    return summary


@router.get("/{scan_id}/download")
def download_cbom(scan_id: str, db: Session = Depends(get_db)):
    result = get_result_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")

    full = result.full_result or {}
    cbom = full.get("cbom", {})

    if not cbom:
        raise HTTPException(
            status_code=404,
            detail="No CBOM data available for this scan"
        )

    cbom_json = format_cbom_download(cbom)
    filename = f"cbom-{result.hostname}-{scan_id[:8]}.json"

    return JSONResponse(
        content=cbom_json,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "application/json"
        }
    )
