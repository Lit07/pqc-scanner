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

router = APIRouter(prefix="/cbom", tags=["CBOM"])
logger = get_logger(__name__)


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
