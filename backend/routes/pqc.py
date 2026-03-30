from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from db.database import get_db
from backend.services.analysis_service import (
    get_result_by_id,
    get_pqc_posture_summary
)
from utils.constants import NIST_PQC_ALGORITHMS
from utils.logger import get_logger

router = APIRouter(prefix="/pqc", tags=["PQC"])
logger = get_logger(__name__)


@router.get("/algorithms")
def get_pqc_algorithms():
    return {
        "algorithms": NIST_PQC_ALGORITHMS,
        "total": len(NIST_PQC_ALGORITHMS),
        "note": "NIST Post-Quantum Cryptography standardized algorithms"
    }


@router.get("/posture")
def get_posture_summary(db: Session = Depends(get_db)):
    summary = get_pqc_posture_summary(db)
    return summary


@router.get("/{scan_id}")
def get_pqc_classification(scan_id: str, db: Session = Depends(get_db)):
    result = get_result_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")

    full = result.full_result or {}
    pqc = full.get("pqc_classification", {})

    return {
        "hostname": result.hostname,
        "pqc_score": pqc.get("pqc_score"),
        "pqc_classification": pqc.get("pqc_classification"),
        "classification_description": pqc.get("classification_description"),
        "classification_color": pqc.get("classification_color"),
        "tier_number": pqc.get("tier_number"),
        "pqc_ready": pqc.get("pqc_ready"),
        "hybrid_mode_possible": pqc.get("hybrid_mode_possible"),
        "estimated_quantum_risk_year": pqc.get("estimated_quantum_risk_year"),
        "overall_verdict": pqc.get("overall_verdict"),
        "immediate_actions": pqc.get("immediate_actions", []),
        "nist_replacements": pqc.get("nist_replacements", []),
        "quantum_attack_vectors": pqc.get("quantum_attack_vectors", [])
    }


@router.get("/{scan_id}/migration")
def get_migration_plan(scan_id: str, db: Session = Depends(get_db)):
    result = get_result_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")

    full = result.full_result or {}
    migration = full.get("migration_plan", {})

    return {
        "hostname": result.hostname,
        "key_type": migration.get("key_type"),
        "current_posture_summary": migration.get("current_posture_summary"),
        "phases": migration.get("phases", []),
        "immediate_actions": migration.get("immediate_actions", []),
        "full_migration_steps": migration.get("full_migration_steps", []),
        "estimated_total_days": migration.get("estimated_total_days"),
        "nist_standards_applicable": migration.get("nist_standards_applicable", []),
        "breaking_changes": migration.get("breaking_changes", False),
        "priority_score": migration.get("priority_score")
    }
