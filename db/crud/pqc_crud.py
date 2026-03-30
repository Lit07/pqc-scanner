from sqlalchemy.orm import Session
from sqlalchemy import func
from db.models import ScanResult, CBOMEntry


def get_cbom_by_scan(db: Session, scan_result_id: str) -> list:
    return db.query(CBOMEntry).filter(
        CBOMEntry.scan_result_id == scan_result_id
    ).all()


def get_all_cbom_entries(db: Session, limit: int = 200) -> list:
    return db.query(CBOMEntry).limit(limit).all()


def get_vulnerable_cbom_entries(db: Session) -> list:
    return db.query(CBOMEntry).filter(
        CBOMEntry.is_pqc_vulnerable == True
    ).all()


def get_cbom_algorithm_distribution(db: Session) -> dict:
    results = db.query(
        CBOMEntry.algorithm,
        func.count(CBOMEntry.id)
    ).group_by(CBOMEntry.algorithm).all()
    return {algo: count for algo, count in results if algo}


def get_pqc_readiness_summary(db: Session) -> dict:
    total = db.query(func.count(ScanResult.id)).scalar() or 0
    elite = db.query(func.count(ScanResult.id)).filter(
        ScanResult.pqc_tier == "Elite"
    ).scalar() or 0
    standard = db.query(func.count(ScanResult.id)).filter(
        ScanResult.pqc_tier == "Standard"
    ).scalar() or 0
    legacy = db.query(func.count(ScanResult.id)).filter(
        ScanResult.pqc_tier == "Legacy"
    ).scalar() or 0
    critical = db.query(func.count(ScanResult.id)).filter(
        ScanResult.pqc_tier == "Critical"
    ).scalar() or 0

    return {
        "total_assets": total,
        "elite_count": elite,
        "standard_count": standard,
        "legacy_count": legacy,
        "critical_count": critical,
        "elite_percentage": round((elite / total * 100), 2) if total else 0,
        "standard_percentage": round((standard / total * 100), 2) if total else 0,
        "legacy_percentage": round((legacy / total * 100), 2) if total else 0,
        "critical_percentage": round((critical / total * 100), 2) if total else 0,
        "pqc_ready_count": elite,
        "pqc_ready_percentage": round((elite / total * 100), 2) if total else 0
    }


def get_key_type_distribution(db: Session) -> dict:
    results = db.query(
        ScanResult.key_type,
        func.count(ScanResult.id)
    ).group_by(ScanResult.key_type).all()
    return {k: v for k, v in results if k}


def get_cipher_distribution(db: Session) -> dict:
    results = db.query(
        ScanResult.cipher_name,
        func.count(ScanResult.id)
    ).group_by(ScanResult.cipher_name).all()
    return {c: v for c, v in results if c}


def get_tls_version_distribution(db: Session) -> dict:
    results = db.query(
        ScanResult.tls_version,
        func.count(ScanResult.id)
    ).group_by(ScanResult.tls_version).all()
    return {t: v for t, v in results if t}


def get_assets_needing_migration(db: Session) -> list:
    return db.query(ScanResult).filter(
        ScanResult.pqc_tier.in_(["Critical", "Legacy"]),
        ScanResult.key_type.in_(["RSA", "EC", "DSA"])
    ).order_by(ScanResult.final_score.asc()).all()