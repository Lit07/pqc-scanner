from sqlalchemy.orm import Session
from sqlalchemy import func
from db.models import ScanResult, TriggeredRule


def get_triggered_rules_by_scan(
    db: Session,
    scan_result_id: str
) -> list:
    return db.query(TriggeredRule).filter(
        TriggeredRule.scan_result_id == scan_result_id
    ).all()


def get_rules_by_severity(
    db: Session,
    severity: str,
    limit: int = 50
) -> list:
    return db.query(TriggeredRule).filter(
        TriggeredRule.severity == severity
    ).limit(limit).all()


def get_critical_rules_count(db: Session) -> int:
    return db.query(func.count(TriggeredRule.id)).filter(
        TriggeredRule.severity == "CRITICAL"
    ).scalar()


def get_pqc_impacting_rules(db: Session, limit: int = 50) -> list:
    return db.query(TriggeredRule).filter(
        TriggeredRule.pqc_impact == True
    ).limit(limit).all()


def get_risk_distribution(db: Session) -> dict:
    results = db.query(
        ScanResult.pqc_tier,
        func.count(ScanResult.id)
    ).group_by(ScanResult.pqc_tier).all()
    return {tier: count for tier, count in results}


def get_average_score(db: Session) -> float:
    avg = db.query(func.avg(ScanResult.final_score)).scalar()
    return round(float(avg), 2) if avg else 0.0


def get_score_distribution(db: Session) -> dict:
    results = db.query(ScanResult.final_score).all()
    scores = [r[0] for r in results if r[0] is not None]
    if not scores:
        return {}
    return {
        "min": min(scores),
        "max": max(scores),
        "avg": round(sum(scores) / len(scores), 2),
        "count": len(scores)
    }


def get_hndl_distribution(db: Session) -> dict:
    results = db.query(
        ScanResult.hndl_threat_level,
        func.count(ScanResult.id)
    ).group_by(ScanResult.hndl_threat_level).all()
    return {level: count for level, count in results if level}