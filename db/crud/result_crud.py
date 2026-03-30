from sqlalchemy.orm import Session
from db.models import ScanResult, TriggeredRule, CBOMEntry
import uuid
import datetime


def create_scan_result(
    db: Session,
    scan_job_id: str,
    full_result: dict
) -> ScanResult:
    summary = full_result.get("summary", {})
    tls = full_result.get("tls_scan", {})
    cert = full_result.get("cert_analysis", {})
    cipher = full_result.get("cipher_analysis", {})
    risk = full_result.get("risk_engine", {}).get("risk_score", {})
    pqc = full_result.get("pqc_classification", {})
    hndl = full_result.get("hndl_assessment", {})
    endpoint = full_result.get("endpoint_classification", {})
    anomaly = full_result.get("anomalies", {})
    shadow = full_result.get("shadow_assets", {})

    scan_result = ScanResult(
        id=str(uuid.uuid4()),
        scan_job_id=scan_job_id,
        hostname=full_result.get("hostname"),
        ip=tls.get("ip"),
        tls_version=tls.get("tls_version"),
        cipher_name=tls.get("cipher_name"),
        cipher_bits=tls.get("cipher_bits"),
        key_type=cert.get("key_type"),
        key_size=cert.get("key_size"),
        curve_name=cert.get("curve_name"),
        is_expired=cert.get("is_expired", False),
        days_to_expiry=cert.get("days_to_expiry"),
        is_self_signed=cert.get("is_self_signed", False),
        is_wildcard=cert.get("is_wildcard", False),
        forward_secrecy=cipher.get("forward_secrecy", False),
        final_score=risk.get("final_score"),
        pqc_tier=risk.get("pqc_tier"),
        pqc_score=pqc.get("pqc_score"),
        pqc_classification=pqc.get("pqc_classification"),
        hndl_threat_level=hndl.get("hndl_threat_level"),
        hndl_score=hndl.get("adjusted_hndl_score"),
        endpoint_type=endpoint.get("endpoint_type"),
        sensitivity=endpoint.get("sensitivity"),
        grade=summary.get("grade"),
        shadow_asset_count=shadow.get("total_shadow_count", 0),
        anomaly_count=anomaly.get("anomaly_count", 0),
        has_regression=anomaly.get("has_regression", False),
        full_result=full_result
    )
    db.add(scan_result)
    db.commit()
    db.refresh(scan_result)

    triggered = full_result.get("risk_engine", {}).get("triggered_rules", [])
    for rule in triggered:
        tr = TriggeredRule(
            id=str(uuid.uuid4()),
            scan_result_id=scan_result.id,
            rule_id=rule.get("id"),
            rule_name=rule.get("name"),
            severity=rule.get("severity"),
            category=rule.get("category"),
            message=rule.get("message"),
            score_penalty=rule.get("score_penalty"),
            pqc_impact=rule.get("pqc_impact", False)
        )
        db.add(tr)

    cbom_entries = full_result.get("cbom", {}).get("components", [])
    for entry in cbom_entries:
        ce = CBOMEntry(
            id=str(uuid.uuid4()),
            scan_result_id=scan_result.id,
            hostname=full_result.get("hostname"),
            component_type=entry.get("component_type"),
            algorithm=entry.get("algorithm"),
            key_size=entry.get("key_size"),
            tls_version=entry.get("tls_version"),
            cipher_suite=entry.get("cipher_suite"),
            certificate_authority=entry.get("certificate_authority"),
            is_pqc_vulnerable=entry.get("is_pqc_vulnerable", True),
            nist_replacement=entry.get("nist_replacement")
        )
        db.add(ce)

    db.commit()
    return scan_result


def get_scan_result(db: Session, scan_job_id: str) -> ScanResult:
    return db.query(ScanResult).filter(
        ScanResult.scan_job_id == scan_job_id
    ).first()


def get_results_by_hostname(
    db: Session,
    hostname: str,
    limit: int = 10
) -> list:
    return db.query(ScanResult).filter(
        ScanResult.hostname == hostname
    ).order_by(ScanResult.scanned_at.desc()).limit(limit).all()


def get_all_results(db: Session, limit: int = 100) -> list:
    return db.query(ScanResult).order_by(
        ScanResult.scanned_at.desc()
    ).limit(limit).all()


def get_high_risk_results(db: Session, limit: int = 20) -> list:
    return db.query(ScanResult).filter(
        ScanResult.pqc_tier.in_(["Critical", "Legacy"])
    ).order_by(ScanResult.final_score.asc()).limit(limit).all()


def get_results_by_tier(db: Session, tier: str) -> list:
    return db.query(ScanResult).filter(
        ScanResult.pqc_tier == tier
    ).order_by(ScanResult.scanned_at.desc()).all()


def get_expiring_certs(db: Session, days: int = 30) -> list:
    return db.query(ScanResult).filter(
        ScanResult.days_to_expiry <= days,
        ScanResult.days_to_expiry >= 0
    ).order_by(ScanResult.days_to_expiry.asc()).all()


def delete_scan_result(db: Session, result_id: str) -> bool:
    result = db.query(ScanResult).filter(ScanResult.id == result_id).first()
    if result:
        db.delete(result)
        db.commit()
        return True
    return False