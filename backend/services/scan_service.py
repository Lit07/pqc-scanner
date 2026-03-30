import datetime
import uuid
from sqlalchemy.orm import Session
from db.models import ScanJob, ScanResult, TriggeredRule, CBOMEntry, Asset
from analysis.aggregator import run_full_scan
from analysis.cbom.cbom_formatter import format_cbom_for_db
from utils.logger import get_logger

logger = get_logger(__name__)


def create_scan_job(db: Session, hostname: str, port: int = 443) -> ScanJob:
    job_id = str(uuid.uuid4())
    job = ScanJob(
        id=job_id,
        hostname=hostname,
        port=port,
        status="pending",
        started_at=datetime.datetime.now(datetime.timezone.utc)
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    logger.info(f"Created scan job {job_id} for {hostname}:{port}")
    return job


def run_scan_for_job(db: Session, job_id: str) -> ScanResult:
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        raise ValueError(f"Scan job {job_id} not found")

    job.status = "running"
    db.commit()
    logger.info(f"Starting scan for job {job_id}: {job.hostname}:{job.port}")

    try:
        previous_scan = _get_previous_scan_data(db, job.hostname)
        scan_history = _get_scan_history_data(db, job.hostname)

        full_result = run_full_scan(
            hostname=job.hostname,
            port=job.port,
            previous_scan=previous_scan,
            scan_history=scan_history,
            probe_shadow=False
        )

        result = _persist_scan_result(db, job, full_result)

        job.status = "completed"
        job.completed_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()

        _update_asset_record(db, job.hostname, result)

        logger.info(f"Scan completed for job {job_id}, result_id={result.id}")
        return result

    except Exception as e:
        job.status = "failed"
        job.error = str(e)
        job.completed_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()
        logger.error(f"Scan failed for job {job_id}: {e}")
        raise


def get_scan_job(db: Session, job_id: str) -> ScanJob:
    return db.query(ScanJob).filter(ScanJob.id == job_id).first()


def get_recent_scans(db: Session, hostname: str, limit: int = 10) -> list:
    return (
        db.query(ScanResult)
        .filter(ScanResult.hostname == hostname)
        .order_by(ScanResult.scanned_at.desc())
        .limit(limit)
        .all()
    )


def _persist_scan_result(db: Session, job: ScanJob, full_result: dict) -> ScanResult:
    result_id = str(uuid.uuid4())
    summary = full_result.get("summary", {})
    risk_engine = full_result.get("risk_engine", {})
    risk_score = risk_engine.get("risk_score", {})
    pqc_class = full_result.get("pqc_classification", {})
    hndl = full_result.get("hndl_assessment", {})
    endpoint = full_result.get("endpoint_classification", {})

    result = ScanResult(
        id=result_id,
        scan_job_id=job.id,
        hostname=job.hostname,
        ip=full_result.get("tls_scan", {}).get("ip"),
        tls_version=full_result.get("tls_scan", {}).get("tls_version"),
        cipher_name=full_result.get("tls_scan", {}).get("cipher_name"),
        cipher_bits=full_result.get("tls_scan", {}).get("cipher_bits"),
        key_type=full_result.get("cert_analysis", {}).get("key_type"),
        key_size=full_result.get("cert_analysis", {}).get("key_size"),
        curve_name=full_result.get("cert_analysis", {}).get("curve_name"),
        is_expired=full_result.get("cert_analysis", {}).get("is_expired", False),
        days_to_expiry=full_result.get("cert_analysis", {}).get("days_to_expiry"),
        is_self_signed=full_result.get("cert_analysis", {}).get("is_self_signed", False),
        is_wildcard=full_result.get("cert_analysis", {}).get("is_wildcard", False),
        forward_secrecy=full_result.get("cipher_analysis", {}).get("forward_secrecy", False),
        final_score=risk_score.get("final_score"),
        pqc_tier=risk_score.get("pqc_tier"),
        pqc_score=pqc_class.get("pqc_score"),
        pqc_classification=pqc_class.get("pqc_classification"),
        hndl_threat_level=hndl.get("hndl_threat_level"),
        hndl_score=hndl.get("adjusted_hndl_score"),
        endpoint_type=endpoint.get("endpoint_type"),
        sensitivity=endpoint.get("sensitivity"),
        grade=summary.get("grade"),
        shadow_asset_count=summary.get("shadow_asset_count", 0),
        anomaly_count=summary.get("anomaly_count", 0),
        has_regression=summary.get("has_regression", False),
        full_result=full_result
    )
    db.add(result)

    triggered = risk_score.get("triggered_rules", [])
    for rule in triggered:
        rule_entry = TriggeredRule(
            id=str(uuid.uuid4()),
            scan_result_id=result_id,
            rule_id=rule.get("rule_id", rule.get("id", "")),
            rule_name=rule.get("rule_name", rule.get("name", "")),
            severity=rule.get("severity"),
            category=rule.get("category"),
            message=rule.get("message", rule.get("rule_name", "")),
            score_penalty=rule.get("adjusted_penalty", rule.get("score_penalty", 0)),
            pqc_impact=rule.get("pqc_impact", False)
        )
        db.add(rule_entry)

    cbom_data = full_result.get("cbom", {})
    if cbom_data:
        cbom_entries = format_cbom_for_db(cbom_data, result_id)
        for entry in cbom_entries:
            cbom_entry = CBOMEntry(
                id=str(uuid.uuid4()),
                **entry
            )
            db.add(cbom_entry)

    db.commit()
    db.refresh(result)
    return result


def _get_previous_scan_data(db: Session, hostname: str) -> dict:
    last_result = (
        db.query(ScanResult)
        .filter(ScanResult.hostname == hostname)
        .order_by(ScanResult.scanned_at.desc())
        .first()
    )
    if not last_result or not last_result.full_result:
        return None

    full = last_result.full_result
    combined = {
        "hostname": hostname,
        "ip": last_result.ip,
        "tls_version": last_result.tls_version,
        "cipher_name": last_result.cipher_name,
        "cipher_bits": last_result.cipher_bits,
        "key_type": last_result.key_type,
        "key_size": last_result.key_size,
        "forward_secrecy": last_result.forward_secrecy,
        "is_expired": last_result.is_expired,
        "is_self_signed": last_result.is_self_signed,
        "issuer_cn": full.get("cert_analysis", {}).get("issuer_cn"),
        "san_domains": full.get("cert_analysis", {}).get("san_domains", []),
        "final_score": last_result.final_score,
        "scanned_at": last_result.scanned_at.isoformat()
            if last_result.scanned_at else None,
        "port": full.get("port")
    }
    return combined


def _get_scan_history_data(db: Session, hostname: str, limit: int = 10) -> list:
    results = (
        db.query(ScanResult)
        .filter(ScanResult.hostname == hostname)
        .order_by(ScanResult.scanned_at.asc())
        .limit(limit)
        .all()
    )
    history = []
    for r in results:
        history.append({
            "hostname": hostname,
            "tls_version": r.tls_version,
            "cipher_name": r.cipher_name,
            "key_size": r.key_size,
            "forward_secrecy": r.forward_secrecy,
            "final_score": r.final_score,
            "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None
        })
    return history


def _update_asset_record(db: Session, hostname: str, result: ScanResult):
    asset = db.query(Asset).filter(Asset.hostname == hostname).first()
    if asset:
        asset.ip = result.ip
        asset.last_scanned = datetime.datetime.now(datetime.timezone.utc)
        asset.latest_score = result.final_score
        asset.latest_tier = result.pqc_tier
        db.commit()
