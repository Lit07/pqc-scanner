from sqlalchemy.orm import Session
from db.models import ScanResult, ScanJob, TriggeredRule, CBOMEntry, Asset
from analysis.risk.scoring import calculate_enterprise_score
from utils.logger import get_logger

logger = get_logger(__name__)


def get_result_by_id(db: Session, scan_result_id: str) -> ScanResult:
    return db.query(ScanResult).filter(ScanResult.id == scan_result_id).first()


def get_result_by_job_id(db: Session, job_id: str) -> ScanResult:
    return (
        db.query(ScanResult)
        .filter(ScanResult.scan_job_id == job_id)
        .first()
    )


def get_results_by_hostname(
    db: Session,
    hostname: str,
    limit: int = 20,
    offset: int = 0
) -> list:
    return (
        db.query(ScanResult)
        .filter(ScanResult.hostname == hostname)
        .order_by(ScanResult.scanned_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def get_result_count_by_hostname(db: Session, hostname: str) -> int:
    return (
        db.query(ScanResult)
        .filter(ScanResult.hostname == hostname)
        .count()
    )


def get_triggered_rules_for_result(db: Session, scan_result_id: str) -> list:
    return (
        db.query(TriggeredRule)
        .filter(TriggeredRule.scan_result_id == scan_result_id)
        .all()
    )


def get_cbom_entries_for_result(db: Session, scan_result_id: str) -> list:
    return (
        db.query(CBOMEntry)
        .filter(CBOMEntry.scan_result_id == scan_result_id)
        .all()
    )


def compute_enterprise_score(db: Session, hostnames: list = None) -> dict:
    query = db.query(ScanResult)

    if hostnames:
        query = query.filter(ScanResult.hostname.in_(hostnames))

    latest_per_host = {}
    results = query.order_by(ScanResult.scanned_at.desc()).all()

    for result in results:
        if result.hostname not in latest_per_host:
            latest_per_host[result.hostname] = result

    asset_scores = []
    for hostname, result in latest_per_host.items():
        asset_scores.append({
            "hostname": hostname,
            "final_score": result.final_score or 0,
            "pqc_tier": result.pqc_tier or "Critical"
        })

    enterprise = calculate_enterprise_score(asset_scores)
    enterprise["assets"] = asset_scores
    return enterprise


def get_pqc_posture_summary(db: Session) -> dict:
    results = db.query(ScanResult).all()

    latest_per_host = {}
    for result in results:
        if result.hostname not in latest_per_host:
            latest_per_host[result.hostname] = result
        elif (result.scanned_at and latest_per_host[result.hostname].scanned_at
              and result.scanned_at > latest_per_host[result.hostname].scanned_at):
            latest_per_host[result.hostname] = result

    total = len(latest_per_host)
    tier_counts = {"Elite": 0, "Standard": 0, "Legacy": 0, "Critical": 0}
    key_type_dist = {}
    tls_version_dist = {}

    for hostname, result in latest_per_host.items():
        tier = result.pqc_tier or "Critical"
        if tier in tier_counts:
            tier_counts[tier] += 1

        kt = result.key_type or "Unknown"
        key_type_dist[kt] = key_type_dist.get(kt, 0) + 1

        tv = result.tls_version or "Unknown"
        tls_version_dist[tv] = tls_version_dist.get(tv, 0) + 1

    pqc_ready = tier_counts.get("Elite", 0)
    pqc_ready_pct = (pqc_ready / total * 100) if total > 0 else 0.0

    return {
        "total_assets": total,
        "elite_count": tier_counts["Elite"],
        "standard_count": tier_counts["Standard"],
        "legacy_count": tier_counts["Legacy"],
        "critical_count": tier_counts["Critical"],
        "pqc_ready_percentage": round(pqc_ready_pct, 2),
        "key_type_distribution": key_type_dist,
        "tls_version_distribution": tls_version_dist
    }


def get_all_assets(db: Session, limit: int = 100, offset: int = 0) -> list:
    return (
        db.query(Asset)
        .filter(Asset.is_active == True)
        .order_by(Asset.last_scanned.desc().nullslast())
        .offset(offset)
        .limit(limit)
        .all()
    )


def get_asset_count(db: Session) -> int:
    return db.query(Asset).filter(Asset.is_active == True).count()


def get_asset_by_id(db: Session, asset_id: str) -> Asset:
    return db.query(Asset).filter(Asset.id == asset_id).first()


def get_asset_by_hostname(db: Session, hostname: str) -> Asset:
    return db.query(Asset).filter(Asset.hostname == hostname).first()
