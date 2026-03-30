from sqlalchemy.orm import Session
from db.models import ScanJob, ScanResult, TriggeredRule, CBOMEntry, Asset
import uuid
import datetime


def create_scan_job(db: Session, hostname: str, port: int, user_id: str) -> ScanJob:
    job = ScanJob(
        id=str(uuid.uuid4()),
        user_id=user_id,
        hostname=hostname,
        port=port,
        status="pending"
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def get_scan_job(db: Session, scan_id: str) -> ScanJob:
    return db.query(ScanJob).filter(ScanJob.id == scan_id).first()


def get_scan_jobs_by_user(db: Session, user_id: str, limit: int = 50) -> list:
    return db.query(ScanJob).filter(
        ScanJob.user_id == user_id
    ).order_by(ScanJob.started_at.desc()).limit(limit).all()


def update_scan_job_status(
    db: Session,
    scan_id: str,
    status: str,
    error: str = None
) -> ScanJob:
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if job:
        job.status = status
        job.completed_at = datetime.datetime.now(datetime.timezone.utc)
        if error:
            job.error = error
        db.commit()
        db.refresh(job)
    return job


def delete_scan_job(db: Session, scan_id: str) -> bool:
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if job:
        db.delete(job)
        db.commit()
        return True
    return False