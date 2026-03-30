from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from db.database import get_db
from backend.schemas.scan import ScanRequest, ScanJobResponse, ScanStatusResponse
from backend.services.scan_service import create_scan_job, run_scan_for_job, get_scan_job
from utils.validators import validate_hostname, validate_port
from utils.logger import get_logger

router = APIRouter(prefix="/scan", tags=["Scan"])
logger = get_logger(__name__)


def _run_scan_background(job_id: str):
    from db.database import SessionLocal
    db = SessionLocal()
    try:
        run_scan_for_job(db, job_id)
    except Exception as e:
        logger.error(f"Background scan failed for job {job_id}: {e}")
    finally:
        db.close()


@router.post("", response_model=ScanJobResponse)
def submit_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    try:
        hostname = validate_hostname(request.hostname)
        port = validate_port(request.port)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    job = create_scan_job(db, hostname, port)

    background_tasks.add_task(_run_scan_background, job.id)

    return ScanJobResponse(
        job_id=job.id,
        hostname=job.hostname,
        port=job.port,
        status=job.status,
        message=f"Scan queued for {hostname}:{port}"
    )


@router.get("/{job_id}", response_model=ScanStatusResponse)
def get_scan_status(job_id: str, db: Session = Depends(get_db)):
    job = get_scan_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job {job_id} not found")

    scan_result_id = None
    if job.result:
        scan_result_id = job.result.id

    return ScanStatusResponse(
        job_id=job.id,
        hostname=job.hostname,
        port=job.port,
        status=job.status,
        started_at=job.started_at.isoformat() if job.started_at else None,
        completed_at=job.completed_at.isoformat() if job.completed_at else None,
        error=job.error,
        scan_result_id=scan_result_id
    )
