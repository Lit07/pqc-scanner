import os
from celery import Celery
from db.database import SessionLocal
from backend.services.scan_service import run_scan_for_job
from utils.logger import get_logger


logger = get_logger("scan_worker")

# Initialize Celery app
# Defaults to localhost Redis if REDIS_URL not provided
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "pqc_scanner",
    broker=REDIS_URL,
    backend=REDIS_URL
)

# Optional configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600  # 1 hour max
)


@celery_app.task(bind=True, name="process_scan_job", max_retries=3)
def process_scan_job(self, job_id: str):
    """
    Celery task that receives a job_id, opens a DB session,
    and executes the full PQC scan pipeline asynchronously.
    """
    logger.info(f"Worker picked up scan job {job_id}")
    
    db = SessionLocal()
    try:
        # Run the full orchestrator pipeline 
        result = run_scan_for_job(db, job_id)
        logger.info(f"Worker completed scan job {job_id} successfully. Score: {result.final_score}")
        return {"status": "success", "result_id": result.id, "score": result.final_score}
        
    except Exception as e:
        logger.error(f"Worker failed on scan job {job_id}: {str(e)}")
        # If it's a network/transient error, you could self.retry(exc=e, countdown=60)
        raise e
        
    finally:
        db.close()
