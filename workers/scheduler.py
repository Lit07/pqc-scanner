from celery.schedules import crontab
from db.database import SessionLocal
from db.models import Asset
from backend.services.scan_service import create_scan_job
from workers.scan_worker import celery_app, process_scan_job
from utils.logger import get_logger


logger = get_logger("scheduler")

# Configure Celery Beat Schedule
celery_app.conf.beat_schedule = {
    # Run daily at 00:00 UTC
    "run-daily-asset-scans": {
        "task": "workers.scheduler.run_daily_asset_scans",
        "schedule": crontab(minute=0, hour=0),
    },
}


@celery_app.task(name="workers.scheduler.run_daily_asset_scans")
def run_daily_asset_scans():
    """
    Celery Beat periodic task that fetches all active managed Assets,
    creates ScanJobs for them, and queues them into the worker.
    """
    logger.info("Scheduler: starting daily asset scan sweep...")
    db = SessionLocal()
    
    try:
        active_assets = db.query(Asset).filter(Asset.is_active == True).all()
        logger.info(f"Scheduler: found {len(active_assets)} active endpoints. Queuing.")
        
        queued_count = 0
        for asset in active_assets:
            # We don't port-scan right now, assuming 443 is primary endpoint
            job = create_scan_job(db, hostname=asset.hostname, port=443)
            
            # Dispatch to worker async
            process_scan_job.delay(job.id)
            queued_count += 1
            
        logger.info(f"Scheduler finished. Queued {queued_count} assets.")
        
    except Exception as e:
        logger.error(f"Scheduler failed during generic scan sweep: {str(e)}")
    
    finally:
        db.close()
