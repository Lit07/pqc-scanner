import time
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from db.database import get_db

router = APIRouter(prefix="/health", tags=["Health"])

_start_time = time.time()


@router.get("")
def health_check(db: Session = Depends(get_db)):
    db_connected = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_connected = False

    return {
        "status": "ok" if db_connected else "degraded",
        "version": "1.0.0",
        "api_version": "v1",
        "db_connected": db_connected,
        "uptime_seconds": round(time.time() - _start_time, 2),
        "service": "pqc-scanner"
    }
