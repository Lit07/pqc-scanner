import sys
import traceback
from db.database import SessionLocal
from backend.services.scan_service import create_scan_job, run_scan_for_job

def test():
    db = SessionLocal()
    try:
        print("Creating job...")
        job = create_scan_job(db, "google.com", 443)
        print("Running scan...")
        res = run_scan_for_job(db, job.id)
        print("Success! Asset saved.")
    except Exception as e:
        print("Failed!")
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    test()
