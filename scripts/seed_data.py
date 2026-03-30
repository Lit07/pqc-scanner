import sys
import uuid
import datetime

# Add root folder to sys.path so we can import from backend, db, utils
sys.path.append(".")

from db.database import SessionLocal, create_tables
from db.models import Asset
from utils.logger import get_logger

logger = get_logger("seed_data")


def seed_database():
    """Drops (if exists) and creates the tables, then inserts test assets."""
    logger.info("Initializing database schema...")
    create_tables()
    logger.info("Tables created successfully.")
    
    db = SessionLocal()
    try:
        # Check if we already have assets
        existing_count = db.query(Asset).count()
        if existing_count > 0:
            logger.info(f"Database contains {existing_count} assets already. Skipping seed.")
            return

        logger.info("Seeding standard test assets...")

        # Sample assets covering various risk profiles for demonstration
        demo_assets = [
            {"hostname": "google.com", "asset_type": "Search Engine", "owner": "Alphabet"},
            {"hostname": "cloudflare.com", "asset_type": "CDN & Proxy", "owner": "Cloudflare Inc"},
            {"hostname": "github.com", "asset_type": "DevOps Tooling", "owner": "Microsoft"},
            {"hostname": "badssl.com", "asset_type": "Testing Domain", "owner": "Public Domain"},
            {"hostname": "expired.badssl.com", "asset_type": "Testing Domain", "owner": "Public Domain"},
            {"hostname": "tls-v1-0.badssl.com", "asset_type": "Legacy System", "owner": "Public Domain"},
            {"hostname": "rc4.badssl.com", "asset_type": "Payment Gateway (Legacy)", "owner": "Public Domain"},
        ]

        inserted = 0
        for asset_data in demo_assets:
            # Check if it physically exists just in case
            if not db.query(Asset).filter(Asset.hostname == asset_data["hostname"]).first():
                asset = Asset(
                    id=str(uuid.uuid4()),
                    hostname=asset_data["hostname"],
                    asset_type=asset_data["asset_type"],
                    owner=asset_data["owner"],
                    is_active=True,
                    created_at=datetime.datetime.now(datetime.timezone.utc)
                )
                db.add(asset)
                inserted += 1

        db.commit()
        logger.info(f"Successfully seeded {inserted} assets.")

    except Exception as e:
        logger.error(f"Failed to seed database: {str(e)}")
        db.rollback()

    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
