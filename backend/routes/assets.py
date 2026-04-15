import uuid
import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from db.database import get_db
from db.models import Asset, ScanResult
from sqlalchemy import func
from backend.schemas.asset import AssetCreate, AssetResponse, AssetListResponse
from backend.services.analysis_service import (
    get_all_assets,
    get_asset_count,
    get_asset_by_id,
    get_asset_by_hostname
)
from utils.validators import validate_hostname
from utils.logger import get_logger

router = APIRouter(prefix="/assets", tags=["Assets"])
logger = get_logger(__name__)

@router.get("/heatmap")
def get_quantum_heatmap(db: Session = Depends(get_db)):
    subquery = db.query(
        ScanResult.hostname, 
        func.max(ScanResult.scanned_at).label("max_scanned_at")
    ).group_by(ScanResult.hostname).subquery()
    
    latest_results = db.query(ScanResult).join(
        subquery,
        (ScanResult.hostname == subquery.c.hostname) & 
        (ScanResult.scanned_at == subquery.c.max_scanned_at)
    ).all()
    
    nodes = []
    for r in latest_results:
        # Generate some synthetic coordinates for visual clustering based on hndl score
        x = hash(r.hostname) % 100
        y = (hash(r.hostname) // 100) % 100
        
        nodes.append({
            "id": r.id,
            "hostname": r.hostname,
            "ip": r.ip or "Unknown",
            "type": r.endpoint_type or "Gateway",
            "hndlScore": r.hndl_score or 50,
            "hndlLevel": r.hndl_threat_level or "Elevated",
            "pqcReady": r.pqc_classification == "Elite",
            "grade": r.grade or "C",
            "cryptoScore": r.final_score or 500,
            "x": x,
            "y": y
        })
        
    return {"nodes": nodes}


@router.get("", response_model=AssetListResponse)
def list_assets(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db)
):
    assets = get_all_assets(db, limit, offset)
    total = get_asset_count(db)

    items = []
    for a in assets:
        latest_scan = db.query(ScanResult).filter(ScanResult.hostname == a.hostname).order_by(ScanResult.scanned_at.desc()).first()
        items.append(AssetResponse(
            id=a.id,
            hostname=a.hostname,
            ip=a.ip or (latest_scan.ip if latest_scan else None),
            asset_type=a.asset_type,
            owner=a.owner,
            last_scanned=a.last_scanned.isoformat() if a.last_scanned else None,
            latest_score=a.latest_score,
            latest_tier=a.latest_tier,
            is_active=a.is_active,
            cert_expiry_days=latest_scan.days_to_expiry if latest_scan else None
        ))

    return AssetListResponse(total=total, assets=items)


@router.post("", response_model=AssetResponse, status_code=201)
def create_asset(request: AssetCreate, db: Session = Depends(get_db)):
    try:
        hostname = validate_hostname(request.hostname)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    existing = get_asset_by_hostname(db, hostname)
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Asset {hostname} already exists"
        )

    asset = Asset(
        id=str(uuid.uuid4()),
        hostname=hostname,
        asset_type=request.asset_type,
        owner=request.owner,
        is_active=True,
        created_at=datetime.datetime.now(datetime.timezone.utc)
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    logger.info(f"Created asset: {hostname}")

    return AssetResponse(
        id=asset.id,
        hostname=asset.hostname,
        ip=asset.ip,
        asset_type=asset.asset_type,
        owner=asset.owner,
        last_scanned=None,
        latest_score=asset.latest_score,
        latest_tier=asset.latest_tier,
        is_active=asset.is_active
    )


@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(asset_id: str, db: Session = Depends(get_db)):
    asset = get_asset_by_id(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    latest_scan = db.query(ScanResult).filter(ScanResult.hostname == asset.hostname).order_by(ScanResult.scanned_at.desc()).first()
    return AssetResponse(
        id=asset.id,
        hostname=asset.hostname,
        ip=asset.ip or (latest_scan.ip if latest_scan else None),
        asset_type=asset.asset_type,
        owner=asset.owner,
        last_scanned=asset.last_scanned.isoformat() if asset.last_scanned else None,
        latest_score=asset.latest_score,
        latest_tier=asset.latest_tier,
        is_active=asset.is_active,
        cert_expiry_days=latest_scan.days_to_expiry if latest_scan else None
    )


@router.delete("/{asset_id}", status_code=204)
def delete_asset(asset_id: str, db: Session = Depends(get_db)):
    asset = get_asset_by_id(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    asset.is_active = False
    db.commit()
    logger.info(f"Deactivated asset: {asset.hostname}")
    return None
