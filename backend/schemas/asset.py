from pydantic import BaseModel, Field
from typing import Optional, List


class AssetCreate(BaseModel):
    hostname: str = Field(..., description="Hostname of the asset")
    asset_type: Optional[str] = Field(None, description="Type of asset")
    owner: Optional[str] = Field(None, description="Asset owner")


class AssetResponse(BaseModel):
    id: str
    hostname: str
    ip: Optional[str]
    asset_type: Optional[str]
    owner: Optional[str]
    last_scanned: Optional[str]
    latest_score: Optional[int]
    latest_tier: Optional[str]
    is_active: bool
    cert_expiry_days: Optional[int] = None


class AssetListResponse(BaseModel):
    total: int
    assets: List[AssetResponse]
