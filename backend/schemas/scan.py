from pydantic import BaseModel, Field
from typing import Optional, List


class ScanRequest(BaseModel):
    hostname: str = Field(..., description="Target hostname to scan")
    port: int = Field(default=443, ge=1, le=65535, description="Target port")
    probe_shadow: bool = Field(default=False, description="Probe for shadow assets")


class ScanJobResponse(BaseModel):
    job_id: str
    hostname: str
    port: int
    status: str
    message: str


class ScanStatusResponse(BaseModel):
    job_id: str
    hostname: str
    port: int
    status: str
    started_at: Optional[str]
    completed_at: Optional[str]
    error: Optional[str]
    scan_result_id: Optional[str]
