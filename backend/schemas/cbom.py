from pydantic import BaseModel
from typing import Optional, List


class CBOMComponent(BaseModel):
    name: str
    version: str
    component_type: str
    pqc_vulnerable: bool
    nist_replacement: Optional[str]
    quantum_attack: Optional[str]


class CBOMResponse(BaseModel):
    hostname: str
    bom_format: str
    spec_version: str
    total_components: int
    vulnerable_components: int
    safe_components: int
    pqc_ready: bool
    components: List[dict]
    dependencies: List[dict]


class CBOMSummary(BaseModel):
    hostname: str
    total_components: int
    vulnerable_count: int
    safe_count: int
    pqc_ready: bool
    replacements_needed: List[dict]
    replacement_count: int
