from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List, Dict, Any

class ScanResultBase(BaseModel):
    account_id: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str
    risk_score: float
    compliance_score: float

class ScanResultResponse(ScanResultBase):
    id: int

    class Config:
        from_attributes = True

class ResourceInventoryResponse(BaseModel):
    id: int
    scan_id: int
    service: str
    resource_type: str
    resource_id: str
    resource_name: str
    configuration: Dict[str, Any]

    class Config:
        from_attributes = True

class AttackPathResponse(BaseModel):
    id: int
    scan_id: int
    path_name: str
    node_chain: List[str]
    risk_level: str
    description: str

    class Config:
        from_attributes = True
