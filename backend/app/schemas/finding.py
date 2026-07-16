from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class FindingBase(BaseModel):
    rule_id: str
    title: str
    severity: str
    service: str
    resource_id: str
    region: str
    description: str
    evidence: Optional[str] = None
    recommendation: str
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    status: str

class FindingUpdate(BaseModel):
    status: str  # "open", "resolved", "ignored"

class FindingResponse(FindingBase):
    id: int
    scan_id: int
    created_at: datetime

    class Config:
        from_attributes = True
