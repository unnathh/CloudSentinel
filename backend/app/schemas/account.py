from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class AWSAccountBase(BaseModel):
    name: str
    account_id: str
    auth_type: str  # "keys" or "role"
    role_arn: Optional[str] = None
    region: Optional[str] = "us-east-1"

class AWSAccountCreate(AWSAccountBase):
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None

class AWSAccountUpdate(BaseModel):
    name: Optional[str] = None
    role_arn: Optional[str] = None
    region: Optional[str] = None
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None

class AWSAccountResponse(AWSAccountBase):
    id: int
    last_scanned: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True
