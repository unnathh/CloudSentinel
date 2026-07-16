from datetime import datetime
from sqlalchemy import Integer, String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base

class AWSAccount(Base):
    __tablename__ = "aws_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    account_id: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    auth_type: Mapped[str] = mapped_column(String, nullable=False)  # "keys" or "role"
    access_key_id: Mapped[str] = mapped_column(String, nullable=True)  # encrypted
    secret_access_key: Mapped[str] = mapped_column(String, nullable=True)  # encrypted
    role_arn: Mapped[str] = mapped_column(String, nullable=True)
    region: Mapped[str] = mapped_column(String, default="us-east-1")
    last_scanned: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
