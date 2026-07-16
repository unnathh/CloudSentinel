from datetime import datetime
from sqlalchemy import Integer, String, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base

class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    account_id: Mapped[int] = mapped_column(Integer, ForeignKey("aws_accounts.id", ondelete="CASCADE"), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String, default="running")  # running, completed, failed
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    compliance_score: Mapped[float] = mapped_column(Float, default=100.0)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    resources = relationship("ResourceInventory", back_populates="scan", cascade="all, delete-orphan")
    attack_paths = relationship("AttackPath", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False)
    rule_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False, index=True)  # Critical, High, Medium, Low, Info
    service: Mapped[str] = mapped_column(String, nullable=False, index=True)  # S3, EC2, IAM, etc.
    resource_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    region: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)
    evidence: Mapped[str] = mapped_column(String, nullable=True)  # JSON or text detail of configuration state
    recommendation: Mapped[str] = mapped_column(String, nullable=False)
    mitre_technique_id: Mapped[str] = mapped_column(String, nullable=True, index=True)
    mitre_technique_name: Mapped[str] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="open", index=True)  # open, resolved, ignored
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationship
    scan = relationship("ScanResult", back_populates="findings")


class ResourceInventory(Base):
    __tablename__ = "resource_inventory"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False)
    service: Mapped[str] = mapped_column(String, nullable=False, index=True)  # IAM, S3, EC2, KMS, VPC, RDS, Lambda, EBS, CloudTrail
    resource_type: Mapped[str] = mapped_column(String, nullable=False)  # User, Bucket, Instance, Key, Function, etc.
    resource_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    resource_name: Mapped[str] = mapped_column(String, nullable=False)
    configuration: Mapped[dict] = mapped_column(JSON, nullable=False)  # Raw configuration metadata

    # Relationship
    scan = relationship("ScanResult", back_populates="resources")


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False)
    path_name: Mapped[str] = mapped_column(String, nullable=False)
    node_chain: Mapped[list] = mapped_column(JSON, nullable=False)  # Array of node identifiers in path order
    risk_level: Mapped[str] = mapped_column(String, nullable=False)  # Critical, High, Medium, Low
    description: Mapped[str] = mapped_column(String, nullable=False)  # Explanation of why the path is exploitable

    # Relationship
    scan = relationship("ScanResult", back_populates="attack_paths")
