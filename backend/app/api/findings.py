from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List, Optional

from app.database import get_db
from app.models.scan import Finding, ScanResult
from app.schemas.finding import FindingResponse, FindingUpdate
from app.api.deps import RoleChecker

router = APIRouter(prefix="/findings", tags=["Findings"])

@router.get("", response_model=List[FindingResponse])
async def list_findings(
    scan_id: Optional[int] = None,
    severity: Optional[str] = None,
    service: Optional[str] = None,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst", "Viewer"]))
):
    query = select(Finding)

    # Resolve latest scan if scan_id not provided
    if scan_id is None:
        latest_scan_stmt = select(ScanResult).where(ScanResult.status == "completed").order_by(desc(ScanResult.started_at)).limit(1)
        latest_scan_res = await db.execute(latest_scan_stmt)
        latest_scan = latest_scan_res.scalars().first()
        if latest_scan:
            scan_id = latest_scan.id
        else:
            return []  # No scans run yet

    query = query.where(Finding.scan_id == scan_id)

    if severity:
        query = query.where(Finding.severity == severity)
    if service:
        query = query.where(Finding.service == service.upper())
    if status:
        query = query.where(Finding.status == status)

    result = await db.execute(query)
    return result.scalars().all()

@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst", "Viewer"]))
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding_status(
    finding_id: int,
    finding_update: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst"]))
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if finding_update.status not in ["open", "resolved", "ignored"]:
        raise HTTPException(status_code=400, detail="Invalid status. Must be 'open', 'resolved', or 'ignored'.")

    finding.status = finding_update.status
    await db.commit()
    await db.refresh(finding)
    return finding
