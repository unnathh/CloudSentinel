from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List, Optional

from app.database import get_db
from app.models.scan import ResourceInventory, ScanResult
from app.schemas.scan import ResourceInventoryResponse
from app.api.deps import RoleChecker

router = APIRouter(prefix="/resources", tags=["Resource Inventory"])

@router.get("", response_model=List[ResourceInventoryResponse])
async def list_resources(
    scan_id: Optional[int] = None,
    service: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst", "Viewer"]))
):
    query = select(ResourceInventory)

    # Resolve latest scan if scan_id not provided
    if scan_id is None:
        latest_scan_stmt = select(ScanResult).where(ScanResult.status == "completed").order_by(desc(ScanResult.started_at)).limit(1)
        latest_scan_res = await db.execute(latest_scan_stmt)
        latest_scan = latest_scan_res.scalars().first()
        if latest_scan:
            scan_id = latest_scan.id
        else:
            return []  # No scans run yet

    query = query.where(ResourceInventory.scan_id == scan_id)

    if service:
        query = query.where(ResourceInventory.service == service.upper())

    result = await db.execute(query)
    return result.scalars().all()

@router.get("/{resource_id}", response_model=ResourceInventoryResponse)
async def get_resource(
    resource_id: str,
    scan_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst", "Viewer"]))
):
    query = select(ResourceInventory).where(ResourceInventory.resource_id == resource_id)
    if scan_id:
        query = query.where(ResourceInventory.scan_id == scan_id)
    else:
        # Fall back to latest scan containing this resource
        query = query.order_by(desc(ResourceInventory.id))

    result = await db.execute(query)
    res = result.scalars().first()
    if not res:
        raise HTTPException(status_code=404, detail="Resource not found")
    return res
