from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List, Optional, Dict, Any

from app.database import get_db
from app.models.scan import ScanResult, ResourceInventory, AttackPath
from app.schemas.graph import CytoscapeGraphResponse
from app.schemas.scan import AttackPathResponse
from app.analyzers.graph_analyzer import GraphAnalyzer
from app.api.deps import RoleChecker

router = APIRouter(prefix="/graph", tags=["Security Graph & Attack Paths"])

@router.get("", response_model=CytoscapeGraphResponse)
async def get_security_graph(
    scan_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst", "Viewer"]))
):
    # Resolve latest scan if scan_id not provided
    if scan_id is None:
        latest_scan_stmt = select(ScanResult).where(ScanResult.status == "completed").order_by(desc(ScanResult.started_at)).limit(1)
        latest_scan_res = await db.execute(latest_scan_stmt)
        latest_scan = latest_scan_res.scalars().first()
        if latest_scan:
            scan_id = latest_scan.id
        else:
            return {"nodes": [], "edges": []}  # No scans run yet

    # Fetch all ResourceInventory records for this scan
    stmt = select(ResourceInventory).where(ResourceInventory.scan_id == scan_id)
    res_list = await db.execute(stmt)
    resources = res_list.scalars().all()

    # Reconstruct the collected configuration layout
    raw_data = {
        "iam": {
            "users": [],
            "roles": [],
            "groups": [],
            "policies": [],
            "password_policy": {}
        },
        "s3": [],
        "ec2": [],
        "vpc": {
            "security_groups": [],
            "vpcs": [],
            "route_tables": [],
            "nacls": []
        },
        "cloudtrail": [],
        "kms": [],
        "lambda": [],
        "rds": [],
        "ebs": {
            "volumes": [],
            "snapshots": []
        }
    }

    for r in resources:
        svc = r.service.lower()
        cfg = r.configuration
        r_type = r.resource_type.lower()

        if svc == "iam":
            if r_type == "user":
                raw_data["iam"]["users"].append(cfg)
            elif r_type == "role":
                raw_data["iam"]["roles"].append(cfg)
            elif r_type == "policy":
                raw_data["iam"]["policies"].append(cfg)
            elif r_type == "password_policy" or r_type == "passwordpolicy":
                raw_data["iam"]["password_policy"] = cfg
        elif svc == "s3":
            raw_data["s3"].append(cfg)
        elif svc == "ec2":
            raw_data["ec2"].append(cfg)
        elif svc == "vpc":
            if r_type == "security_group" or r_type == "securitygroup":
                raw_data["vpc"]["security_groups"].append(cfg)
            elif r_type == "vpc":
                raw_data["vpc"]["vpcs"].append(cfg)
        elif svc == "cloudtrail":
            raw_data["cloudtrail"].append(cfg)
        elif svc == "kms":
            raw_data["kms"].append(cfg)
        elif svc == "lambda":
            raw_data["lambda"].append(cfg)
        elif svc == "rds":
            raw_data["rds"].append(cfg)
        elif svc == "ebs":
            if r_type == "volume":
                raw_data["ebs"]["volumes"].append(cfg)
            elif r_type == "snapshot":
                raw_data["ebs"]["snapshots"].append(cfg)

    # Rebuild graph
    analyzer = GraphAnalyzer(raw_data)
    G = analyzer.build_graph()
    cyto_json = analyzer.serialize_to_cytoscape(G)
    return cyto_json

@router.get("/paths", response_model=List[AttackPathResponse])
async def list_attack_paths(
    scan_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst", "Viewer"]))
):
    # Resolve latest scan if scan_id not provided
    if scan_id is None:
        latest_scan_stmt = select(ScanResult).where(ScanResult.status == "completed").order_by(desc(ScanResult.started_at)).limit(1)
        latest_scan_res = await db.execute(latest_scan_stmt)
        latest_scan = latest_scan_res.scalars().first()
        if latest_scan:
            scan_id = latest_scan.id
        else:
            return []

    stmt = select(AttackPath).where(AttackPath.scan_id == scan_id)
    result = await db.execute(stmt)
    return result.scalars().all()
