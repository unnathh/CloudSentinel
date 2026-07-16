from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from typing import List

from app.database import get_db, SessionLocal
from app.models.account import AWSAccount
from app.models.scan import ScanResult, Finding, ResourceInventory, AttackPath
from app.schemas.account import AWSAccountCreate, AWSAccountResponse, AWSAccountUpdate
from app.schemas.scan import ScanResultResponse
from app.services.encryption_service import encryption_service
from app.services.scan_service import ScanService
from app.collectors.aws_collector import AWSCollector
from app.collectors.mock_collector import MockAWSCollector
from app.rules.registry import run_all_rules
from app.analyzers.graph_analyzer import GraphAnalyzer
from app.api.deps import RoleChecker

router = APIRouter(prefix="/accounts", tags=["AWS Accounts"])

# Viewer, Analyst, and Admin roles can view accounts
@router.get("", response_model=List[AWSAccountResponse])
async def list_accounts(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst", "Viewer"]))
):
    result = await db.execute(select(AWSAccount))
    return result.scalars().all()

# Analyst and Admin can register accounts
@router.post("", response_model=AWSAccountResponse, status_code=status.HTTP_201_CREATED)
async def create_account(
    account_in: AWSAccountCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst"]))
):
    # Verify account name or ID does not exist
    exists_stmt = select(AWSAccount).where(
        (AWSAccount.account_id == account_in.account_id) | (AWSAccount.name == account_in.name)
    )
    result = await db.execute(exists_stmt)
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Account with this ID or name already registered")

    # If it is the demo account, bypass boto3 STS check
    if account_in.name == "demo-aws-account" or account_in.account_id == "123456789012":
        account = AWSAccount(
            name=account_in.name,
            account_id="123456789012",
            auth_type="keys",
            region=account_in.region or "us-east-1"
        )
    else:
        # Validate credentials via STS
        collector = AWSCollector(
            access_key_id=account_in.access_key_id,
            secret_access_key=account_in.secret_access_key,
            role_arn=account_in.role_arn,
            default_region=account_in.region
        )
        conn = collector.validate_connection()
        if not conn["success"]:
            raise HTTPException(status_code=400, detail=f"AWS connection validation failed: {conn.get('error')}")
        
        # Encrypt access keys
        enc_key = encryption_service.encrypt(account_in.access_key_id)
        enc_secret = encryption_service.encrypt(account_in.secret_access_key)
        
        account = AWSAccount(
            name=account_in.name,
            account_id=conn["account_id"],
            auth_type=account_in.auth_type,
            access_key_id=enc_key,
            secret_access_key=enc_secret,
            role_arn=account_in.role_arn,
            region=account_in.region
        )

    db.add(account)
    await db.commit()
    await db.refresh(account)
    return account

@router.get("/{account_id}", response_model=AWSAccountResponse)
async def get_account(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst", "Viewer"]))
):
    result = await db.execute(select(AWSAccount).where(AWSAccount.id == account_id))
    account = result.scalars().first()
    if not account:
        raise HTTPException(status_code=404, detail="AWS Account not found")
    return account

@router.delete("/{account_id}", status_code=status.HTTP_200_OK)
async def delete_account(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin"]))
):
    result = await db.execute(select(AWSAccount).where(AWSAccount.id == account_id))
    account = result.scalars().first()
    if not account:
        raise HTTPException(status_code=404, detail="AWS Account not found")
    
    await db.delete(account)
    await db.commit()
    return {"message": "Account deleted successfully"}

# Scan trigger endpoint
@router.post("/{account_id}/scan", response_model=ScanResultResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(
    account_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst"]))
):
    # Verify account exists
    result = await db.execute(select(AWSAccount).where(AWSAccount.id == account_id))
    account = result.scalars().first()
    if not account:
        raise HTTPException(status_code=404, detail="AWS Account not found")
    
    # Check if there's already a scan running for this account
    active_scan = await db.execute(
        select(ScanResult).where(ScanResult.account_id == account_id, ScanResult.status == "running")
    )
    if active_scan.scalars().first():
        raise HTTPException(status_code=400, detail="A scan is already actively running for this account.")

    # Launch scan in background task
    # Note: We create the ScanResult inside the run_scan to avoid duplicate operations,
    # but we can return it. To return it immediately, we create it here:
    scan = ScanResult(account_id=account.id, status="running")
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Helper function to execute background database operations
    async def scan_task_wrapper():
        # Open separate database context to avoid session sharing issues in background workers
        async with SessionLocal() as task_db:
            try:
                # We need to load and run the scan
                # To override the placeholder scan we created:
                # We fetch the scan object in the task context
                task_scan_result = await task_db.execute(select(ScanResult).where(ScanResult.id == scan.id))
                task_scan = task_scan_result.scalars().first()
                if not task_scan:
                    return

                # Perform collection, analysis, rules evaluations
                is_mock = account.name == "demo-aws-account" or account.account_id == "123456789012"
                if is_mock:
                    collector = MockAWSCollector(account_name=account.name)
                else:
                    decrypted_key = encryption_service.decrypt(account.access_key_id)
                    decrypted_secret = encryption_service.decrypt(account.secret_access_key)
                    collector = AWSCollector(
                        access_key_id=decrypted_key or None,
                        secret_access_key=decrypted_secret or None,
                        role_arn=account.role_arn,
                        default_region=account.region or "us-east-1"
                    )

                collected_data = collector.collect_all()

                # Populate Inventory
                for service, content in collected_data.items():
                    if service in ["account_id"]:
                        continue
                    if isinstance(content, list):
                        for item in content:
                            res = ResourceInventory(
                                scan_id=task_scan.id,
                                service=service.upper(),
                                resource_type=item.get("Type") or "Resource",
                                resource_id=item.get("Name") or item.get("InstanceId") or item.get("VolumeId") or item.get("FunctionArn") or item.get("DBInstanceIdentifier") or "unknown",
                                resource_name=item.get("Name") or item.get("InstanceId") or item.get("FunctionName") or item.get("DBInstanceIdentifier") or "unnamed",
                                configuration=item
                            )
                            task_db.add(res)
                    elif isinstance(content, dict):
                        for sub_service, sub_items in content.items():
                            if isinstance(sub_items, list):
                                for sub_item in sub_items:
                                    res = ResourceInventory(
                                        scan_id=task_scan.id,
                                        service=service.upper(),
                                        resource_type=sub_service.rstrip("s").capitalize(),
                                        resource_id=sub_item.get("Arn") or sub_item.get("UserName") or sub_item.get("GroupId") or sub_item.get("PolicyName") or "unknown",
                                        resource_name=sub_item.get("UserName") or sub_item.get("RoleName") or sub_item.get("PolicyName") or "unnamed",
                                        configuration=sub_item
                                    )
                                    task_db.add(res)

                # Rules
                findings_data = run_all_rules(collected_data)
                for f_dict in findings_data:
                    finding = Finding(
                        scan_id=task_scan.id,
                        rule_id=f_dict["rule_id"],
                        title=f_dict["title"],
                        severity=f_dict["severity"],
                        service=f_dict["service"],
                        resource_id=f_dict["resource_id"],
                        region=f_dict["region"],
                        description=f_dict["description"],
                        evidence=f_dict["evidence"],
                        recommendation=f_dict["recommendation"],
                        mitre_technique_id=f_dict["mitre_technique_id"],
                        mitre_technique_name=f_dict["mitre_technique_name"],
                        status="open"
                    )
                    task_db.add(finding)

                # NetworkX escalation paths
                graph_analyzer = GraphAnalyzer(collected_data)
                G = graph_analyzer.build_graph()
                paths = graph_analyzer.find_attack_paths(G)
                
                for path in paths:
                    ap = AttackPath(
                        scan_id=task_scan.id,
                        path_name=path["path_name"],
                        node_chain=path["node_chain"],
                        risk_level=path["risk_level"],
                        description=path["description"]
                    )
                    task_db.add(ap)

                # Scores
                num_critical = sum(1 for f in findings_data if f["severity"] == "Critical")
                num_high = sum(1 for f in findings_data if f["severity"] == "High")
                num_medium = sum(1 for f in findings_data if f["severity"] == "Medium")
                num_low = sum(1 for f in findings_data if f["severity"] == "Low")

                deduction = (num_critical * 12.0) + (num_high * 6.0) + (num_medium * 2.0) + (num_low * 0.5)
                compliance_score = max(0.0, min(100.0, 100.0 - deduction))
                risk_score = min(100.0, (num_critical * 25.0) + (num_high * 12.0) + (num_medium * 4.0) + (len(paths) * 15.0))

                task_scan.status = "completed"
                task_scan.completed_at = datetime.utcnow()
                task_scan.risk_score = round(risk_score, 1)
                task_scan.compliance_score = round(compliance_score, 1)
                
                # Update account last scanned
                account_result = await task_db.execute(select(AWSAccount).where(AWSAccount.id == account_id))
                task_account = account_result.scalars().first()
                if task_account:
                    task_account.last_scanned = datetime.utcnow()

                await task_db.commit()
            except Exception as e:
                task_scan.status = "failed"
                task_scan.completed_at = datetime.utcnow()
                await task_db.commit()
                logger.error(f"Background scan error: {e}", exc_info=True)

    background_tasks.add_task(scan_task_wrapper)
    return scan

@router.get("/{account_id}/scans", response_model=List[ScanResultResponse])
async def list_account_scans(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst", "Viewer"]))
):
    result = await db.execute(
        select(ScanResult).where(ScanResult.account_id == account_id).order_by(ScanResult.started_at.desc())
    )
    return result.scalars().all()
