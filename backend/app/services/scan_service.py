import logging
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from typing import Dict, Any, List

from app.models.account import AWSAccount
from app.models.scan import ScanResult, Finding, ResourceInventory, AttackPath
from app.services.encryption_service import encryption_service
from app.collectors.aws_collector import AWSCollector
from app.collectors.mock_collector import MockAWSCollector
from app.rules.registry import run_all_rules
from app.analyzers.graph_analyzer import GraphAnalyzer

logger = logging.getLogger("cloudsentinel.scan_service")

class ScanService:
    @staticmethod
    async def run_scan(account_id: int, db: AsyncSession) -> ScanResult:
        """Executes a security scan against the selected AWS account."""
        # 1. Fetch AWS Account
        result = await db.execute(select(AWSAccount).where(AWSAccount.id == account_id))
        account = result.scalars().first()
        if not account:
            raise ValueError("AWS Account not found")

        # 2. Create ScanResult
        scan = ScanResult(account_id=account.id, status="running")
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        try:
            # 3. Setup Collector (Mock vs Real)
            is_mock = account.name == "demo-aws-account" or account.account_id == "123456789012"
            if is_mock:
                logger.info(f"Running mock collector for demo account {account.name}")
                collector = MockAWSCollector(account_name=account.name)
            else:
                logger.info(f"Running boto3 collector for account {account.name}")
                # Decrypt keys
                decrypted_key = encryption_service.decrypt(account.access_key_id)
                decrypted_secret = encryption_service.decrypt(account.secret_access_key)
                collector = AWSCollector(
                    access_key_id=decrypted_key or None,
                    secret_access_key=decrypted_secret or None,
                    role_arn=account.role_arn,
                    default_region=account.region or "us-east-1"
                )

            # 4. Collect configurations
            # Runs blocking SDK I/O calls (in a production system, this could be offloaded to celery,
            # but for this FastAPI stack we run it directly or mock it).
            collected_data = collector.collect_all()

            # 5. Populate Resource Inventory
            # To avoid database bloat, we clear previous resources of the same account, or let CASCADE handle it.
            # We record each service categories into the inventory
            for service, content in collected_data.items():
                if service in ["account_id"]:
                    continue
                
                # Format to inventory model
                # content can be a list (like s3 buckets) or dict (like iam)
                if isinstance(content, list):
                    for item in content:
                        res = ResourceInventory(
                            scan_id=scan.id,
                            service=service.upper(),
                            resource_type=item.get("Type") or "Resource",
                            resource_id=item.get("Name") or item.get("InstanceId") or item.get("VolumeId") or item.get("FunctionArn") or item.get("DBInstanceIdentifier") or "unknown",
                            resource_name=item.get("Name") or item.get("InstanceId") or item.get("FunctionName") or item.get("DBInstanceIdentifier") or "unnamed",
                            configuration=item
                        )
                        db.add(res)
                elif isinstance(content, dict):
                    # For services like IAM which have sub-lists
                    for sub_service, sub_items in content.items():
                        if isinstance(sub_items, list):
                            for sub_item in sub_items:
                                res = ResourceInventory(
                                    scan_id=scan.id,
                                    service=service.upper(),
                                    resource_type=sub_service.rstrip("s").capitalize(),
                                    resource_id=sub_item.get("Arn") or sub_item.get("UserName") or sub_item.get("GroupId") or sub_item.get("PolicyName") or "unknown",
                                    resource_name=sub_item.get("UserName") or sub_item.get("RoleName") or sub_item.get("PolicyName") or "unnamed",
                                    configuration=sub_item
                                )
                                db.add(res)

            # 6. Run CIS Benchmark & General Rules
            findings_data = run_all_rules(collected_data)
            for f_dict in findings_data:
                finding = Finding(
                    scan_id=scan.id,
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
                db.add(finding)

            # 7. Analyze IAM privilege escalation paths (NetworkX Graph)
            graph_analyzer = GraphAnalyzer(collected_data)
            G = graph_analyzer.build_graph()
            paths = graph_analyzer.find_attack_paths(G)
            
            for path in paths:
                ap = AttackPath(
                    scan_id=scan.id,
                    path_name=path["path_name"],
                    node_chain=path["node_chain"],
                    risk_level=path["risk_level"],
                    description=path["description"]
                )
                db.add(ap)

            # 8. Calculate risk and compliance scores
            num_critical = sum(1 for f in findings_data if f["severity"] == "Critical")
            num_high = sum(1 for f in findings_data if f["severity"] == "High")
            num_medium = sum(1 for f in findings_data if f["severity"] == "Medium")
            num_low = sum(1 for f in findings_data if f["severity"] == "Low")

            # Compliance starts at 100 and drops based on severity count
            # Critical = -12%, High = -6%, Medium = -2%, Low = -0.5%
            deduction = (num_critical * 12.0) + (num_high * 6.0) + (num_medium * 2.0) + (num_low * 0.5)
            compliance_score = max(0.0, min(100.0, 100.0 - deduction))

            # Risk score composite (0-100)
            risk_score = min(100.0, (num_critical * 25.0) + (num_high * 12.0) + (num_medium * 4.0) + (len(paths) * 15.0))

            # 9. Update Scan state
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            scan.risk_score = round(risk_score, 1)
            scan.compliance_score = round(compliance_score, 1)
            
            account.last_scanned = datetime.utcnow()
            await db.commit()
            logger.info(f"Scan {scan.id} finished. Risk: {scan.risk_score}, Compliance: {scan.compliance_score}")

        except Exception as e:
            logger.error(f"Scan failed for account {account.name}: {e}", exc_info=True)
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            await db.commit()

        return scan
