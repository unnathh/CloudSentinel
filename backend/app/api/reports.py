import csv
import json
from io import BytesIO, StringIO
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Optional

from app.database import get_db
from app.models.scan import ScanResult, Finding, AttackPath
from app.models.account import AWSAccount
from app.api.deps import RoleChecker

# ReportLab imports (safe fallback if installation delayed)
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

router = APIRouter(prefix="/reports", tags=["Reports Export"])

async def get_report_data(scan_id: Optional[int], db: AsyncSession):
    # Resolve scan_id
    if scan_id is None:
        latest_scan_stmt = select(ScanResult).where(ScanResult.status == "completed").order_by(desc(ScanResult.started_at)).limit(1)
        latest_scan_res = await db.execute(latest_scan_stmt)
        scan = latest_scan_res.scalars().first()
    else:
        result = await db.execute(select(ScanResult).where(ScanResult.id == scan_id))
        scan = result.scalars().first()

    if not scan:
        raise HTTPException(status_code=404, detail="No scan report found.")

    # Fetch AWS Account
    acct_result = await db.execute(select(AWSAccount).where(AWSAccount.id == scan.account_id))
    account = acct_result.scalars().first()

    # Fetch findings
    findings_stmt = select(Finding).where(Finding.scan_id == scan.id)
    findings_res = await db.execute(findings_stmt)
    findings = findings_res.scalars().all()

    # Fetch attack paths
    paths_stmt = select(AttackPath).where(AttackPath.scan_id == scan.id)
    paths_res = await db.execute(paths_stmt)
    paths = paths_res.scalars().all()

    return scan, account, findings, paths

@router.get("/json")
async def export_json(
    scan_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst", "Viewer"]))
):
    scan, account, findings, paths = await get_report_data(scan_id, db)
    
    report_payload = {
        "metadata": {
            "account_id": account.account_id if account else "unknown",
            "account_name": account.name if account else "unknown",
            "scan_id": scan.id,
            "started_at": scan.started_at.isoformat(),
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "status": scan.status,
            "compliance_score": scan.compliance_score,
            "risk_score": scan.risk_score
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "service": f.service,
                "resource_id": f.resource_id,
                "region": f.region,
                "description": f.description,
                "recommendation": f.recommendation,
                "mitre_technique": f"{f.mitre_technique_id or ''}: {f.mitre_technique_name or ''}",
                "status": f.status
            }
            for f in findings
        ],
        "attack_paths": [
            {
                "path_name": p.path_name,
                "node_chain": p.node_chain,
                "risk_level": p.risk_level,
                "description": p.description
            }
            for p in paths
        ]
    }

    response_content = json.dumps(report_payload, indent=2)
    filename = f"cloudsentinel_report_{scan.id}.json"
    
    return StreamingResponse(
        StringIO(response_content),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/csv")
async def export_csv(
    scan_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst", "Viewer"]))
):
    scan, account, findings, _ = await get_report_data(scan_id, db)

    output = StringIO()
    writer = csv.writer(output)
    
    # Headers
    writer.writerow([
        "Rule ID", "Title", "Severity", "Service", "Resource ID", 
        "Region", "Description", "Recommendation", "MITRE ID", "Status"
    ])
    
    for f in findings:
        writer.writerow([
            f.rule_id, f.title, f.severity, f.service, f.resource_id,
            f.region, f.description, f.recommendation, f.mitre_technique_id, f.status
        ])
        
    output.seek(0)
    filename = f"cloudsentinel_findings_{scan.id}.csv"
    
    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/pdf")
async def export_pdf(
    scan_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(RoleChecker(["Admin", "Analyst", "Viewer"]))
):
    scan, account, findings, paths = await get_report_data(scan_id, db)

    if not REPORTLAB_AVAILABLE:
        # Fallback if ReportLab import failed or packages still installing in background
        raise HTTPException(
            status_code=500, 
            detail="PDF generation engine (ReportLab) is currently setting up. Please try again in a few seconds or use JSON/CSV export."
        )

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#0F172A'), # Slate 900
        spaceAfter=12
    )
    
    section_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=18,
        spaceAfter=8
    )

    body_style = styles['Normal']
    
    # Header Title
    story.append(Paragraph("CloudSentinel Security Assessment Report", title_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    story.append(Spacer(1, 12))
    
    # Executive Summary Card Table
    summary_data = [
        [
            Paragraph("<b>AWS Account Name:</b>", body_style), Paragraph(account.name if account else "N/A", body_style),
            Paragraph("<b>AWS Account ID:</b>", body_style), Paragraph(account.account_id if account else "N/A", body_style)
        ],
        [
            Paragraph("<b>Scan Status:</b>", body_style), Paragraph(scan.status.capitalize(), body_style),
            Paragraph("<b>Scan Timestamp:</b>", body_style), Paragraph(scan.started_at.strftime('%Y-%m-%d %H:%M:%S'), body_style)
        ],
        [
            Paragraph("<b>Compliance Score:</b>", body_style), Paragraph(f"<b>{scan.compliance_score}%</b>", body_style),
            Paragraph("<b>Security Risk Score:</b>", body_style), Paragraph(f"<b>{scan.risk_score} / 100</b>", body_style)
        ]
    ]
    
    summary_table = Table(summary_data, colWidths=[120, 150, 120, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')), # Slate 50
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
    ]))
    
    story.append(Paragraph("Executive Scan Summary", section_style))
    story.append(summary_table)
    story.append(Spacer(1, 15))

    # Findings metrics
    num_critical = sum(1 for f in findings if f.severity == "Critical")
    num_high = sum(1 for f in findings if f.severity == "High")
    num_medium = sum(1 for f in findings if f.severity == "Medium")
    num_low = sum(1 for f in findings if f.severity == "Low")

    metrics_data = [
        ["Critical", "High", "Medium", "Low", "Total Findings"],
        [str(num_critical), str(num_high), str(num_medium), str(num_low), str(len(findings))]
    ]
    metrics_table = Table(metrics_data, colWidths=[100, 100, 100, 100, 140])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
    ]))
    story.append(Paragraph("Findings Breakdown by Severity", section_style))
    story.append(metrics_table)
    story.append(Spacer(1, 15))

    # Attack Paths list
    story.append(Paragraph("Identified Critical Attack Paths", section_style))
    if not paths:
        story.append(Paragraph("No critical IAM privilege escalation paths discovered in this scan.", body_style))
    else:
        for idx, p in enumerate(paths):
            story.append(Paragraph(f"<b>Path {idx+1}: {p.path_name}</b>", body_style))
            chain_str = " -> ".join([n.split('/')[-1] for n in p.node_chain])
            story.append(Paragraph(f"<i>Chain: {chain_str}</i>", body_style))
            story.append(Paragraph(f"Description: {p.description}", body_style))
            story.append(Spacer(1, 6))

    story.append(Spacer(1, 10))

    # Detailed findings table
    story.append(Paragraph("vulnerability & Configuration Findings (Failing Rules)", section_style))
    if not findings:
        story.append(Paragraph("Congratulations! No failing configuration checks.", body_style))
    else:
        table_data = [["Severity", "Service", "Rule Name", "Resource Affected", "Status"]]
        for f in findings[:25]: # Limit to top 25 in PDF for length safety
            table_data.append([
                f.severity,
                f.service,
                f.title,
                f.resource_id.split("/")[-1] if len(f.resource_id) > 25 else f.resource_id,
                f.status
            ])
            
        findings_table = Table(table_data, colWidths=[80, 70, 180, 150, 60])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ]))
        story.append(findings_table)
        if len(findings) > 25:
            story.append(Spacer(1, 5))
            story.append(Paragraph(f"<i>* Showing 25 of {len(findings)} total findings. Download JSON report for complete dataset.</i>", body_style))

    doc.build(story)
    buffer.seek(0)
    
    filename = f"cloudsentinel_report_{scan.id}.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
