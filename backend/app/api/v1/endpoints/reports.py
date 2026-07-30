"""
Sentinel AI — Reports Endpoint
GET /reports/agent-docs/{agent_id}/pdf — download agent PDF manual
GET /reports/{session_id}/{format} — download session PDF/Markdown/JSON report
"""
import os
from pathlib import Path

import structlog
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models.user import User
from app.db.repositories.audit_log_repository import AuditLogRepository
from app.db.repositories.session_repository import SessionRepository

log = structlog.get_logger(__name__)
router = APIRouter()

FORMAT_MAP = {
    "pdf": ("report.pdf", "application/pdf"),
    "markdown": ("report.md", "text/markdown"),
    "json": ("report.json", "application/json"),
}

AGENT_PDF_MAP = {
    "triage": "01_Incident_Triage_Agent_Documentation.pdf",
    "remediation": "02_Remediation_Agent_Documentation.pdf",
    "devsecops": "03_DevSecOps_Agent_Documentation.pdf",
    "compliance": "04_Compliance_Agent_Documentation.pdf",
    "threat_intel": "05_Threat_Intel_Agent_Documentation.pdf",
    "exec_reporting": "06_Exec_Reporting_Agent_Documentation.pdf",
}

@router.get("/agent-docs/{agent_id}/pdf")
async def download_agent_pdf(agent_id: str):
    """Download separate PDF documentation for a specific sub-agent."""
    if agent_id not in AGENT_PDF_MAP:
        raise HTTPException(status_code=400, detail=f"Invalid agent_id. Choose from: {list(AGENT_PDF_MAP.keys())}")
    
    filename = AGENT_PDF_MAP[agent_id]
    possible_paths = [
        Path("/app/data/agent_docs/pdf") / filename,
        Path("/app/docs/agents/pdf") / filename,
        Path(__file__).parents[4] / "docs" / "agents" / "pdf" / filename,
        Path(__file__).parents[2] / "data" / "agent_docs" / "pdf" / filename,
    ]
    pdf_path = None
    for p in possible_paths:
        if p.exists():
            pdf_path = p
            break
            
    if not pdf_path:
        from app.services.agent_docs import ensure_all_agent_pdfs_generated
        ensure_all_agent_pdfs_generated()
        for p in possible_paths:
            if p.exists():
                pdf_path = p
                break

    if not pdf_path:
        raise HTTPException(status_code=404, detail="Agent documentation PDF not found.")

    return FileResponse(
        path=str(pdf_path),
        filename=filename,
        media_type="application/pdf"
    )

@router.get("/{session_id}/{format}")
async def download_report(
    session_id: str,
    format: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Download a report artifact (PDF, Markdown, or JSON) for a completed session."""
    if format not in FORMAT_MAP:
        raise HTTPException(status_code=400, detail=f"Invalid format '{format}'. Use: pdf, markdown, json")

    repo = SessionRepository(db)
    session = await repo.get_by_id(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")
    if session.status not in ("completed", "failed"):
        raise HTTPException(status_code=409, detail="Report not yet available — scan still running")

    filename, media_type = FORMAT_MAP[format]
    from app.core.config import settings
    file_path = Path(settings.REPORTS_OUTPUT_DIR) / session_id / filename

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found. The scan may have failed.")

    # Audit log the download
    audit = AuditLogRepository(db)
    await audit.append(
        user_id=current_user.id,
        action="REPORT_DOWNLOADED",
        session_id=session_id,
        details={"format": format},
    )

    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=f"sentinel-ai-report-{session_id[:8]}.{file_path.suffix.lstrip('.')}",
    )
