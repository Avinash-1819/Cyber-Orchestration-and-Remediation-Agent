"""
Sentinel AI — Reports Endpoint
GET /reports/{session_id}/{format} — download PDF/Markdown/JSON report
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
        raise HTTPException(status_code=404, detail=f"Report file not found. The scan may have failed.")

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
