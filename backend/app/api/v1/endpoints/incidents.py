"""
Sentinel AI — Incidents Endpoint
Query findings and IOCs across sessions, approve remediation actions (audit-logged).
"""
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Any, Dict, List, Optional

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models.user import User
from app.db.repositories.audit_log_repository import AuditLogRepository
from app.db.repositories.session_repository import SessionRepository
from app.agents.state import SentinelState

log = structlog.get_logger(__name__)
router = APIRouter()


class ApproveRemediationRequest(BaseModel):
    session_id: str
    finding_id: str
    command: str  # Exact command text being approved (for audit log)
    justification: Optional[str] = None


class ApproveRemediationResponse(BaseModel):
    approved: bool
    audit_id: str
    message: str


@router.get("/{session_id}/findings")
async def get_findings(
    session_id: str,
    severity: Optional[str] = Query(default=None, description="Filter by severity: CRITICAL,HIGH,MEDIUM,LOW"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all findings from a session, optionally filtered by severity."""
    repo = SessionRepository(db)
    session = await repo.get_by_id(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    state_data = session.state_json or {}
    findings = state_data.get("findings", [])

    if severity:
        severities = [s.strip().upper() for s in severity.split(",")]
        findings = [f for f in findings if f.get("severity", "").upper() in severities]

    return {"session_id": session_id, "findings": findings, "total": len(findings)}


@router.get("/{session_id}/iocs")
async def get_iocs(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all extracted IOCs from a session."""
    repo = SessionRepository(db)
    session = await repo.get_by_id(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    state_data = session.state_json or {}
    iocs = state_data.get("extracted_iocs", [])
    return {"session_id": session_id, "iocs": iocs, "total": len(iocs)}


@router.post("/remediation/approve", response_model=ApproveRemediationResponse)
async def approve_remediation(
    body: ApproveRemediationRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Record a user's explicit approval of a destructive remediation command.
    IMPORTANT: This endpoint LOGS the approval only — it does NOT execute any command.
    The architecture enforces this as a hard boundary.
    """
    repo = SessionRepository(db)
    session = await repo.get_by_id(body.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    # Verify the finding exists and is destructive
    state_data = session.state_json or {}
    findings = state_data.get("findings", [])
    finding = next((f for f in findings if f.get("id") == body.finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not finding.get("destructive", False):
        raise HTTPException(status_code=400, detail="This finding is not flagged as destructive")

    # Log the approval to the immutable audit trail
    audit = AuditLogRepository(db)
    entry = await audit.append(
        user_id=current_user.id,
        action="REMEDIATION_APPROVED",
        session_id=body.session_id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("User-Agent"),
        details={
            "finding_id": body.finding_id,
            "finding_title": finding.get("title", ""),
            "approved_command": body.command,  # Full command text for audit trail
            "justification": body.justification,
        },
    )

    log.info(
        "remediation_approved",
        user_id=current_user.id,
        session_id=body.session_id,
        finding_id=body.finding_id,
        audit_id=entry.id,
    )

    return ApproveRemediationResponse(
        approved=True,
        audit_id=entry.id,
        message="Approval recorded in audit log. Copy the command and run it manually.",
    )
