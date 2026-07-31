"""
Sentinel AI — Scan Endpoint
POST /scan — start a new scan session and run the pipeline asynchronously.
"""
import asyncio
import uuid
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.orchestrator import run_pipeline
from app.agents.state import SentinelState
from app.api.deps import get_current_user
from app.core.config import settings
from app.core.rate_limit import rate_limit_middleware
from app.db.database import get_db
from app.db.models.scan_session import ScanSession
from app.db.models.user import User
from app.db.repositories.audit_log_repository import AuditLogRepository
from app.db.repositories.session_repository import SessionRepository

log = structlog.get_logger(__name__)
router = APIRouter()


class ScanRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=500_000, description="Raw input to analyze")
    input_type_hint: str | None = Field(
        default=None,
        description="Optional hint: CODE, LOGS, REPO_URL, CVE, IOC, QUERY. If not provided, auto-classified."
    )
    selected_agents: list[str] | None = Field(
        default=None,
        description="Optional: list of specific agents to run e.g. ['IncidentTriageAgent','ThreatIntelAgent']. If None, auto-pipeline."
    )
    mode: str | None = Field(
        default="auto",
        description="'auto' = full orchestrated pipeline. 'custom' = only run selected_agents."
    )



class ScanResponse(BaseModel):
    session_id: str
    status: str
    message: str
    pipeline: str | None = None
    classification_confidence: float | None = None
    clarification_question: str | None = None


async def _run_and_persist(
    session_id: str,
    user_id: str,
    raw_input: str,
    input_type_hint: str | None,
    db_session_factory,
    selected_agents: list[str] | None = None,
    mode: str = "auto",
) -> None:
    """
    Background task: run the full pipeline and persist final state.
    Runs in its own DB session context.
    """
    from app.db.database import AsyncSessionLocal

    # Build initial state — strip and normalise input; short queries are valid
    clean_input = raw_input.strip()

    initial_state = SentinelState(
        session_id=session_id,
        user_id=user_id,
        raw_input=clean_input,
        input_type=input_type_hint or "UNKNOWN",
        pipeline="UNKNOWN",  # Will be set by orchestrator classification
    )

    try:
        final_state = await run_pipeline(
            initial_state,
            selected_agents=selected_agents,
            mode=mode,
        )
        try:
            from app.services.report_engine import generate_all_reports
            paths = generate_all_reports(final_state)
            final_state.report_pdf_path = paths.get("pdf")
            final_state.report_markdown_path = paths.get("markdown")
            final_state.report_json_path = paths.get("json")
        except Exception as report_err:
            log.warning("background_report_gen_failed", session_id=session_id, error=str(report_err))
    except Exception as e:
        log.exception("pipeline_background_error", session_id=session_id)
        final_state = initial_state
        final_state.status = "failed"
        final_state.add_error("BackgroundRunner", f"Unhandled pipeline error: {e}")

    # Persist final state
    async with AsyncSessionLocal() as db:
        repo = SessionRepository(db)
        summary = final_state.finding_summary
        await repo.update_state(
            session_id=session_id,
            state_json=final_state.model_dump(mode="json"),
            status=final_state.status,
            pipeline=final_state.pipeline,
            input_type=final_state.input_type,
            current_agent=final_state.current_agent,
            finding_count=summary["total"],
            critical_count=summary["CRITICAL"],
            high_count=summary["HIGH"],
            error_count=len(final_state.errors),
        )

    log.info("pipeline_completed_and_persisted", session_id=session_id, status=final_state.status)


@router.post("", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_scan(
    request: Request,
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    _rate_limit=Depends(rate_limit_middleware(
        max_requests=settings.RATE_LIMIT_SCAN_PER_MINUTE,
        window_seconds=60
    )),
):
    """
    Start a new Sentinel AI scan session.
    Returns 202 Accepted immediately; pipeline runs in background.
    Connect to /ws/{session_id} for live execution updates.
    """
    session_id = str(uuid.uuid4())

    # Create session record
    session = ScanSession(
        id=session_id,
        user_id=current_user.id,
        pipeline="UNKNOWN",
        input_type=body.input_type_hint or "UNKNOWN",
        status="running",
    )
    repo = SessionRepository(db)
    await repo.create(session)

    # Audit log
    audit = AuditLogRepository(db)
    await audit.append(
        user_id=current_user.id,
        action="SCAN_STARTED",
        session_id=session_id,
        ip_address=request.client.host if request.client else None,
        details={"input_type_hint": body.input_type_hint, "input_length": len(body.input)},
    )

    log.info("scan_started", session_id=session_id, user_id=current_user.id)

    # Launch pipeline as background task
    background_tasks.add_task(
        _run_and_persist,
        session_id=session_id,
        user_id=current_user.id,
        raw_input=body.input,
        input_type_hint=body.input_type_hint,
        db_session_factory=None,
        selected_agents=body.selected_agents,
        mode=body.mode or "auto",
    )

    return ScanResponse(
        session_id=session_id,
        status="running",
        message=f"Scan started. Connect to /api/v1/ws/{session_id} for live updates.",
    )
