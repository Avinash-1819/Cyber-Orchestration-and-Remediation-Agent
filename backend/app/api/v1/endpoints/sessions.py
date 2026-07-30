"""
Sentinel AI — Sessions Endpoint
GET /sessions — list user sessions
GET /sessions/{id} — get full session state (resumable)
"""
from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.state import SentinelState
from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models.user import User
from app.db.repositories.session_repository import SessionRepository
from app.core.exceptions import SessionNotFoundError

log = structlog.get_logger(__name__)
router = APIRouter()


class SessionSummary(BaseModel):
    id: str
    pipeline: str
    input_type: str
    status: str
    current_agent: Optional[str]
    finding_count: int
    critical_count: int
    high_count: int
    created_at: str
    completed_at: Optional[str]


class SessionDetail(BaseModel):
    id: str
    pipeline: str
    input_type: str
    status: str
    state: Dict[str, Any]  # Full SentinelState
    created_at: str


@router.get("", response_model=List[SessionSummary])
async def list_sessions(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all scan sessions for the current user, newest first."""
    repo = SessionRepository(db)
    sessions = await repo.list_by_user(current_user.id, limit=limit, offset=offset)
    return [
        SessionSummary(
            id=s.id,
            pipeline=s.pipeline,
            input_type=s.input_type,
            status=s.status,
            current_agent=s.current_agent,
            finding_count=s.finding_count,
            critical_count=s.critical_count,
            high_count=s.high_count,
            created_at=s.created_at.isoformat(),
            completed_at=s.completed_at.isoformat() if s.completed_at else None,
        )
        for s in sessions
    ]


@router.get("/{session_id}", response_model=SessionDetail)
async def get_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get full session state including execution trace (for session resumability)."""
    repo = SessionRepository(db)
    session = await repo.get_by_id(session_id)

    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    if session.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    return SessionDetail(
        id=session.id,
        pipeline=session.pipeline,
        input_type=session.input_type,
        status=session.status,
        state=session.state_json or {},
        created_at=session.created_at.isoformat(),
    )
