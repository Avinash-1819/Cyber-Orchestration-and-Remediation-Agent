"""
Sentinel AI — Session Repository
"""
from datetime import datetime, timezone
from typing import Optional

import structlog
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.scan_session import ScanSession

log = structlog.get_logger(__name__)


class SessionRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(self, session: ScanSession) -> ScanSession:
        self.db.add(session)
        await self.db.commit()
        await self.db.refresh(session)
        log.info("session_created", session_id=session.id, user_id=session.user_id)
        return session

    async def get_by_id(self, session_id: str) -> Optional[ScanSession]:
        result = await self.db.execute(
            select(ScanSession).where(ScanSession.id == session_id)
        )
        return result.scalar_one_or_none()

    async def list_by_user(self, user_id: str, limit: int = 50, offset: int = 0) -> list[ScanSession]:
        result = await self.db.execute(
            select(ScanSession)
            .where(ScanSession.user_id == user_id)
            .order_by(desc(ScanSession.created_at))
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def update_state(self, session_id: str, state_json: dict, status: str,
                           pipeline: Optional[str] = None,
                           input_type: Optional[str] = None,
                           current_agent: Optional[str] = None,
                           finding_count: int = 0, critical_count: int = 0,
                           high_count: int = 0, error_count: int = 0) -> None:
        session = await self.get_by_id(session_id)
        if not session:
            log.warning("session_not_found_for_update", session_id=session_id)
            return
        session.state_json = state_json
        session.status = status
        if pipeline:
            session.pipeline = pipeline
        if input_type:
            session.input_type = input_type
        session.current_agent = current_agent
        session.finding_count = finding_count
        session.critical_count = critical_count
        session.high_count = high_count
        session.error_count = error_count
        if status in ("completed", "failed"):
            session.completed_at = datetime.now(timezone.utc)
        await self.db.commit()

    async def get_active_sessions(self, user_id: str) -> list[ScanSession]:
        result = await self.db.execute(
            select(ScanSession)
            .where(ScanSession.user_id == user_id, ScanSession.status == "running")
            .order_by(desc(ScanSession.created_at))
        )
        return list(result.scalars().all())
