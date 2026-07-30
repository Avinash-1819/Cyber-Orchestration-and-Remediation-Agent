"""
Sentinel AI — Audit Log Repository (append-only)
"""
from typing import Optional
import structlog
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.audit_log import AuditLog

log = structlog.get_logger(__name__)


class AuditLogRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def append(
        self,
        user_id: str,
        action: str,
        details: Optional[dict] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditLog:
        """Append an immutable audit entry. Never call update/delete on this table."""
        entry = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self.db.add(entry)
        await self.db.commit()
        await self.db.refresh(entry)
        log.info("audit_log_appended", action=action, user_id=user_id, session_id=session_id)
        return entry

    async def list_by_user(self, user_id: str, limit: int = 100) -> list[AuditLog]:
        result = await self.db.execute(
            select(AuditLog)
            .where(AuditLog.user_id == user_id)
            .order_by(desc(AuditLog.created_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    async def list_by_session(self, session_id: str) -> list[AuditLog]:
        result = await self.db.execute(
            select(AuditLog)
            .where(AuditLog.session_id == session_id)
            .order_by(AuditLog.created_at)
        )
        return list(result.scalars().all())
