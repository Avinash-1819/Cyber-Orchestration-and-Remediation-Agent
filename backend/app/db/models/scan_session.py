"""
Sentinel AI — ScanSession ORM Model
Stores the complete SentinelState as JSON, plus queryable indexed fields.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)

    # Quick-query fields (indexed)
    pipeline: Mapped[str] = mapped_column(String(16), nullable=False)  # A, B, C, A_THEN_B
    input_type: Mapped[str] = mapped_column(String(32), nullable=False)  # CODE, LOGS, etc.
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running", index=True)
    current_agent: Mapped[str | None] = mapped_column(String(64), nullable=True)
    classification_confidence: Mapped[float] = mapped_column(Float, default=1.0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Full SentinelState stored as JSON blob for resumability
    state_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Denormalized for the dashboard (avoids deserializing full state for list views)
    finding_count: Mapped[int] = mapped_column(default=0)
    critical_count: Mapped[int] = mapped_column(default=0)
    high_count: Mapped[int] = mapped_column(default=0)
    error_count: Mapped[int] = mapped_column(default=0)

    # Relationships
    user: Mapped["User"] = relationship(back_populates="sessions")

    def __repr__(self) -> str:
        return f"<ScanSession id={self.id} pipeline={self.pipeline} status={self.status}>"
