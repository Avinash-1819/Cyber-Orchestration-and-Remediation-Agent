"""
Sentinel AI — CVE Cache ORM Model (7-day TTL)
Caches NVD CVE API responses to reduce API calls and handle NVD rate limits.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class CVECache(Base):
    __tablename__ = "cve_cache"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)

    # Full NVD response stored as JSON
    nvd_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # Denormalized for quick queries
    cvss_v3_score: Mapped[float | None] = mapped_column(nullable=True)
    cvss_v3_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)

    cached_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<CVECache cve_id={self.cve_id!r} cvss={self.cvss_v3_score}>"
