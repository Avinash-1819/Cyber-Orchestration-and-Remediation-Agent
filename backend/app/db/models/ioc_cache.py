"""
Sentinel AI — IOC Enrichment Cache ORM Model (24h TTL)
Prevents repeated API calls for the same IOC across sessions.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class IOCEnrichmentCache(Base):
    __tablename__ = "ioc_enrichment_cache"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # Composite key: value + type (e.g., "1.2.3.4::IP")
    ioc_key: Mapped[str] = mapped_column(String(512), unique=True, nullable=False, index=True)
    ioc_value: Mapped[str] = mapped_column(String(512), nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False)  # IP, Domain, Hash, Username

    # Merged enrichment data from VirusTotal + Shodan
    enrichment_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    enrichment_status: Mapped[str] = mapped_column(String(32), nullable=False, default="ok")  # ok | unavailable

    cached_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<IOCEnrichmentCache key={self.ioc_key!r} status={self.enrichment_status}>"
