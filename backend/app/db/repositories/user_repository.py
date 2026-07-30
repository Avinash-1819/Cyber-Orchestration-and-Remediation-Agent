"""
Sentinel AI — User Repository
"""
from typing import Optional

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.user import User

log = structlog.get_logger(__name__)


class UserRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(self, user: User) -> User:
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        log.info("user_created", user_id=user.id, username=user.username)
        return user

    async def get_by_id(self, user_id: str) -> Optional[User]:
        result = await self.db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_by_github_id(self, github_id: str) -> Optional[User]:
        result = await self.db.execute(select(User).where(User.github_id == github_id))
        return result.scalar_one_or_none()

    async def get_by_username(self, username: str) -> Optional[User]:
        result = await self.db.execute(select(User).where(User.username == username))
        return result.scalar_one_or_none()

    async def upsert_github_user(
        self,
        github_id: str,
        username: str,
        email: Optional[str],
        display_name: Optional[str],
        avatar_url: Optional[str],
    ) -> User:
        from datetime import datetime, timezone

        user = await self.get_by_github_id(github_id)
        if user:
            user.username = username
            user.email = email
            user.display_name = display_name
            user.avatar_url = avatar_url
            user.last_login = datetime.now(timezone.utc)
        else:
            import uuid
            user = User(
                id=str(uuid.uuid4()),
                github_id=github_id,
                username=username,
                email=email,
                display_name=display_name,
                avatar_url=avatar_url,
            )
            self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user
