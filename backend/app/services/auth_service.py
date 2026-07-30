"""
Sentinel AI — Auth Service (GitHub OAuth2 + Local Dev Bypass)
"""
from datetime import datetime, timezone
from typing import Optional, Tuple

import httpx
import structlog

from app.core.config import settings
from app.core.exceptions import AuthError
from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)
from app.db.models.user import User
from app.db.repositories.user_repository import UserRepository

log = structlog.get_logger(__name__)


class AuthService:
    def __init__(self, user_repo: UserRepository) -> None:
        self.user_repo = user_repo

    # ============================================================
    # GitHub OAuth2
    # ============================================================

    def get_github_oauth_url(self) -> str:
        """Return the GitHub OAuth2 authorization URL."""
        if not settings.GITHUB_CLIENT_ID:
            raise AuthError("GitHub OAuth2 is not configured (GITHUB_CLIENT_ID missing)")
        return (
            f"https://github.com/login/oauth/authorize"
            f"?client_id={settings.GITHUB_CLIENT_ID}"
            f"&redirect_uri={settings.GITHUB_REDIRECT_URI}"
            f"&scope=read:user,user:email"
        )

    async def exchange_github_code(self, code: str) -> Tuple[User, str, str]:
        """
        Exchange a GitHub OAuth2 code for tokens and upsert the user.
        Returns (user, access_token, refresh_token).
        """
        if not settings.GITHUB_CLIENT_ID or not settings.GITHUB_CLIENT_SECRET:
            raise AuthError("GitHub OAuth2 is not configured")

        async with httpx.AsyncClient() as client:
            # Exchange code for access token
            token_response = await client.post(
                "https://github.com/login/oauth/access_token",
                json={
                    "client_id": settings.GITHUB_CLIENT_ID,
                    "client_secret": settings.GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": settings.GITHUB_REDIRECT_URI,
                },
                headers={"Accept": "application/json"},
                timeout=15,
            )
            token_response.raise_for_status()
            token_data = token_response.json()

            github_token = token_data.get("access_token")
            if not github_token:
                raise AuthError(f"GitHub did not return an access token: {token_data}")

            # Fetch user profile
            user_response = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {github_token}", "Accept": "application/vnd.github+json"},
                timeout=15,
            )
            user_response.raise_for_status()
            github_user = user_response.json()

            # Fetch primary email if not in profile
            email = github_user.get("email")
            if not email:
                email_response = await client.get(
                    "https://api.github.com/user/emails",
                    headers={"Authorization": f"Bearer {github_token}"},
                    timeout=15,
                )
                if email_response.status_code == 200:
                    emails = email_response.json()
                    primary = next((e for e in emails if e.get("primary") and e.get("verified")), None)
                    if primary:
                        email = primary.get("email")

        user = await self.user_repo.upsert_github_user(
            github_id=str(github_user["id"]),
            username=github_user["login"],
            email=email,
            display_name=github_user.get("name"),
            avatar_url=github_user.get("avatar_url"),
        )
        log.info("github_login_success", user_id=user.id, username=user.username)
        return user, create_access_token(user.id), create_refresh_token(user.id)

    # ============================================================
    # Local Dev Auth Bypass
    # ============================================================

    async def register_local_user(self, username: str, password: str) -> User:
        if not settings.ENABLE_LOCAL_AUTH:
            raise AuthError("Local authentication is disabled in production")
        existing = await self.user_repo.get_by_username(username)
        if existing:
            raise AuthError(f"Username '{username}' is already taken")
        import uuid
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            hashed_password=hash_password(password),
            is_local_user=True,
        )
        return await self.user_repo.create(user)

    async def login_local(self, username: str, password: str) -> Tuple[User, str, str]:
        if not settings.ENABLE_LOCAL_AUTH:
            raise AuthError("Local authentication is disabled in production")
        user = await self.user_repo.get_by_username(username)
        if not user or not user.is_local_user or not user.hashed_password:
            raise AuthError("Invalid credentials")
        if not verify_password(password, user.hashed_password):
            raise AuthError("Invalid credentials")
        user.last_login = datetime.now(timezone.utc)
        log.info("local_login_success", user_id=user.id, username=user.username)
        return user, create_access_token(user.id), create_refresh_token(user.id)
