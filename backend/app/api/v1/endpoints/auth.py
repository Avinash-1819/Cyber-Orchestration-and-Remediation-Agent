"""
Sentinel AI — Auth Endpoints (GitHub OAuth2 + Local Dev Bypass)
"""
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import AuthError
from app.core.security import create_access_token, create_refresh_token, decode_token, extract_user_id
from app.db.database import get_db
from app.db.repositories.audit_log_repository import AuditLogRepository
from app.db.repositories.user_repository import UserRepository
from app.services.auth_service import AuthService

log = structlog.get_logger(__name__)
router = APIRouter()


class LocalLoginRequest(BaseModel):
    username: str
    password: str


class LocalRegisterRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: str
    username: str


class RefreshRequest(BaseModel):
    refresh_token: str


def _get_auth_service(db: AsyncSession) -> AuthService:
    return AuthService(UserRepository(db))


@router.get("/github/login")
async def github_login(db: AsyncSession = Depends(get_db)):
    """Redirect to GitHub OAuth2 authorization."""
    try:
        svc = _get_auth_service(db)
        url = svc.get_github_oauth_url()
        return RedirectResponse(url=url)
    except AuthError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/github/callback")
async def github_callback(
    code: str = Query(...),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """Handle GitHub OAuth2 callback and issue JWT tokens."""
    try:
        svc = _get_auth_service(db)
        user, access_token, refresh_token = await svc.exchange_github_code(code)

        audit = AuditLogRepository(db)
        await audit.append(
            user_id=user.id,
            action="LOGIN_GITHUB",
            ip_address=request.client.host if request and request.client else None,
        )

        # Redirect to frontend with tokens in URL fragment (SPA handles it)
        frontend_url = f"{settings.FRONTEND_URL}/auth/callback?access_token={access_token}&refresh_token={refresh_token}&user_id={user.id}&username={user.username}"
        return RedirectResponse(url=frontend_url)

    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        log.exception("github_callback_error")
        raise HTTPException(status_code=500, detail="Authentication failed")


@router.post("/local/register", response_model=TokenResponse)
async def local_register(body: LocalRegisterRequest, db: AsyncSession = Depends(get_db)):
    """Register a local dev user (only available when ENABLE_LOCAL_AUTH=true)."""
    if not settings.ENABLE_LOCAL_AUTH:
        raise HTTPException(status_code=403, detail="Local auth is disabled")
    try:
        svc = _get_auth_service(db)
        user = await svc.register_local_user(body.username, body.password)
        return TokenResponse(
            access_token=create_access_token(user.id),
            refresh_token=create_refresh_token(user.id),
            user_id=user.id,
            username=user.username,
        )
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/local/login", response_model=TokenResponse)
async def local_login(body: LocalLoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Login with local credentials (dev only)."""
    if not settings.ENABLE_LOCAL_AUTH:
        raise HTTPException(status_code=403, detail="Local auth is disabled")
    try:
        svc = _get_auth_service(db)
        user, access_token, refresh_token = await svc.login_local(body.username, body.password)

        audit = AuditLogRepository(db)
        await audit.append(
            user_id=user.id,
            action="LOGIN_LOCAL",
            ip_address=request.client.host if request.client else None,
        )
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            user_id=user.id,
            username=user.username,
        )
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Refresh access token using refresh token."""
    try:
        payload = decode_token(body.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload.get("sub")
        user_repo = UserRepository(db)
        user = await user_repo.get_by_id(user_id)
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        return TokenResponse(
            access_token=create_access_token(user.id),
            refresh_token=create_refresh_token(user.id),
            user_id=user.id,
            username=user.username,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
