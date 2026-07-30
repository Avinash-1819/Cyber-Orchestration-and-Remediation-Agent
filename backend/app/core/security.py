"""
Sentinel AI — JWT + Auth Security Utilities
"""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import structlog
from jose import JWTError, jwt
import bcrypt
from app.core.config import settings
from app.core.exceptions import InvalidTokenError, TokenExpiredError

log = structlog.get_logger(__name__)


# === Password Hashing ===

def hash_password(password: str) -> str:
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False


# === JWT ===

def _get_secret() -> str:
    """Get JWT secret, falling back to env var or auto-generated value."""
    import os
    secret = settings.JWT_SECRET or os.environ.get("JWT_SECRET", "")
    if not secret:
        raise RuntimeError("JWT_SECRET is not configured. Check your .env file.")
    return secret


def create_access_token(user_id: str, additional_claims: Optional[dict] = None) -> str:
    """Create a short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": expire,
        "type": "access",
        **(additional_claims or {}),
    }
    return jwt.encode(payload, _get_secret(), algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    """Create a long-lived JWT refresh token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    jti = secrets.token_hex(32)
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": expire,
        "type": "refresh",
        "jti": jti,
    }
    return jwt.encode(payload, _get_secret(), algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token. Raises on invalid/expired."""
    try:
        payload = jwt.decode(token, _get_secret(), algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError as e:
        err_str = str(e).lower()
        if "expired" in err_str:
            raise TokenExpiredError("Token has expired") from e
        raise InvalidTokenError(f"Invalid token: {e}") from e


def extract_user_id(token: str) -> str:
    """Extract user_id (sub claim) from a valid JWT token."""
    payload = decode_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise InvalidTokenError("Token missing 'sub' claim")
    return str(user_id)
