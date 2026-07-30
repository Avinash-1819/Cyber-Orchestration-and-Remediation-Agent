"""
Sentinel AI — In-Process Sliding Window Rate Limiter
No Redis required for v1. Uses in-memory atomic counters per key.
For multi-process deployments, replace with Redis-based implementation.
"""
import asyncio
import time
from collections import defaultdict, deque
from typing import Optional

import structlog
from fastapi import Request
from fastapi.responses import JSONResponse

log = structlog.get_logger(__name__)


class SlidingWindowRateLimiter:
    """Thread-safe sliding window rate limiter using deque of timestamps."""

    def __init__(self) -> None:
        self._windows: dict[str, deque] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> bool:
        """Returns True if the request is allowed, False if rate-limited."""
        now = time.monotonic()
        cutoff = now - window_seconds

        async with self._lock:
            window = self._windows[key]

            # Evict timestamps outside the window
            while window and window[0] < cutoff:
                window.popleft()

            if len(window) >= max_requests:
                log.warning("rate_limit_exceeded", key=key, count=len(window), limit=max_requests)
                return False

            window.append(now)
            return True

    async def remaining(self, key: str, max_requests: int, window_seconds: int) -> int:
        """Returns the number of remaining requests in the current window."""
        now = time.monotonic()
        cutoff = now - window_seconds

        async with self._lock:
            window = self._windows[key]
            valid = sum(1 for ts in window if ts >= cutoff)
            return max(0, max_requests - valid)


# Global singleton limiter instance
_limiter = SlidingWindowRateLimiter()


def get_limiter() -> SlidingWindowRateLimiter:
    return _limiter


def rate_limit_middleware(max_requests: int, window_seconds: int = 60, key_func=None):
    """
    FastAPI dependency factory for rate limiting.

    Usage:
        @router.post("/scan")
        async def scan(request: Request, _=Depends(rate_limit_middleware(10, 60))):
            ...
    """
    async def dependency(request: Request):
        # Default key: client IP
        if key_func:
            key = key_func(request)
        else:
            forwarded_for = request.headers.get("X-Forwarded-For")
            key = forwarded_for.split(",")[0].strip() if forwarded_for else (request.client.host if request.client else "unknown")

        allowed = await _limiter.is_allowed(key, max_requests, window_seconds)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": f"Too many requests. Max {max_requests} per {window_seconds}s.",
                },
                headers={"Retry-After": str(window_seconds)},
            )

    return dependency
