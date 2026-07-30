"""
Sentinel AI — Application Entry Point
"""
from contextlib import asynccontextmanager
import secrets

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.logging import configure_logging
from app.db.database import init_db
from app.api.v1 import router as api_v1_router

configure_logging()
log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown."""
    log.info("sentinel_ai_starting", env=settings.APP_ENV, version="1.0.0")

    # Auto-generate JWT secret if not configured
    if not settings.JWT_SECRET:
        generated = secrets.token_hex(64)
        import os
        os.environ["JWT_SECRET"] = generated
        log.warning(
            "jwt_secret_auto_generated",
            message="JWT_SECRET was not set. A random secret was generated for this session. "
                    "Set JWT_SECRET in .env to persist sessions across restarts.",
        )

    await init_db()
    log.info("database_initialized")

    yield

    log.info("sentinel_ai_shutdown")


app = FastAPI(
    title="Sentinel AI",
    description="Commercial-grade multi-agent cybersecurity platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.APP_ENV == "development" else None,
    redoc_url="/api/redoc" if settings.APP_ENV == "development" else None,
)

# === Middleware ===
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL, "http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Routes ===
app.include_router(api_v1_router, prefix="/api/v1")


@app.get("/", tags=["System"])
async def root():
    return JSONResponse({
        "app": "Sentinel AI Platform",
        "status": "online",
        "version": "1.0.0",
        "docs": "/api/docs",
        "health": "/health",
        "api_v1": "/api/v1",
    })


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    from fastapi.responses import Response
    return Response(status_code=204)


@app.get("/health", tags=["System"])
async def health_check():
    return JSONResponse({"status": "ok", "version": "1.0.0", "service": "sentinel-ai"})
