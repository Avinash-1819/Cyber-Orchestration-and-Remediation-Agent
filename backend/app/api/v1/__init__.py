"""
Sentinel AI — API v1 Router
"""
from fastapi import APIRouter

from app.api.v1.endpoints import auth, incidents, reports, scan, sessions, ws

router = APIRouter()
router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
router.include_router(scan.router, prefix="/scan", tags=["Scan"])
router.include_router(sessions.router, prefix="/sessions", tags=["Sessions"])
router.include_router(reports.router, prefix="/reports", tags=["Reports"])
router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
router.include_router(ws.router, prefix="/ws", tags=["WebSocket"])
