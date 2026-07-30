"""
Sentinel AI — WebSocket Endpoint
/ws/{session_id} — streams execution_trace events live as each agent runs.
Uses native FastAPI WebSocket + asyncio Queue pattern (no Redis needed).
"""
import asyncio
import json
from typing import Optional

import structlog
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.base_agent import register_ws_subscriber, unregister_ws_subscriber
from app.core.security import extract_user_id
from app.core.exceptions import InvalidTokenError, TokenExpiredError
from app.db.database import AsyncSessionLocal
from app.db.repositories.session_repository import SessionRepository
from app.db.repositories.user_repository import UserRepository

log = structlog.get_logger(__name__)
router = APIRouter()


async def _authenticate_ws(token: str) -> Optional[str]:
    """Validate JWT from WebSocket query param. Returns user_id or None."""
    try:
        return extract_user_id(token)
    except (InvalidTokenError, TokenExpiredError):
        return None


@router.websocket("/{session_id}")
async def ws_session_stream(
    websocket: WebSocket,
    session_id: str,
    token: str = Query(..., description="JWT access token"),
):
    """
    WebSocket stream for a scan session.
    Streams: agent_started, agent_completed, trace, agent_error, classified, complete events.

    Protocol:
      Server → Client: JSON event objects
      Client → Server: "ping" for keepalive (optional)
    """
    # Authenticate via JWT in query param (WS can't send Authorization header easily)
    user_id = await _authenticate_ws(token)
    if not user_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid or expired token")
        return

    # Verify session ownership
    async with AsyncSessionLocal() as db:
        session_repo = SessionRepository(db)
        session = await session_repo.get_by_id(session_id)
        user_repo = UserRepository(db)
        user = await user_repo.get_by_id(user_id)

        if not session:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Session not found")
            return
        if session.user_id != user_id and not (user and user.is_admin):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Access denied")
            return

    await websocket.accept()
    log.info("ws_connected", session_id=session_id, user_id=user_id)

    # Send current state immediately (for reconnecting clients)
    async with AsyncSessionLocal() as db:
        session_repo = SessionRepository(db)
        session = await session_repo.get_by_id(session_id)
        if session and session.state_json:
            await websocket.send_text(json.dumps({
                "type": "state_snapshot",
                "session_id": session_id,
                "status": session.status,
                "current_agent": session.current_agent,
                "execution_trace": session.state_json.get("execution_trace", []),
                "findings_count": session.finding_count,
            }))

    # Register queue for live events from agents
    event_queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    register_ws_subscriber(session_id, event_queue)

    try:
        while True:
            # Wait for either an event from agents or a client message (ping/timeout)
            done, pending = await asyncio.wait(
                [
                    asyncio.create_task(event_queue.get()),
                    asyncio.create_task(websocket.receive_text()),
                ],
                timeout=30,
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()

            if not done:
                # Keepalive ping
                await websocket.send_text(json.dumps({"type": "ping"}))
                continue

            for task in done:
                try:
                    result = task.result()
                    if isinstance(result, str):
                        # Client message (pong/ping — ignore)
                        continue
                    elif isinstance(result, dict):
                        # Agent event from queue
                        await websocket.send_text(json.dumps(result, default=str))

                        # If session is completed/failed, send final state and close
                        if result.get("type") in ("session_complete", "session_failed"):
                            await websocket.close(code=status.WS_1000_NORMAL_CLOSURE)
                            return
                except Exception:
                    pass

    except WebSocketDisconnect:
        log.info("ws_disconnected", session_id=session_id, user_id=user_id)
    except Exception as e:
        log.error("ws_error", session_id=session_id, error=str(e))
    finally:
        unregister_ws_subscriber(session_id, event_queue)
