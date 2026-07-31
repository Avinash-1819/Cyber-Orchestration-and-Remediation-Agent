"""
Sentinel AI — Abstract Base Agent
Provides the shared LLM-call + validation + trace-logging + error-capture pattern.
All 6 specialized agents extend this class.
"""
import asyncio
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Set

import structlog

from app.agents.state import SentinelState
from app.core.exceptions import AgentError
from app.services.llm_client import LLMClient, get_llm_client

log = structlog.get_logger(__name__)

# Registry of all active WebSocket subscribers, keyed by session_id
# This is populated by the WS endpoint and used to push live updates
_ws_subscribers: Dict[str, Set[Any]] = {}


def register_ws_subscriber(session_id: str, queue: asyncio.Queue) -> None:
    if session_id not in _ws_subscribers:
        _ws_subscribers[session_id] = set()
    _ws_subscribers[session_id].add(queue)


def unregister_ws_subscriber(session_id: str, queue: asyncio.Queue) -> None:
    if session_id in _ws_subscribers:
        _ws_subscribers[session_id].discard(queue)


async def _broadcast_state_update(session_id: str, event: dict) -> None:
    """Broadcast a state update event to all WebSocket subscribers for this session."""
    subscribers = _ws_subscribers.get(session_id, set())
    dead = set()
    for queue in subscribers:
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            dead.add(queue)
    for q in dead:
        subscribers.discard(q)


class BaseAgent(ABC):
    """
    Abstract base for all Sentinel AI agents.

    Subclasses must implement:
    - AGENT_NAME: str — identifying name for trace/logging
    - execute(state: SentinelState) -> SentinelState — core logic

    The base class handles:
    - Setting current_agent on entry/exit
    - Appending execution trace entries
    - Broadcasting WS events for live pipeline timeline
    - Capturing exceptions into state.errors without crashing the pipeline
    """

    AGENT_NAME: str = "BaseAgent"

    def __init__(self) -> None:
        self._llm: LLMClient | None = None

    @property
    def llm(self) -> LLMClient:
        """Lazy-initialized LLM client — only instantiated when an agent actually calls the LLM."""
        if self._llm is None:
            self._llm = get_llm_client()
        return self._llm

    async def run(self, state: SentinelState) -> SentinelState:
        """
        Entry point called by the LangGraph orchestrator.
        Wraps execute() with tracing, error handling, and WS broadcasting.
        """
        log.info("agent_starting", agent=self.AGENT_NAME, session_id=state.session_id)

        state.current_agent = self.AGENT_NAME
        state.append_trace(
            agent=self.AGENT_NAME,
            event="started",
            details={"session_id": state.session_id},
        )

        # Broadcast live update to WebSocket subscribers
        await _broadcast_state_update(state.session_id, {
            "type": "agent_started",
            "agent": self.AGENT_NAME,
            "session_id": state.session_id,
        })

        try:
            state = await self.execute(state)

            state.append_trace(
                agent=self.AGENT_NAME,
                event="completed",
                details={"finding_count": len(state.findings)},
            )
            await _broadcast_state_update(state.session_id, {
                "type": "agent_completed",
                "agent": self.AGENT_NAME,
                "session_id": state.session_id,
                "finding_count": len(state.findings),
            })
            log.info("agent_completed", agent=self.AGENT_NAME, session_id=state.session_id)

        except AgentError as e:
            log.error("agent_error", agent=self.AGENT_NAME, error=str(e), session_id=state.session_id)
            state.add_error(self.AGENT_NAME, str(e))
            await _broadcast_state_update(state.session_id, {
                "type": "agent_error",
                "agent": self.AGENT_NAME,
                "session_id": state.session_id,
                "error": str(e),
            })

        except Exception as e:
            # Catch-all: never crash the whole pipeline on one agent's failure
            log.exception("agent_unexpected_error", agent=self.AGENT_NAME, session_id=state.session_id)
            state.add_error(self.AGENT_NAME, f"Unexpected error: {type(e).__name__}: {str(e)[:200]}")
            await _broadcast_state_update(state.session_id, {
                "type": "agent_error",
                "agent": self.AGENT_NAME,
                "session_id": state.session_id,
                "error": f"Unexpected: {str(e)[:200]}",
            })

        finally:
            state.current_agent = None

        return state

    @abstractmethod
    async def execute(self, state: SentinelState) -> SentinelState:
        """Core agent logic. Must return the mutated state."""
        pass

    def _trace(self, state: SentinelState, event: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Convenience method for mid-execution trace entries."""
        state.append_trace(agent=self.AGENT_NAME, event=event, details=details or {})
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(
                _broadcast_state_update(state.session_id, {
                    "type": "trace",
                    "agent": self.AGENT_NAME,
                    "event": event,
                    "details": details or {},
                })
            )
            task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
        except RuntimeError:
            # No running event loop (e.g. sync test context) — trace already recorded.
            pass
