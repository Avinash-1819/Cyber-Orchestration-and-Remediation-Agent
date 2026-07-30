"""
Sentinel AI — Typed Exception Hierarchy
All domain exceptions inherit from SentinelError for uniform error handling.
"""
from typing import Any, Optional


class SentinelError(Exception):
    """Base exception for all Sentinel AI errors."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, details={self.details!r})"


# === Agent / Orchestration ===

class AgentError(SentinelError):
    """Error raised by an agent during execution."""

    def __init__(self, agent_name: str, message: str, details: Optional[Any] = None) -> None:
        super().__init__(f"[{agent_name}] {message}", details)
        self.agent_name = agent_name


class ValidationError(SentinelError):
    """LLM response failed Pydantic schema validation after retries."""

    def __init__(self, agent_name: str, raw_response: str, validation_error: str) -> None:
        super().__init__(
            f"[{agent_name}] LLM output failed schema validation",
            {"raw_response": raw_response[:500], "validation_error": validation_error},
        )
        self.agent_name = agent_name


class ClassificationError(SentinelError):
    """Payload classification failed or confidence too low."""
    pass


class LowConfidenceError(SentinelError):
    """Classification confidence is below the configured threshold."""

    def __init__(self, confidence: float, threshold: float, suggestion: str) -> None:
        super().__init__(
            f"Classification confidence {confidence:.2f} is below threshold {threshold:.2f}",
            {"suggestion": suggestion},
        )
        self.confidence = confidence
        self.threshold = threshold
        self.suggestion = suggestion


# === External API ===

class ExternalAPIError(SentinelError):
    """Error communicating with an external intelligence source."""

    def __init__(self, source: str, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(f"[{source}] {message}", {"status_code": status_code})
        self.source = source
        self.status_code = status_code


class RateLimitError(ExternalAPIError):
    """External API rate limit exceeded."""

    def __init__(self, source: str, retry_after: Optional[int] = None) -> None:
        super().__init__(source, f"Rate limit exceeded (retry_after={retry_after}s)")
        self.retry_after = retry_after


# === Auth ===

class AuthError(SentinelError):
    """Authentication or authorization failure."""
    pass


class TokenExpiredError(AuthError):
    """JWT token has expired."""
    pass


class InvalidTokenError(AuthError):
    """JWT token is malformed or has an invalid signature."""
    pass


class InsufficientPermissionsError(AuthError):
    """User does not have permission to perform this action."""
    pass


# === Database ===

class DatabaseError(SentinelError):
    """Database operation failed."""
    pass


class SessionNotFoundError(DatabaseError):
    """Scan session does not exist."""

    def __init__(self, session_id: str) -> None:
        super().__init__(f"Session not found: {session_id}")
        self.session_id = session_id


# === Reporting ===

class ReportGenerationError(SentinelError):
    """Failed to generate a report artifact."""
    pass
