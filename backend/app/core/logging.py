"""
Sentinel AI — Structured Logging Configuration (structlog)
"""
import logging
import sys

import structlog
from structlog.types import EventDict, WrappedLogger

from app.core.config import settings


def add_app_info(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """Add application metadata to every log entry."""
    event_dict["app"] = "sentinel-ai"
    event_dict["env"] = settings.APP_ENV
    return event_dict


def configure_logging() -> None:
    """Configure structlog for the application."""
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        add_app_info,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if settings.APP_ENV == "production":
        # JSON output for log aggregators (Datadog, CloudWatch, etc.)
        processors = shared_processors + [
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Human-readable console output for development
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=True),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.APP_LOG_LEVEL.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Also configure stdlib logging so uvicorn/httpx logs flow through structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.APP_LOG_LEVEL.upper(), logging.INFO),
    )
