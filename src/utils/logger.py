"""Structured JSON logging for the A3E-DNS artifact.

Emits one JSON object per line on stderr, with a fixed set of fields:

    {"ts": "2026-11-10T12:34:56.789Z",
     "level": "INFO",
     "logger": "src.models.aee_engine",
     "msg": "…",
     "thesis": {"chapter": "Chapter 6", "framework": "A3E-DNS"},
     "…extra fields…"}

The JSON schema is stable so that the observability stack (§6.11.2:
Prometheus + Grafana) can parse it without a custom parser.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Any

from src import thesis_reference

__all__ = [
    "JsonFormatter",
    "get_logger",
    "configure_logging",
    "log_event",
]

_STANDARD_FIELDS = frozenset(
    (
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName",
    )
)


class JsonFormatter(logging.Formatter):
    """Format log records as a single JSON object per line."""

    def __init__(self, *, include_thesis: bool = True) -> None:
        super().__init__()
        self._include_thesis = include_thesis
        self._thesis = thesis_reference() if include_thesis else None

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc)
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if self._include_thesis and self._thesis is not None:
            payload["thesis"] = self._thesis

        # Anything the caller attached via `extra=` lands here.
        for key, value in record.__dict__.items():
            if key in _STANDARD_FIELDS or key in payload:
                continue
            if key.startswith("_"):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = repr(value)

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = record.stack_info

        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(
    level: str = "INFO",
    *,
    include_thesis: bool = True,
    stream: Any = None,
) -> None:
    """Configure the root logger to emit structured JSON.

    Safe to call more than once; only the first call installs handlers.
    """
    stream = stream if stream is not None else sys.stderr
    root = logging.getLogger()
    if any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        root.setLevel(getattr(logging, level.upper(), logging.INFO))
        return

    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter(include_thesis=include_thesis))
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


def get_logger(name: str, *, level: str | None = None) -> logging.Logger:
    """Return a configured logger for the given dotted module name."""
    logger = logging.getLogger(name)
    if level is not None:
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    return logger


def log_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    """Log a structured event at INFO level.

    ``event`` becomes the ``msg`` field; the remaining keyword arguments
    become top-level JSON fields (subject to JSON-serialisability; the
    formatter falls back to ``repr`` for non-serialisable values).
    """
    logger.info(event, extra=fields)
