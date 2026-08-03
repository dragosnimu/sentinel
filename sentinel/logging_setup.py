"""Structured logging to journald.

One format for every daemon, and a redaction filter on the way out. A security
tool that leaks an API key into its own logs has created the incident it exists
to prevent, and journald is readable by more people than `/etc/sentinel`.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any

from sentinel.util.shellsafe import redact

_RESERVED = frozenset(
    {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName", "message", "asctime",
    }
)


class RedactingFilter(logging.Filter):
    """Strip credential-shaped strings from the message and from extras."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: redact(v) if isinstance(v, str) else v for k, v in record.args.items()
                }
            else:
                record.args = tuple(
                    redact(a) if isinstance(a, str) else a for a in record.args
                )
        for key, value in list(record.__dict__.items()):
            if key not in _RESERVED and isinstance(value, str):
                record.__dict__[key] = redact(value)
        return True


class JSONFormatter(logging.Formatter):
    """One JSON object per line. journald keeps it, and it greps cleanly."""

    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "service": self.service,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)

        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = str(value)

        return json.dumps(payload, ensure_ascii=False, default=str)


class HumanFormatter(logging.Formatter):
    """Readable output for a terminal. Used when stderr is a tty."""

    def __init__(self, service: str) -> None:
        super().__init__(
            fmt=f"%(asctime)s %(levelname)-8s [{service}] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )


def setup_logging(service: str, level: str | None = None) -> logging.Logger:
    """Configure the root logger for a daemon. Idempotent."""
    resolved = (level or os.environ.get("SENTINEL_LOG_LEVEL") or "INFO").upper()

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        HumanFormatter(service) if sys.stderr.isatty() else JSONFormatter(service)
    )
    handler.addFilter(RedactingFilter())

    root.addHandler(handler)
    root.setLevel(getattr(logging, resolved, logging.INFO))

    # These are chatty at INFO and say nothing Sentinel needs.
    for noisy in ("asyncio", "httpx", "httpcore", "telegram", "urllib3", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    return logging.getLogger(service)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
