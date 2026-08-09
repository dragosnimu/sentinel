"""Structured logging to journald.

One format for every daemon, and a redaction filter on the way out. A security
tool that leaks an API key into its own logs has created the incident it exists
to prevent, and journald is readable by more people than `/etc/sentinel`.

## Redaction happens in two places, and it has to

`RedactingFilter` cleans `record.msg` and `record.args` **when they are already
strings**, plus the string extras. Three things are structurally out of its
reach, and each one is a way past it:

  * the exception — `exc_info` and `exc_text` are in `_RESERVED`, deliberately,
    and a filter cannot rewrite a traceback that has not been rendered yet. So
    everything reached through `exc_info=`, including every `log.exception()`
    call, used to walk straight into `payload["exc"]`;
  * a non-string `msg` or `%`-argument — `log.error(exc)` or
    `log.debug("cannot read %s: %s", path, exc)`. The filter skips them because
    they are not `str`; the interpolation into text happens later, in
    `record.getMessage()`;
  * an extra that is not JSON-serialisable — the `str()` that would expose it
    also happens later, in the formatter.

None of that is theoretical. An exception message routinely quotes the input
that caused it: a PostgreSQL constraint violation carries the rejected row
verbatim, and that row is whatever the operator typed into Telegram.

So the formatters redact too. The redaction is applied to the *values*, never to
the serialised JSON: the credential pattern ends in `\\S+`, which does not stop
at a quote — over `json.dumps` output it eats the closing quote and the comma
and leaves a line no parser can read.

## What is and is not covered — read this before trusting it

Redacted on the way out: `msg` (after interpolation), `exc`, `stack`, every
string extra, and any extra the formatter has to stringify.

**Not redacted: strings nested inside a JSON-serialisable extra.** An
`extra={"peer": {"auth": "token=..."}}` is handed to `json.dumps` whole — the
filter skips it because the value is not a `str`, and the formatter does not
walk into it. Five call sites pass container extras today — `detect/accounts.py`,
`services/maintenance_service.py`, `services/reconcile_service.py` and twice in
`services/selfcheck_service.py`; none carries a credential (they carry check keys
and IP addresses), but nothing stops one.

That count was four until the census was redone. The first scan read literal
`extra={...}` dicts, so it could not see `extra=vars(result)` or `extra=summary`
— which are three of the five, and the loudest in production. It also counted
`health/prober.py`, whose extra values are ints. A count produced by a scan
blind to half its subject is this file's own failure mode: the number was the
scan's reach, reported as the code's shape.

Closing it means recursing into containers and redacting the string leaves.
Note what that would and would not buy: `redact` is *contextual* — it matches
`token=<value>` inside one string. A leaf like `"token=abc"` would be cleaned; a
split `{"token": "abc"}` would not, because the key and the value are separate
strings and neither looks like a credential on its own. Key-aware redaction is a
larger change and is not what this module does today.
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
            # Redacted here, not in the filter: the filter only touches `msg`
            # and `args` when they are already `str`, and the interpolation that
            # turns a non-string one into text happens right here. Without this,
            # `log.error(exc)` and `log.debug("...%s", exc)` land in journald
            # raw — and this is the formatter systemd actually gets.
            "msg": redact(record.getMessage()),
        }
        # Redacted here rather than in the filter: the filter runs before the
        # traceback exists as text, and `exc_info`/`stack_info` are in
        # `_RESERVED`, so the filter cannot reach them by construction.
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        if record.stack_info:
            payload["stack"] = redact(self.formatStack(record.stack_info))

        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                # Another way past the filter: it only redacts values that are
                # already `str`, and this `str()` happens only now.
                payload[key] = redact(str(value))

        return json.dumps(payload, ensure_ascii=False, default=str)


class HumanFormatter(logging.Formatter):
    """Readable output for a terminal. Used when stderr is a tty."""

    def __init__(self, service: str) -> None:
        super().__init__(
            fmt=f"%(asctime)s %(levelname)-8s [{service}] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )

    def format(self, record: logging.LogRecord) -> str:
        # Same gap as the JSON side: the base `logging.Formatter` appends the
        # traceback from `exc_text`, which the filter never sees. A terminal is
        # less public than journald, but "less public" is not a useful category
        # for a credential — this is what gets pasted into tickets and chat.
        return redact(super().format(record))


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
