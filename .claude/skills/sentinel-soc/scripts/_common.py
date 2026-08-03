"""Shared helpers for the sentinel-soc skill scripts.

These scripts are invoked by a headless Claude Code session running as the
`sentinel` user. They are strictly read-only: they open the database with a
read-only transaction and never write.

Kept dependency-light on purpose — asyncpg (already in the venv) and stdlib.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import asyncpg
except ImportError:  # pragma: no cover - only hit outside the server venv
    print(
        "asyncpg is not available. Run this with the Sentinel venv:\n"
        "  /opt/sentinel/venv/bin/python <script>",
        file=sys.stderr,
    )
    raise SystemExit(2) from None

SECRETS_FILE = Path(os.environ.get("SENTINEL_SECRETS", "/etc/sentinel/secrets.env"))
CONFIG_FILE = Path(os.environ.get("SENTINEL_CONFIG", "/etc/sentinel/sentinel.yaml"))

# Statement timeout for every query these scripts run. A skill script must never
# be the reason the database is busy.
STATEMENT_TIMEOUT_MS = 15_000


# --------------------------------------------------------------------------
# Connection
# --------------------------------------------------------------------------
def _read_env_file(path: Path) -> dict[str, str]:
    """Parse a KEY=value file. Values may be quoted. Comments and blanks skipped."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key.strip()] = value
    return out


def database_dsn() -> str:
    """Resolve the database DSN from the environment or the secrets file."""
    if dsn := os.environ.get("SENTINEL_DB_DSN"):
        return dsn
    env = _read_env_file(SECRETS_FILE)
    if dsn := env.get("SENTINEL_DB_DSN"):
        return dsn
    user = env.get("SENTINEL_DB_USER", "sentinel")
    password = env.get("SENTINEL_DB_PASSWORD", "")
    host = env.get("SENTINEL_DB_HOST", "127.0.0.1")
    port = env.get("SENTINEL_DB_PORT", "5432")
    name = env.get("SENTINEL_DB_NAME", "sentinel")
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


async def connect() -> asyncpg.Connection:
    conn = await asyncpg.connect(database_dsn(), timeout=10)
    await conn.execute(f"SET statement_timeout = {STATEMENT_TIMEOUT_MS}")
    # Belt and braces: even if a query were somehow mutating, this refuses it.
    await conn.execute("SET default_transaction_read_only = on")
    return conn


def run(coro: Awaitable[Any]) -> Any:
    """Run an async main and translate operational failures into clean exits."""
    try:
        return asyncio.run(coro)  # type: ignore[arg-type]
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except (asyncpg.PostgresError, OSError) as exc:
        die(f"database error: {exc}")


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, list | tuple):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if hasattr(value, "__str__") and type(value).__module__ in ("ipaddress", "uuid", "decimal"):
        return str(value)
    return value


def rows_to_dicts(rows: Sequence[Any]) -> list[dict[str, Any]]:
    return [{k: _jsonable(v) for k, v in dict(r).items()} for r in rows]


def emit(data: Any, fmt: str = "json") -> None:
    """Print a result set as JSON or as an aligned table."""
    if fmt == "json":
        print(json.dumps(_jsonable(data), ensure_ascii=False, indent=2, default=str))
        return

    if not isinstance(data, list) or not data:
        print("(no rows)")
        return

    cols = list(data[0].keys())
    widths = {c: max(len(c), *(len(_cell(r.get(c))) for r in data)) for c in cols}
    print(" | ".join(c.ljust(widths[c]) for c in cols))
    print("-+-".join("-" * widths[c] for c in cols))
    for r in data:
        print(" | ".join(_cell(r.get(c)).ljust(widths[c]) for c in cols))


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict | list):
        return json.dumps(_jsonable(value), ensure_ascii=False)[:120]
    return str(value)[:120]


def die(message: str, code: int = 1) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(code)


# --------------------------------------------------------------------------
# Argument helpers
# --------------------------------------------------------------------------
_WINDOW_RE = re.compile(r"^(\d+)([mhd])$")
_WINDOW_UNITS = {"m": "minutes", "h": "hours", "d": "days"}


def parse_window(value: str) -> timedelta:
    """Parse `30m`, `24h`, `7d` into a timedelta. Bounded to 90 days."""
    match = _WINDOW_RE.match(value.strip().lower())
    if not match:
        die(f"invalid time window {value!r}; use forms like 30m, 24h, 7d")
    amount, unit = int(match.group(1)), match.group(2)  # type: ignore[union-attr]
    delta = timedelta(**{_WINDOW_UNITS[unit]: amount})
    if delta > timedelta(days=90):
        die("time window may not exceed 90d")
    if delta <= timedelta(0):
        die("time window must be positive")
    return delta


def since(window: str) -> datetime:
    return datetime.now(timezone.utc) - parse_window(window)


def add_format_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("json", "table"),
        default="json",
        help="output format (default: json)",
    )


def main_wrapper(fn: Callable[[], Any]) -> None:
    """Entry point wrapper that keeps tracebacks out of the model's context."""
    try:
        fn()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate: a clean message beats a traceback
        die(f"{type(exc).__name__}: {exc}")
