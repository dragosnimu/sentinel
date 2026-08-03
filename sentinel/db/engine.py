"""asyncpg connection pool, retry, and LISTEN/NOTIFY.

Ingest signals detect over `LISTEN/NOTIFY` rather than polling hard. But NOTIFY
is fire-and-forget: it is lost if the listener is momentarily disconnected. So
the listener also polls on a floor interval and reads a watermark. A lost
notification costs latency, never correctness.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable
from typing import Any

import asyncpg

from sentinel.config import Config, database_dsn, get_config
from sentinel.errors import StorageError
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

EVENTS_CHANNEL = "sentinel_events"
_RETRY_DELAYS = (0.5, 1, 2, 5, 10, 30)


class Database:
    """A pool plus the few conveniences every daemon needs."""

    def __init__(self, cfg: Config | None = None, dsn: str | None = None) -> None:
        self._cfg = cfg or get_config()
        self._dsn = dsn or database_dsn(self._cfg)
        self._pool: asyncpg.Pool | None = None

    # -- lifecycle ---------------------------------------------------------
    async def connect(self) -> None:
        if self._pool is not None:
            return
        db = self._cfg.database
        last_error: Exception | None = None

        for delay in (*_RETRY_DELAYS, None):
            try:
                self._pool = await asyncpg.create_pool(
                    self._dsn,
                    min_size=db.pool_min,
                    max_size=db.pool_max,
                    command_timeout=db.statement_timeout_ms / 1000,
                    server_settings={
                        "application_name": "sentinel",
                        "statement_timeout": str(db.statement_timeout_ms),
                        # A stuck idle transaction holds locks and blocks
                        # partition maintenance; kill them rather than debug them.
                        "idle_in_transaction_session_timeout": "60000",
                    },
                )
                log.info("database connected", extra={"host": db.host, "database": db.name})
                return
            except (asyncpg.PostgresError, OSError) as exc:
                last_error = exc
                if delay is None:
                    break
                log.warning(
                    "database not reachable, retrying",
                    extra={"delay_s": delay, "detail": str(exc)},
                )
                await asyncio.sleep(delay)

        raise StorageError(f"could not connect to the database: {last_error}")

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise StorageError("database pool is not open; call connect() first")
        return self._pool

    async def __aenter__(self) -> Database:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    # -- queries -----------------------------------------------------------
    async def fetch(self, sql: str, *args: Any) -> list[asyncpg.Record]:
        async with self.pool.acquire() as conn:
            return await conn.fetch(sql, *args)

    async def fetchrow(self, sql: str, *args: Any) -> asyncpg.Record | None:
        async with self.pool.acquire() as conn:
            return await conn.fetchrow(sql, *args)

    async def fetchval(self, sql: str, *args: Any) -> Any:
        async with self.pool.acquire() as conn:
            return await conn.fetchval(sql, *args)

    async def execute(self, sql: str, *args: Any) -> str:
        async with self.pool.acquire() as conn:
            return await conn.execute(sql, *args)

    async def executemany(self, sql: str, rows: list[tuple[Any, ...]]) -> None:
        if not rows:
            return
        async with self.pool.acquire() as conn:
            await conn.executemany(sql, rows)

    @contextlib.asynccontextmanager
    async def transaction(self) -> AsyncIterator[asyncpg.Connection]:
        async with self.pool.acquire() as conn, conn.transaction():
            yield conn

    # -- notification ------------------------------------------------------
    async def notify(self, channel: str = EVENTS_CHANNEL, payload: str = "") -> None:
        # pg_notify() rather than NOTIFY so the channel and payload are bound
        # parameters. NOTIFY takes an identifier, which would mean building SQL
        # by string concatenation.
        await self.execute("SELECT pg_notify($1, $2)", channel, payload[:7000])

    async def listen(
        self,
        channel: str,
        callback: Callable[[str], Any],
        *,
        poll_floor_s: float = 0.25,
    ) -> None:
        """Listen on a channel, reconnecting forever.

        The caller is expected to also poll a watermark at `poll_floor_s`, so a
        dropped notification delays work rather than losing it.
        """
        while True:
            conn: asyncpg.Connection | None = None
            try:
                conn = await asyncpg.connect(self._dsn)

                def _handler(
                    _conn: object, _pid: int, _channel: str, payload: str
                ) -> None:
                    result = callback(payload)
                    if asyncio.iscoroutine(result):
                        asyncio.create_task(result)  # noqa: RUF006 - fire and forget by design

                await conn.add_listener(channel, _handler)
                log.info("listening", extra={"channel": channel})

                while not conn.is_closed():
                    await asyncio.sleep(poll_floor_s)

            except asyncio.CancelledError:
                raise
            except (asyncpg.PostgresError, OSError) as exc:
                log.warning("listener dropped, reconnecting", extra={"detail": str(exc)})
                await asyncio.sleep(2)
            finally:
                if conn is not None and not conn.is_closed():
                    with contextlib.suppress(Exception):
                        await conn.close()

    # -- health ------------------------------------------------------------
    async def healthy(self) -> bool:
        try:
            return await self.fetchval("SELECT 1") == 1
        except (asyncpg.PostgresError, OSError, StorageError):
            return False

    async def size_bytes(self) -> int:
        return int(await self.fetchval("SELECT pg_database_size(current_database())") or 0)


_db: Database | None = None


async def get_db() -> Database:
    """Process-wide pool. Each daemon is a separate process, so one each."""
    global _db
    if _db is None:
        _db = Database()
        await _db.connect()
    return _db


async def close_db() -> None:
    global _db
    if _db is not None:
        await _db.close()
        _db = None
