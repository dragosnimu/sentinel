"""Rate-limit bookkeeping for `/intreaba`.

One row per attempt that actually reaches the model (see `ai/ask.py`), never
per rejected message — a chat testing the limit itself must not be able to
extend its own lockout by hammering it.
"""

from __future__ import annotations

from sentinel.db.engine import Database


async def record(db: Database, chat_id: int) -> None:
    await db.execute("INSERT INTO ask_log (chat_id) VALUES ($1)", chat_id)


async def count_last_hour(db: Database, chat_id: int) -> int:
    return int(await db.fetchval(
        "SELECT count(*) FROM ask_log WHERE chat_id = $1 "
        "AND asked_at > now() - interval '1 hour'",
        chat_id) or 0)
