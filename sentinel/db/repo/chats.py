"""Per-chat notification preferences, and per-chat use of the bot.

A row appears the first time a chat sets something — or, since `record_command`,
the first time it sends a command. Chats that have done neither have no row and
fall back to the deployment config, which is why every read here tolerates a
missing row rather than creating one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sentinel.db.engine import Database


@dataclass
class ChatPrefs:
    chat_id: int
    quiet_hours: str | None = None
    muted_until: datetime | None = None
    timezone: str | None = None
    quiet_set_at: datetime | None = None


async def get_prefs(db: Database, chat_id: int) -> ChatPrefs:
    row = await db.fetchrow(
        "SELECT chat_id, quiet_hours, muted_until, timezone, quiet_set_at "
        "FROM telegram_chats WHERE chat_id = $1",
        chat_id)
    if row is None:
        return ChatPrefs(chat_id=chat_id)
    return ChatPrefs(**dict(row))


async def set_quiet_hours(db: Database, chat_id: int, window: str | None,
                          *, tz: str | None = None) -> None:
    """Set or clear the recurring window. `None` clears it."""
    await db.execute(
        """
        INSERT INTO telegram_chats (chat_id, quiet_hours, timezone, quiet_set_at)
        VALUES ($1, $2::text, $3::text, now())
        ON CONFLICT (chat_id) DO UPDATE
            SET quiet_hours = $2::text,
                -- COALESCE so setting a window does not wipe a timezone the
                -- operator configured separately.
                timezone = COALESCE($3::text, telegram_chats.timezone),
                quiet_set_at = now()
        """,
        chat_id, window, tz)


async def set_muted_until(db: Database, chat_id: int, until: datetime | None) -> None:
    await db.execute(
        """
        INSERT INTO telegram_chats (chat_id, muted_until)
        VALUES ($1, $2::timestamptz)
        ON CONFLICT (chat_id) DO UPDATE SET muted_until = $2::timestamptz
        """,
        chat_id, until)


async def clear_all_mutes(db: Database, chat_id: int) -> None:
    """`/unmute` — both mechanisms at once.

    Both, because an operator who says "stop muting" and then gets silence
    anyway from the other mechanism has been given a control that lies.
    """
    await db.execute(
        "UPDATE telegram_chats SET quiet_hours = NULL, muted_until = NULL, "
        "quiet_set_at = now() WHERE chat_id = $1",
        chat_id)


async def all_prefs(db: Database) -> dict[int, ChatPrefs]:
    """Every chat that has set something, keyed by chat id.

    Read once per push cycle rather than once per chat per message: the push
    loop runs every 15 seconds forever, and this table has as many rows as you
    have operators.
    """
    rows = await db.fetch(
        "SELECT chat_id, quiet_hours, muted_until, timezone, quiet_set_at "
        "FROM telegram_chats")
    return {int(r["chat_id"]): ChatPrefs(**dict(r)) for r in rows}


async def touch(db: Database, chat_id: int, **_: Any) -> None:
    """Record that a chat exists, without changing any preference."""
    await db.execute(
        "INSERT INTO telegram_chats (chat_id) VALUES ($1) ON CONFLICT DO NOTHING",
        chat_id)


async def record_command(db: Database, chat_id: int) -> None:
    """Count one accepted command against the chat that sent it.

    `commands_count` and `last_command_at` have been in the schema since 0006
    and were written by nothing at all, so they read 0 and NULL on a host whose
    operator had been using the bot for weeks. Two columns shaped exactly like a
    record of that use, containing the same thing an unused bot would contain —
    which is how they were read during a diagnosis, and why it went the wrong
    way for an hour.

    A row may not exist yet (a chat that never set a preference has none), so
    this inserts rather than assuming, and increments in SQL rather than
    read-modify-write: two commands arriving together must count as two.
    """
    await db.execute(
        """
        INSERT INTO telegram_chats (chat_id, commands_count, last_command_at)
        VALUES ($1, 1, now())
        ON CONFLICT (chat_id) DO UPDATE
            SET commands_count = telegram_chats.commands_count + 1,
                last_command_at = now()
        """,
        chat_id)
