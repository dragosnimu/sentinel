"""Single-use approval tokens.

The security property that matters is in `consume`: the token is checked and
marked used inside ONE statement. A read-then-write would let two taps on the
same button — a double tap, a retried callback, two operators at once — both
pass the check before either wrote, and a patch would apply twice.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sentinel.db.engine import Database

# Short enough that an approval is a decision about the machine as it is now,
# long enough to read the plan first.
DEFAULT_TTL_S = 600


@dataclass
class Token:
    token: str
    purpose: str
    stage: int
    chat_id: int | None
    plan_id: int | None
    plan_hash: str | None
    expires_at: datetime


def new_token() -> str:
    # Appears in a Telegram callback_data, which is capped at 64 bytes and lives
    # in a chat history forever — so it is opaque, unguessable, and worthless
    # once used.
    return secrets.token_urlsafe(18)


async def issue(db: Database, *, purpose: str, stage: int = 1,
                chat_id: int | None = None, plan_id: int | None = None,
                plan_hash: str | None = None, created_by: str,
                ttl_s: int = DEFAULT_TTL_S) -> str:
    token = new_token()
    await db.execute(
        """
        INSERT INTO approval_tokens
            (token, purpose, stage, chat_id, plan_id, plan_hash, created_by, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))
        """,
        token, purpose, stage, chat_id, plan_id, plan_hash, created_by, ttl_s)
    return token


async def consume(db: Database, token: str, *, purpose: str, chat_id: int | None,
                  used_by: str) -> Token | None:
    """Atomically validate and spend a token. Returns None if it is unknown,
    expired, already used, or belongs to a different chat or purpose.

    The conditions live in the UPDATE, not in Python: checking first and writing
    afterwards is how the same button gets honoured twice.
    """
    row = await db.fetchrow(
        """
        UPDATE approval_tokens
           SET used_at = now(), used_by = $4
         WHERE token = $1
           AND purpose = $2
           AND used_at IS NULL
           AND expires_at > now()
           AND (chat_id IS NULL OR chat_id = $3)
        RETURNING token, purpose, stage, chat_id, plan_id, plan_hash, expires_at
        """,
        token, purpose, chat_id, used_by)
    return Token(**dict(row)) if row else None


async def revoke_for_plan(db: Database, plan_id: int) -> int:
    """Kill every outstanding token for a plan.

    Called when a plan is rejected, re-generated or applied. Without it, a
    button sent an hour ago stays live in a chat scrollback — which is exactly
    the kind of thing someone taps by accident while scrolling.
    """
    rows = await db.fetch(
        "UPDATE approval_tokens SET used_at = now(), used_by = 'revoked' "
        "WHERE plan_id = $1 AND used_at IS NULL RETURNING token",
        plan_id)
    return len(rows)


async def purge_expired(db: Database) -> int:
    rows = await db.fetch(
        "DELETE FROM approval_tokens WHERE used_at IS NOT NULL "
        "AND created_at < now() - interval '7 days' RETURNING token")
    return len(rows)


async def outstanding(db: Database, plan_id: int) -> list[dict[str, Any]]:
    rows = await db.fetch(
        "SELECT token, stage, chat_id, expires_at FROM approval_tokens "
        "WHERE plan_id = $1 AND used_at IS NULL AND expires_at > now()",
        plan_id)
    return [dict(r) for r in rows]
