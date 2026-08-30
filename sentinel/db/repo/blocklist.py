"""The blocklist as the DB sees it — the history and the UI view.

The nftables sets are the source of truth for what is *actually* blocked (kernel
TTL expires entries there, and a reboot clears them — both deliberate escape
hatches). This table is the record of *why*: who blocked what, when, on what
grounds, and when it was lifted. The two can drift (a TTL expires in the kernel
while the row still says active); the UI reconciles by asking the executor for
the live set count.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sentinel.db.engine import Database


@dataclass
class Block:
    id: int
    ip: str
    reason: str
    created_by: str
    blocked_at: datetime
    expires_at: datetime | None
    ttl_seconds: int | None
    incident_id: int | None
    active: bool


async def record_block(
    db: Database,
    *,
    ip: str,
    reason: str,
    created_by: str,
    ttl_seconds: int | None,
    incident_id: int | None = None,
    actor_key: str | None = None,
) -> int:
    return int(
        await db.fetchval(
            """
            INSERT INTO blocklist (ip, reason, created_by, ttl_seconds, expires_at,
                                   incident_id, actor_key, active)
            VALUES ($1::inet, $2, $3, $4,
                    CASE WHEN $4::int IS NULL THEN NULL ELSE now() + make_interval(secs => $4) END,
                    $5, $6, true)
            RETURNING id
            """,
            ip, reason[:500], created_by, ttl_seconds, incident_id, actor_key,
        )
    )


async def mark_unblocked(db: Database, ip: str, *, by: str, reason: str = "manual") -> int:
    """Mark every active row for this IP as lifted. Returns how many."""
    rows = await db.fetch(
        """
        UPDATE blocklist
           SET active = false, unblocked_at = now(), unblocked_by = $2, unblock_reason = $3
         WHERE host(ip) = $1 AND active
        RETURNING id
        """,
        ip, by, reason[:200],
    )
    return len(rows)


async def mark_all_unblocked(db: Database, *, by: str, reason: str) -> int:
    rows = await db.fetch(
        """
        UPDATE blocklist SET active = false, unblocked_at = now(), unblocked_by = $1,
                             unblock_reason = $2
        WHERE active RETURNING id
        """,
        by, reason[:200],
    )
    return len(rows)


async def list_active(db: Database, limit: int = 200) -> list[Block]:
    rows = await db.fetch(
        """
        SELECT id, host(ip) AS ip, reason, created_by, blocked_at, expires_at,
               ttl_seconds, incident_id, active
        FROM blocklist WHERE active ORDER BY blocked_at DESC LIMIT $1
        """,
        limit,
    )
    return [Block(**dict(r)) for r in rows]


async def recent(db: Database, limit: int = 100) -> list[Block]:
    rows = await db.fetch(
        """
        SELECT id, host(ip) AS ip, reason, created_by, blocked_at, expires_at,
               ttl_seconds, incident_id, active
        FROM blocklist ORDER BY blocked_at DESC LIMIT $1
        """,
        limit,
    )
    return [Block(**dict(r)) for r in rows]


async def count_active(db: Database) -> int:
    return int(await db.fetchval("SELECT count(*) FROM blocklist WHERE active") or 0)


async def count_active_cidrs(db: Database) -> int:
    """How many active blocks are RANGES rather than single addresses.

    Reads the mask straight off `ip`, not `prefix_len`: `record_block` above
    never sets `prefix_len` on insert, only `ip` — so a query keyed on
    `prefix_len` would read back zero forever regardless of what is actually
    blocked. `ip` genuinely carries the mask for whatever string was inserted
    (a plain address defaults to /32 or /128; a CIDR string keeps its own),
    so that is what the decider's max_active_cidrs guard must trust.
    """
    return int(await db.fetchval(
        """
        SELECT count(*) FROM blocklist
         WHERE active AND (
           (family(ip) = 4 AND masklen(ip) < 32) OR
           (family(ip) = 6 AND masklen(ip) < 128)
         )
        """
    ) or 0)


async def count_auto_since(db: Database, seconds: int) -> int:
    """How many the decider has auto-blocked in the last `seconds`. Feeds the
    per-minute rate cap: a runaway detector must not black-hole the internet one
    /32 at a time. created_by is 'auto:<rule>' for every decider block."""
    return int(await db.fetchval(
        "SELECT count(*) FROM blocklist "
        "WHERE created_by LIKE 'auto:%' AND blocked_at > now() - make_interval(secs => $1)",
        seconds,
    ) or 0)


async def is_active(db: Database, ip: str) -> bool:
    return bool(await db.fetchval("SELECT 1 FROM blocklist WHERE host(ip) = $1 AND active LIMIT 1", ip))
