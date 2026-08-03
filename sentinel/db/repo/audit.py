"""The audit log, from the application side.

Privileged operations are audited by the root executor, which writes its own
rows precisely so that a compromised caller cannot forge or omit one. This
module is for everything else: logins, config changes, acknowledgements — the
things the web app and the bot do on their own authority.

Both feed the same hash-chained table, and a broken chain is detectable.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

GENESIS_HASH = "0" * 64


def _entry_hash(payload: dict[str, Any], prev_hash: str) -> str:
    material = json.dumps(
        {**payload, "prev_hash": prev_hash},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(material.encode()).hexdigest()


async def record(
    db: Database,
    *,
    actor: str,
    source: str,
    operation: str,
    target: str | None = None,
    params: dict[str, Any] | None = None,
    result: str = "ok",
    detail: str | None = None,
) -> int:
    """Append one hash-chained entry.

    The read of the previous hash and the insert happen in one transaction with
    the row locked, so two concurrent writers cannot both chain onto the same
    predecessor and silently fork the chain.

    `params` holds argument *names and values* here, unlike the executor which
    records names only. The difference is deliberate: the executor handles paths
    and commands that may embed credentials, while these are application-level
    values the operator needs to see. Anything sensitive still must not be
    passed in — there is no redaction at this layer.
    """
    payload = {
        "actor": actor,
        "source": source,
        "operation": operation,
        "target": target,
        "params": params or {},
        "result": result,
        "detail": (detail or "")[:1000] or None,
    }

    async with db.transaction() as conn:
        prev = await conn.fetchval(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE"
        )
        prev_hash = prev or GENESIS_HASH
        digest = _entry_hash(payload, prev_hash)

        return int(
            await conn.fetchval(
                """
                INSERT INTO audit_log (actor, source, operation, target, params,
                                       result, detail, prev_hash, entry_hash)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING id
                """,
                actor,
                source,
                operation,
                target,
                json.dumps(payload["params"], default=str),
                result,
                payload["detail"],
                prev_hash,
                digest,
            )
        )


async def verify_chain(db: Database, limit: int = 10_000) -> dict[str, Any]:
    """Walk the chain and report the first break.

    A break means one of two things: the database was restored from a backup
    over newer rows (benign, but worth confirming you know about it), or someone
    modified the table. The latter requires superuser access, because a trigger
    refuses UPDATE and DELETE at the database level — so it is not a small
    finding.
    """
    rows = await db.fetch(
        """
        SELECT id, actor, source, operation, target, params, result, detail,
               prev_hash, entry_hash
          FROM audit_log
         ORDER BY id
         LIMIT $1
        """,
        limit,
    )
    if not rows:
        return {"ok": True, "checked": 0, "first_break": None}

    expected_prev = GENESIS_HASH
    for row in rows:
        payload = {
            "actor": row["actor"],
            "source": row["source"],
            "operation": row["operation"],
            "target": row["target"],
            "params": json.loads(row["params"]) if isinstance(row["params"], str) else row["params"],
            "result": row["result"],
            "detail": row["detail"],
        }
        if row["prev_hash"] != expected_prev:
            return {
                "ok": False,
                "checked": len(rows),
                "first_break": row["id"],
                "reason": "prev_hash does not match the preceding entry",
            }
        if _entry_hash(payload, row["prev_hash"]) != row["entry_hash"]:
            return {
                "ok": False,
                "checked": len(rows),
                "first_break": row["id"],
                "reason": "entry_hash does not match the row contents",
            }
        expected_prev = row["entry_hash"]

    return {"ok": True, "checked": len(rows), "first_break": None}


async def recent(
    db: Database, *, hours: int = 24, limit: int = 200, source: str | None = None
) -> list[dict[str, Any]]:
    rows = await db.fetch(
        """
        SELECT id, at, actor, source, operation, target, result, detail
          FROM audit_log
         WHERE at >= now() - make_interval(hours => $1)
           AND ($2::text IS NULL OR source = $2)
         ORDER BY at DESC
         LIMIT $3
        """,
        hours,
        source,
        limit,
    )
    return [dict(r) for r in rows]
