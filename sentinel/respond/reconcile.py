"""Make the database agree with the kernel about who is blocked.

They come apart at every reboot, by design: the nftables table is never
persisted, so a restart clears every block. That is a stated guarantee — "a
reboot is always a way out of a self-inflicted block" — and it is the single
cheapest protection against locking yourself out of your own server.

What was missing is the other half. After that reboot the database still claimed
seven addresses were blocked. Nothing was. For a day the dashboard, the Telegram
commands and the operator's mental model all described a firewall state that did
not exist.

So this does not re-apply the blocks. It **records that they are gone**:

    kernel is the truth about what is blocked
    database is the record of what was decided

When those disagree, the database is what gets corrected, and the correction is
written down with a reason rather than applied silently — an attacker who was
blocked and is now not is a fact worth being able to find later.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger

log = get_logger(__name__)


@dataclass
class Reconciliation:
    stored: int
    live: int
    released: int
    reapplied: int
    note: str


async def reconcile(db: Database, cfg: Config, *, reapply: bool = False) -> Reconciliation:
    """Bring the two views back together.

    `reapply=True` inverts the default and pushes the stored blocks back into
    the kernel instead. It exists because a reboot for an unrelated reason —
    a kernel update at 04:00 — releasing every attacker is a defensible thing to
    not want. It is not the default, because turning it on quietly removes the
    escape hatch the rest of the design leans on.
    """
    from sentinel.db.repo import blocklist as blocklist_repo
    from sentinel.respond import actions

    live = await actions.live_count()
    if live < 0:
        return Reconciliation(0, -1, 0, 0, "executorul nu răspunde")

    stored_rows = await blocklist_repo.list_active(db, limit=10_000)
    stored = len(stored_rows)

    if stored == 0 or live == stored:
        return Reconciliation(stored, live, 0, 0, "deja sincronizate")

    if not reapply:
        released = 0
        for row in stored_rows:
            await blocklist_repo.mark_unblocked(
                db, row.ip, by="reconcile",
                reason="tabela nftables nu mai conține blocarea (probabil repornire)")
            released += 1
        log.warning("blocklist reconciled to the kernel",
                    extra={"stored": stored, "live": live, "released": released})
        return Reconciliation(stored, live, released, 0,
                              f"{released} blocări marcate ca expirate")

    reapplied = 0
    for row in stored_rows:
        ttl = None
        if row.expires_at is not None:
            from datetime import datetime, timezone
            ttl = int((row.expires_at - datetime.now(timezone.utc)).total_seconds())
            if ttl <= 0:
                await blocklist_repo.mark_unblocked(db, row.ip, by="reconcile",
                                                    reason="expirat")
                continue
        try:
            await actions.block(db, row.ip, ttl=ttl, reason=f"reaplicat: {row.reason}",
                                by="reconcile")
            reapplied += 1
        except Exception as exc:  # noqa: BLE001 - one bad row must not stop the rest
            log.error("could not reapply a block",
                      extra={"ip": row.ip, "detail": str(exc)})
    log.warning("blocklist reapplied to the kernel",
                extra={"stored": stored, "reapplied": reapplied})
    return Reconciliation(stored, live, 0, reapplied,
                          f"{reapplied} blocări reaplicate")


async def summary(db: Database) -> dict[str, Any]:
    from sentinel.db.repo import blocklist as blocklist_repo
    from sentinel.respond import actions

    return {
        "stored": len(await blocklist_repo.list_active(db, limit=10_000)),
        "live": await actions.live_count(),
    }
