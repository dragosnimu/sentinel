"""Make the database agree with the kernel about who is blocked.

They come apart at every reboot, by design: the nftables table is never
persisted, so a restart clears every block. That is a stated guarantee — "a
reboot is always a way out of a self-inflicted block" — and it is the single
cheapest protection against locking yourself out of your own server.

What was missing is the other half. After that reboot the database still claimed
seven addresses were blocked. Nothing was. For a day the dashboard, the Telegram
commands and the operator's mental model all described a firewall state that did
not exist.

    kernel is the truth about what is blocked
    database is the record of what was decided

When they disagree, the record is what gets corrected — and the correction is
written down with a reason rather than applied silently, because an attacker who
was blocked and is now not is a fact worth being able to find later.

## Element by element, not by count

The first version compared two numbers and, on any mismatch, released
everything. That is right at boot, where the kernel is empty, and badly wrong on
a timer: one element expiring a second early would release every other block on
the host.

So the comparison is per address. Only the rows the kernel does not actually
have are touched, and a block that is present stays present.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger

log = get_logger(__name__)


@dataclass
class Reconciliation:
    stored: int
    live: int
    released: int = 0
    reapplied: int = 0
    note: str = ""
    missing: list[str] = field(default_factory=list)

    @property
    def in_sync(self) -> bool:
        return not self.missing


def _canonical(value: str) -> str:
    """A form both sides agree on.

    The database stores `203.0.113.4`; nftables may report `203.0.113.4` or
    `203.0.113.4/32` depending on how the element was added and which version is
    answering. Comparing the raw strings would decide that every single-address
    block is missing and release the lot.
    """
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return value.strip()
    return str(net.network_address) if net.num_addresses == 1 else str(net)


async def reconcile(db: Database, cfg: Config, *, reapply: bool = False) -> Reconciliation:
    """Bring the two views back together.

    `reapply=True` inverts the default and pushes the missing blocks back into
    the kernel instead. It exists because a reboot for an unrelated reason — a
    kernel update at 04:00 — releasing every attacker is a defensible thing to
    not want. It is not the default, because turning it on quietly removes the
    escape hatch the rest of the design leans on.
    """
    from sentinel.db.repo import blocklist as blocklist_repo
    from sentinel.respond import actions

    live = await actions.live_blocked()
    if live is None:
        # Not zero. An unreachable executor must never be read as "nothing is
        # blocked", which would release everything on a transient socket error.
        return Reconciliation(0, -1, note="executorul nu răspunde")

    stored_rows = await blocklist_repo.list_active(db, limit=10_000)
    live_canon = {_canonical(v) for v in live}
    missing = [row for row in stored_rows if _canonical(row.ip) not in live_canon]

    result = Reconciliation(stored=len(stored_rows), live=len(live),
                            missing=[r.ip for r in missing])
    if not missing:
        result.note = "deja sincronizate"
        return result

    if not reapply:
        for row in missing:
            await blocklist_repo.mark_unblocked(
                db, row.ip, by="reconcile",
                reason="nu mai există în nftables (repornire sau tabelă recreată)")
            result.released += 1
        log.warning("blocklist reconciled to the kernel",
                    extra={"stored": result.stored, "live": result.live,
                           "released": result.released})
        result.note = f"{result.released} blocări marcate ca expirate"
        return result

    for row in missing:
        ttl = None
        if row.expires_at is not None:
            from datetime import datetime, timezone
            ttl = int((row.expires_at - datetime.now(timezone.utc)).total_seconds())
            if ttl <= 0:
                await blocklist_repo.mark_unblocked(db, row.ip, by="reconcile",
                                                    reason="expirat")
                continue
        try:
            await actions.block(db, row.ip, ttl=ttl,
                                reason=f"reaplicat: {row.reason}", by="reconcile")
            result.reapplied += 1
        except Exception as exc:  # noqa: BLE001 - one bad row must not stop the rest
            log.error("could not reapply a block",
                      extra={"ip": row.ip, "detail": str(exc)})
    log.warning("blocklist reapplied to the kernel",
                extra={"stored": result.stored, "reapplied": result.reapplied})
    result.note = f"{result.reapplied} blocări reaplicate"
    return result


async def summary(db: Database) -> dict[str, Any]:
    from sentinel.db.repo import blocklist as blocklist_repo
    from sentinel.respond import actions

    live = await actions.live_blocked()
    return {
        "stored": len(await blocklist_repo.list_active(db, limit=10_000)),
        "live": -1 if live is None else len(live),
    }
