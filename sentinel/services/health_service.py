"""`sentinel health` — one availability + capacity probe, then exit.

Invoked by sentinel-health.timer every 30s as a systemd oneshot. Doing it as a
oneshot rather than a long-running loop means a hung probe cannot wedge the
service: systemd's TimeoutStartSec kills it and the next tick starts clean, and a
gap in samples is recorded as an outage rather than papered over.

Each run:
  1. syncs inventory.yaml into the assets table (so an edit takes effect without
     a restart — cheap, idempotent) and, when that sync retired something, says
     so once, by name, on Telegram — see `_announce_retired`;
  2. probes every asset once and records availability + outages;
  3. samples host capacity.

Flags:
  --probe-only / --capacity-only   run just one half (for debugging)
  --rollup                         roll up yesterday's availability and exit
                                   (called from maintenance, not the 30s timer)
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence
from html import escape
from pathlib import Path

from sentinel.config import Config, get_config
from sentinel.db.engine import Database
from sentinel.health import capacity, prober, sla
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.scan import inventory
from sentinel.services import parse_service_args

log = get_logger(__name__)


async def _connect(cfg: Config) -> Database:
    db = Database(cfg)
    await db.connect()
    return db


async def _sync_inventory(db: Database, path: Path = inventory.INVENTORY_PATH) -> None:
    """Sync inventory.yaml into the assets table, and say what the sync changed.

    Wrapped, because a bad inventory must not stop the probe: the rows already
    in the table are what this run can still measure, and refusing to measure
    them because the file is unreadable turns one fault into a monitoring
    outage.

    `path` is a parameter for the same reason `inventory.sync` has one — so a
    test can point this at a fixture instead of /etc.
    """
    try:
        result = await inventory.sync(db, path)
    except Exception as exc:  # noqa: BLE001 - a bad inventory must not stop probing known assets
        log.error("inventory sync failed; probing existing assets anyway",
                  extra={"detail": str(exc)})
        return

    retired = list(result.get("retired_names") or [])
    if not retired:
        return
    try:
        await _announce_retired(db, retired)
    except Exception as exc:  # noqa: BLE001
        # The rows are already retired, and `retire_missing` skips rows that
        # carry a `retired_at`, so this list will not come back on the next
        # pass: a failed insert is the one chance lost, not a delayed one. It is
        # logged WITH the names, at error, so the fact still exists somewhere
        # reachable — and it is not reported as delivered.
        log.error("retired assets could not be queued for Telegram",
                  extra={"names": ", ".join(retired), "detail": str(exc)})


async def _announce_retired(db: Database, names: list[str]) -> None:
    """One queued Telegram message naming the assets that stopped being watched.

    Why this exists at all: `sync` has returned the retired names since the day
    retiring was added, and the only caller dropped the value on the floor. The
    change reached the operator as two INFO lines in the journal, which is the
    same place the four permanently-red services hid for eighteen days. A
    monitoring tool that changes what it monitors without saying so is back to
    confirming its own intention.

    Why once, and why without a suppression window: `sentinel health` runs
    `sync` every 30 seconds, but `retire_missing` only touches rows where
    `retired_at IS NULL`, so an asset is reported retired on exactly one pass —
    the next pass returns an empty list. The message is bounded by the edit that
    caused it, not by a timer that could be got wrong. (Re-adding a name and
    removing it again is a second edit, and gets a second message; that is the
    intended reading, not a duplicate.)

    Why no threshold on how many: a threshold would block a legitimate removal
    of eight assets out of fourteen and would then need a way around itself. The
    number is not the signal — the names are, because the operator is the only
    party who can tell an edit they made from a file that got truncated.

    `high`, not `critical`: it is held by a quiet window and delivered when the
    window lifts (`telegram/quiet.py`). Something the operator most likely did
    themselves does not have to wake them at 03:00; it does have to arrive.
    """
    listed = "\n".join(f"• <code>{escape(n, quote=False)}</code>" for n in names)
    body = (
        "<b>Nume scoase din inventar</b>\n\n"
        f"{listed}\n\n"
        "Ce e mai sus nu mai e sondat și nu mai apare pe pagina Servicii. "
        "Rândurile rămân în bază, cu tot istoricul lor; un nume pus la loc în "
        "<code>inventory.yaml</code> revine activ, cu același id.\n\n"
        "<b>Dacă nu tu ai făcut ștergerea, fișierul e trunchiat.</b> Sentinel nu "
        "poate deosebi o scoatere intenționată de una pierdută dintr-o editare "
        "eșuată — la asta poți răspunde doar tu."
    )
    await db.execute(
        """
        INSERT INTO notifications (channel, severity, dedup_key, title, body)
        VALUES ('telegram', $1::text, $2::text, $3::text, $4::text)
        """,
        "high", f"inventory:retired:{','.join(names)}"[:180],
        "Active retrase din inventar", body)


async def _run(args: argparse.Namespace) -> int:
    cfg = get_config()
    db = await _connect(cfg)
    try:
        if args.rollup:
            await sla.rollup_day(db)
            return 0

        # Keep the DB's asset list in step with inventory.yaml. Idempotent and
        # cheap for a handful of assets; means editing the inventory takes effect
        # on the next tick with no restart.
        if not args.capacity_only:
            await _sync_inventory(db)
            await prober.probe_all(db, cfg)

        if not args.probe_only:
            await capacity.sample_and_record(db)
        return 0
    finally:
        await db.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel health", add_help=False)
    parser.add_argument("--probe-only", action="store_true")
    parser.add_argument("--capacity-only", action="store_true")
    parser.add_argument("--rollup", action="store_true", help="roll up yesterday's availability and exit")
    args = parse_service_args(parser, argv)

    setup_logging("sentinel-health")
    try:
        return asyncio.run(_run(args))
    except Exception as exc:  # noqa: BLE001
        log.error("health run failed", extra={"detail": str(exc)})
        return 1
