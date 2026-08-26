"""`sentinel health` — one availability + capacity probe, then exit.

Invoked by sentinel-health.timer every 30s as a systemd oneshot. Doing it as a
oneshot rather than a long-running loop means a hung probe cannot wedge the
service: systemd's TimeoutStartSec kills it and the next tick starts clean, and a
gap in samples is recorded as an outage rather than papered over.

Each run:
  1. syncs inventory.yaml into the assets table (so an edit takes effect without
     a restart — cheap, idempotent);
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
            try:
                await inventory.sync(db)
            except Exception as exc:  # noqa: BLE001 - a bad inventory must not stop probing known assets
                log.error("inventory sync failed; probing existing assets anyway",
                          extra={"detail": str(exc)})
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
