"""`sentinel scan` — the vulnerability scan pass.

One-shot, not a daemon: the systemd timer fires it inside the maintenance window
(03:00-05:00 by default), it runs every enabled scanner once, records findings,
and exits. Running at 3 a.m. keeps the heavier scanners off the box during the
day, and one-shot means a hung scanner is reaped by the timer, not left running.
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence

from sentinel.config import get_config
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.scan import orchestrator
from sentinel.services import parse_service_args

log = get_logger(__name__)


async def _main() -> int:
    cfg = get_config()
    db = Database(cfg)
    await db.connect()
    try:
        log.info("scan pass started")
        summary = await orchestrator.run_all(db, cfg, triggered_by="schedule")
        log.info("scan pass done", extra={"summary": summary})
    finally:
        await db.close()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel scan", add_help=False)
    parser.add_argument("--log-level", default="INFO")
    args = parse_service_args(parser, argv)
    setup_logging("sentinel-scan", args.log_level)
    try:
        return asyncio.run(_main())
    except Exception as exc:  # noqa: BLE001
        log.error("scan failed to start", extra={"detail": str(exc)})
        return 1
