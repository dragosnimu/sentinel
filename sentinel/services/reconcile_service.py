"""`sentinel reconcile` — make the recorded blocklist match the kernel.

Runs once at boot, after the executor has recreated the table, and can be run by
hand whenever the self-check reports the two disagreeing.

By default it corrects the DATABASE: the kernel is the truth about what is
blocked, and after a reboot the truth is "nothing". `--reapply` inverts that for
an operator who would rather not have a 04:00 kernel update release every
attacker — at the cost of the escape hatch the rest of the design leans on.
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence

from sentinel.config import get_config
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.respond.reconcile import reconcile
from sentinel.services import parse_service_args

log = get_logger(__name__)


async def _main(reapply: bool) -> int:
    cfg = get_config()
    db = Database(cfg)
    await db.connect()
    try:
        result = await reconcile(db, cfg, reapply=reapply)
        log.info("reconcile done", extra=vars(result))
        print(f"bază: {result.stored} · kernel: {result.live} · {result.note}")
        return 0 if result.live >= 0 else 1
    finally:
        await db.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel reconcile", add_help=False)
    parser.add_argument("--reapply", action="store_true",
                        help="push stored blocks back into the kernel instead")
    parser.add_argument("--log-level", default="INFO")
    args = parse_service_args(parser, argv)
    setup_logging("sentinel-reconcile", args.log_level)
    try:
        return asyncio.run(_main(args.reapply))
    except Exception as exc:  # noqa: BLE001
        log.error("reconcile failed", extra={"detail": str(exc)})
        return 1
