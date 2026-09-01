"""`sentinel restoredrill` — exercițiul lunar de restaurare (Funcționalitatea 07).

One-shot, pornit de `sentinel-restore-drill.timer`. Alege un punct de
restaurare, cere executorului să-l verifice într-un spațiu izolat — niciodată
`/` — și înregistrează rezultatul. Vezi `sentinel/patch/restore_drill.py`
pentru mecanism și `executor/commands.py:op_restore_drill_verify` pentru
izolare.

Nu ridică pe un eșec al exercițiului însuși (executor jos, punct corupt) —
acelea sunt înregistrate ca rânduri `succeeded=false` și raportate mai departe
de verificarea de sănătate (`sentinel/selfcheck/checks.py:check_restore_drill`),
canalul deja existent spre Telegram. Codul de ieșire nenul e rezervat pentru
ce chiar oprește serviciul: baza inaccesibilă, o eroare neprevăzută.
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence

from sentinel.config import get_config
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.patch import restore_drill
from sentinel.services import parse_service_args

log = get_logger(__name__)


async def _main() -> int:
    cfg = get_config()
    db = Database(cfg)
    await db.connect()
    try:
        log.info("restore drill started")
        outcome = await restore_drill.run(db, cfg)
        if not outcome.ran:
            log.info("restore drill: nothing to do", extra={"detail": outcome.detail})
        else:
            log.info("restore drill done",
                     extra={"succeeded": outcome.succeeded, "detail": outcome.detail,
                            "counts": outcome.counts})
    finally:
        await db.close()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel restoredrill", add_help=False)
    parser.add_argument("--log-level", default="INFO")
    args = parse_service_args(parser, argv)
    setup_logging("sentinel-restoredrill", args.log_level)
    try:
        return asyncio.run(_main())
    except Exception as exc:  # noqa: BLE001
        log.error("restore drill failed to start", extra={"detail": str(exc)})
        return 1
