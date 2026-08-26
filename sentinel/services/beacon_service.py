"""`sentinel beacon` — expeditorul semnalului către martorul extern.

Serviciu propriu, de lungă durată, nu un timer și nu inclus în alt serviciu.

Timer la 60 s ar însemna un proces nou în fiecare minut, cu o conexiune nouă la
baza de date de fiecare dată — cost inutil pentru o buclă care doarme.

Inclus în `sentinel-detect` ar fi mai rău: ar muri odată cu el. Separat,
ambele moduri de eșec ajung la martor — dacă expeditorul cade, semnalul dispare;
dacă altceva cade, semnalul sosește cu contoare care nu mai avansează.
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence

from sentinel.config import get_config
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.report import beacon
from sentinel.services import parse_service_args

log = get_logger(__name__)


async def _main() -> int:
    cfg = get_config()
    db = Database(cfg)
    await db.connect()
    try:
        await beacon.run_forever(db, cfg)
    finally:
        await db.close()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel beacon", add_help=False)
    parser.add_argument("--log-level", default="INFO")
    args = parse_service_args(parser, argv)
    setup_logging("sentinel-beacon", args.log_level)
    try:
        return asyncio.run(_main())
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # noqa: BLE001
        log.error("beacon failed to start", extra={"detail": str(exc)})
        return 1
