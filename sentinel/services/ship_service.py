"""`sentinel ship` — expeditorul de loturi către agregatorul extern.

Serviciu propriu, separat de `sentinel-beacon`, și separarea e cerința, nu o
consecință a împărțirii pe fișiere.

Beaconul e canalul prin care gazda spune că trăiește. Nu reîncearcă, nu
blochează, nu scrie pe disc, iar unitatea lui e strânsă în consecință
(`ReadOnlyPaths=/etc/sentinel`, `MemoryMax=128M`). Expeditorul face lucrul opus:
citește loturi de rânduri, ține conexiuni mai lungi, reîncearcă cu backoff. Puse
în același proces, o scurgere de memorie sau o buclă de reîncercare din al doilea
ar opri primul — adică un bug în raportarea de date ar deveni o pană a canalului
prin care se anunță penele. Vezi capul lui `sentinel/report/beacon.py`.
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence

from sentinel.config import get_config
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.report import shipper
from sentinel.services import parse_service_args

log = get_logger(__name__)


async def _main() -> int:
    cfg = get_config()
    db = Database(cfg)
    await db.connect()
    try:
        await shipper.run_forever(db, cfg)
    finally:
        await db.close()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel ship", add_help=False)
    parser.add_argument("--log-level", default="INFO")
    args = parse_service_args(parser, argv)
    setup_logging("sentinel-shipper", args.log_level)
    try:
        return asyncio.run(_main())
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # noqa: BLE001
        log.error("shipper failed to start", extra={"detail": str(exc)})
        return 1
