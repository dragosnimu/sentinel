"""`sentinel patchwindow` — fereastra săptămânală de reparare (Funcționalitatea 08).

One-shot, pornit de `sentinel-patch-window.timer`. Nu vorbește NICIODATĂ cu
Telegram direct — vezi `sentinel/patch/window.py` pentru motiv: singurele două
transporturi stampilate cu identitatea instanței sunt `StampingBot` (procesul
botului) și `telegram/direct.py` (folosit doar de cei trei apelanți deja
verificați de `tests/security/test_telegram_names_its_instance.py`). Un al
patrulea apelant necunoscut ar trimite mesaje nemarcate — exact incidentul din
27 august 2026. În loc să trimită, fereastra scrie o singură coloană
(`patch_plans.proposed_by_window`), iar bucla de push deja existentă a botului
(`sentinel/telegram/bot.py:_push_plans`), deja stampilată, deja testată,
preia planul eliberat în cel mult 15 secunde.

Nu ridică pe un eșec al ferestrei înseși (poarta nu găsește nimic eligibil,
fereastra e oprită de un eșec anterior) — acelea sunt stări normale,
înregistrate ca rânduri în `patch_window_runs` și raportate mai departe de
`sentinel/selfcheck/checks.py:check_patch_window`. Codul de ieșire nenul e
rezervat pentru ce chiar oprește serviciul: baza inaccesibilă, o eroare
neprevăzută.
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence

from sentinel.config import get_config
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.patch import window
from sentinel.services import parse_service_args

log = get_logger(__name__)


async def _main() -> int:
    cfg = get_config()
    db = Database(cfg)
    await db.connect()
    try:
        log.info("patch window started")
        outcome = await window.run(db, cfg)
        if outcome.halted:
            log.error("patch window halted", extra={"detail": outcome.halt_detail})
        elif outcome.proposed_plan_id is not None:
            log.warning("patch window released a plan",
                       extra={"plan": outcome.proposed_plan_id, "detail": outcome.detail})
        else:
            log.info("patch window: nothing released", extra={"detail": outcome.detail})
    finally:
        await db.close()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel patchwindow", add_help=False)
    parser.add_argument("--log-level", default="INFO")
    args = parse_service_args(parser, argv)
    setup_logging("sentinel-patchwindow", args.log_level)
    try:
        return asyncio.run(_main())
    except Exception as exc:  # noqa: BLE001
        log.error("patch window failed to start", extra={"detail": str(exc)})
        return 1
