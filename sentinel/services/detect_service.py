"""`sentinel detect` — the detection daemon.

Long-running (systemd Type=exec, Restart=always). Every few seconds it runs one
detection pass over whatever ingest has written since the last one. Cheap and
deterministic: it is SQL over an indexed table, not a model call, so it can run
continuously at no per-event cost.

Each pass detects, raises incidents, and (P6) lets the decider act — observe
mode by default, so nothing is blocked until the operator arms it. Once an hour
it also refreshes the seasonal baselines the anomaly rule reads.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
from collections.abc import Sequence

from sentinel.config import Config, get_config
from sentinel.db.engine import Database
from sentinel.detect import engine
from sentinel.db.repo import logins as logins_repo
from sentinel.detect import logins as detect_logins
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.predict import baseline
from sentinel.services import parse_service_args

log = get_logger(__name__)

INTERVAL_S = 10
BASELINE_INTERVAL_S = 3600


async def _connect(cfg: Config) -> Database:
    db = Database(cfg)
    await db.connect()
    return db


async def _main() -> int:
    cfg = get_config()
    db = await _connect(cfg)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    log.info("detect daemon started", extra={"enabled": cfg.detection.enabled})
    next_baseline = 0.0  # loop.time() starts near zero, so the first pass runs it
    try:
        while not stop.is_set():
            try:
                await engine.run_once(db, cfg)
            except Exception as exc:  # noqa: BLE001 - a bad pass must not kill the daemon
                log.error("detect pass failed", extra={"detail": str(exc)})

            # Alertele de logare, pe aceeasi bataie. Nu pe o cale proprie: un
            # mecanism nou de alertare e si un mecanism nou care poate tacea
            # fara sa se observe. Starea traieste in coloane (`alerted_at`,
            # `summarised_at`), deci o trecere sarita nu pierde nimic — se
            # recupereaza la urmatoarea.
            try:
                # Intai maturatoarea: o sesiune inchisa presupus trebuie sa-si
                # primeasca rezumatul in aceeasi trecere, nu in urmatoarea.
                inchise = await logins_repo.close_stale_sessions(db)
                if inchise:
                    log.info("stale sessions closed", extra={"count": inchise})
                # Fusul CONFIGURAT, nu cel al gazdei: fereastra de „ore
                # nefirești" se evaluează în el, iar o diferență între cele
                # două ar muta fereastra cu tot decalajul fără ca nimic s-o
                # spună. Vezi `ODD_HOURS` în `detect/logins.py`.
                anuntate = await detect_logins.announce_new_sessions(
                    db, tz_name=cfg.timezone)
                rezumate = await detect_logins.summarise_closed_sessions(db)
                if anuntate or rezumate:
                    log.info("login alerts queued",
                             extra={"opened": anuntate, "closed": rezumate})
            except Exception as exc:  # noqa: BLE001 - idem
                log.error("login alerting failed", extra={"detail": str(exc)})
            if loop.time() >= next_baseline:
                next_baseline = loop.time() + BASELINE_INTERVAL_S
                try:
                    await baseline.update(db, cfg)
                except Exception as exc:  # noqa: BLE001 - baselines are best-effort
                    log.error("baseline update failed", extra={"detail": str(exc)})
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=INTERVAL_S)
    finally:
        await db.close()
    log.info("detect daemon stopped")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parse_service_args(
        argparse.ArgumentParser(prog="sentinel detect", add_help=False), argv)
    setup_logging("sentinel-detect")
    try:
        return asyncio.run(_main())
    except Exception as exc:  # noqa: BLE001
        log.error("detect failed to start", extra={"detail": str(exc)})
        return 1
