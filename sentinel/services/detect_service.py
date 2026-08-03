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

from sentinel.config import Config, get_config
from sentinel.db.engine import Database
from sentinel.detect import engine
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.predict import baseline

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


def main() -> int:
    argparse.ArgumentParser(prog="sentinel detect", add_help=False).parse_known_args()
    setup_logging("sentinel-detect")
    try:
        return asyncio.run(_main())
    except Exception as exc:  # noqa: BLE001
        log.error("detect failed to start", extra={"detail": str(exc)})
        return 1
