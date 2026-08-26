"""`sentinel ai` — the AI worker daemon.

Long-running (systemd Type=exec, Restart=always). It triages serious incidents
with the model, bounded by the token budget. It is deliberately non-critical: if
it dies, detection, response and scanning all continue untouched — the only loss
is the Romanian narrative and the recalibrated severity on new incidents.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
from collections.abc import Sequence

from sentinel.ai import worker
from sentinel.config import get_config, get_secrets
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.services import parse_service_args

log = get_logger(__name__)


async def _main() -> int:
    cfg = get_config()
    db = Database(cfg)
    await db.connect()

    api_key = None
    try:
        api_key = get_secrets().require("ANTHROPIC_API_KEY")
    except Exception:  # noqa: BLE001 - absent key is degraded, not fatal
        api_key = None

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    log.info("ai daemon started", extra={"enabled": cfg.ai.enabled, "has_key": bool(api_key)})
    try:
        await worker.run(db, cfg, api_key, stop)
    finally:
        await db.close()
    log.info("ai daemon stopped")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel ai", add_help=False)
    parser.add_argument("--log-level", default="INFO")
    args = parse_service_args(parser, argv)
    setup_logging("sentinel-ai", args.log_level)
    try:
        return asyncio.run(_main())
    except Exception as exc:  # noqa: BLE001
        log.error("ai failed to start", extra={"detail": str(exc)})
        return 1
