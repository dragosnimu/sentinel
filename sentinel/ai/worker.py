"""The AI worker loop: triage serious incidents as they arrive, within budget.

Polls for open incidents at or above `triage_min_severity` that have no verdict
yet, and triages a few per pass. The budget is checked before every single call,
so once the cap is hit the loop keeps running but places no calls — detection is
unaffected, the deterministic verdicts simply stand un-narrated until tomorrow.
If the API key is absent or ai is disabled, the loop idles quietly rather than
restart-looping under systemd.
"""

from __future__ import annotations

import asyncio
import contextlib

from sentinel.ai import budget, triage
from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import incidents as inc_repo
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

INTERVAL_S = 30
MAX_PER_PASS = 5


async def _pass(db: Database, cfg: Config, api_key: str) -> None:
    ok, reason = await budget.allowed(db, cfg)
    if not ok:
        log.info("ai budget: skipping pass", extra={"reason": reason})
        return
    incidents = await inc_repo.untriaged(
        db, min_severity=cfg.ai.triage_min_severity, limit=MAX_PER_PASS)
    for inc in incidents:
        ok, reason = await budget.allowed(db, cfg)
        if not ok:
            log.warning("ai budget: stopping mid-pass", extra={"reason": reason})
            break
        await triage.triage_incident(db, cfg, api_key, inc.id)


async def run(db: Database, cfg: Config, api_key: str | None, stop: asyncio.Event) -> None:
    if not api_key:
        log.warning("ANTHROPIC_API_KEY absent — AI layer idle (detection unaffected)")
    while not stop.is_set():
        try:
            if cfg.ai.enabled and api_key:
                await _pass(db, cfg, api_key)
        except Exception as exc:  # noqa: BLE001 - a bad pass must not kill the daemon
            log.error("ai pass failed", extra={"detail": str(exc)})
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=INTERVAL_S)
