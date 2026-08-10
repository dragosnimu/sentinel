"""`sentinel selfcheck` — one pass of the self-check.

One-shot, driven by a timer, for the same reason the scan is: a hung check is
reaped by systemd rather than left running, and there is no long-lived process
that can itself get stuck in the way the thing it is watching did.

Exit codes are meant for `systemctl status` and for a human running it by hand:

    0  everything the check can see is working
    1  something is degraded
    2  something is down
    3  the self-check itself could not run
"""

from __future__ import annotations

import argparse
import asyncio

from sentinel.config import get_config
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.selfcheck import run_all
from sentinel.selfcheck.runner import run_and_alert

log = get_logger(__name__)

_EXIT = {"ok": 0, "unknown": 0, "degraded": 1, "down": 2}


async def _main(quiet: bool, print_all: bool) -> int:
    cfg = get_config()
    db = Database(cfg)
    await db.connect()
    try:
        if print_all:
            results = await run_all(db, cfg)
            for r in sorted(results, key=lambda x: (x.status != "down", x.status != "degraded", x.key)):
                mark = {"ok": "  ok", "degraded": "WARN", "down": "DOWN",
                        "unknown": "  ??"}[r.status]
                print(f"[{mark}] {r.key:28} {r.title}")
                if r.detail:
                    print(f"         {r.detail}")
                if r.action and r.status != "ok":
                    print(f"         → {r.action}")
            from sentinel.selfcheck.checks import worst
            return _EXIT.get(worst(results), 3)

        summary = await run_and_alert(db, cfg, quiet=quiet)
        # WARNING rather than INFO when something is wrong, so the operator's
        # `journalctl -p warning` shows it without knowing to look for it.
        #
        # `incomplete` counts as wrong. A run where a check group raised finds
        # no faults BECAUSE it did not look, and `worst()` ranks `unknown` above
        # `degraded`, so the exit code is 0. Logging that as "selfcheck clean"
        # put the one word the operator greps for on the one run that proved
        # nothing — the fact was in `extra`, contradicted by the message.
        if summary["bad"] or summary["incomplete"]:
            log.warning("selfcheck found problems", extra=summary)
        else:
            log.info("selfcheck clean", extra=summary)
        return _EXIT.get(summary["worst"], 3)
    finally:
        await db.close()


def main() -> int:
    parser = argparse.ArgumentParser(prog="sentinel selfcheck", add_help=False)
    parser.add_argument("--quiet", action="store_true",
                        help="run and record, but send nothing")
    parser.add_argument("--print", dest="print_all", action="store_true",
                        help="print every check and exit; sends nothing")
    parser.add_argument("--log-level", default="INFO")
    args, _ = parser.parse_known_args()
    setup_logging("sentinel-selfcheck", args.log_level)
    try:
        return asyncio.run(_main(args.quiet, args.print_all))
    except Exception as exc:  # noqa: BLE001
        log.error("selfcheck failed to run", extra={"detail": str(exc)})
        return 3
