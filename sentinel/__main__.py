"""CLI dispatcher.

The systemd units invoke subcommands of this. Keeping one entry point means one
place that sets up logging, loads config, and reports a clean startup failure
instead of a traceback in `journalctl`.

    sentinel ingest | detect | ai | telegram | web | scan | health | maintenance
             | restoredrill | patchwindow
    sentinel selfcheck [--print]
    sentinel reconcile [--reapply]
    sentinel telegram --send-test [--message TEXT]
    sentinel migrate [--dry-run]
    sentinel config-check
    sentinel version

Flags after the subcommand belong to the service and are handed to it. They are
NOT discarded: a flag nobody parses used to mean "start the daemon", which is
how `sentinel telegram --send-test` started a second bot poller on a host that
was already running one. See `services.parse_service_args`.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from typing import Any

from sentinel import __version__
from sentinel.errors import ConfigError, SentinelError
from sentinel.logging_setup import setup_logging

SERVICES = ("ingest", "detect", "ai", "telegram", "web", "scan", "health",
            "maintenance", "selfcheck", "reconcile", "beacon", "ship",
            "restoredrill", "patchwindow")


def _run_service(name: str, args: argparse.Namespace,
                 extra: Sequence[str]) -> int:
    # Imported lazily so that `sentinel config-check` and `sentinel version` work
    # on a machine where the runtime dependencies of one daemon are missing.
    import importlib

    try:
        module = importlib.import_module(f"sentinel.services.{name}_service")
    except ImportError as exc:
        # Logging is set up here rather than before the import so a missing
        # service produces one clean line instead of a "starting" followed by a
        # failure.
        log = setup_logging(f"sentinel-{name}", args.log_level)
        log.error(
            "service not implemented yet in this build",
            extra={"service": name, "detail": str(exc)},
        )
        return 78  # EX_CONFIG

    # The service's own main() decides whether it is starting a daemon or
    # running a one-shot admin command, and sets up logging accordingly — a
    # `--create-admin` invocation should not emit a "service starting" line.
    #
    # It is handed the leftovers explicitly rather than re-reading sys.argv:
    # every service that did read sys.argv had to guess where its own flags
    # started, and `sentinel --log-level DEBUG web --list-users` is the
    # invocation that guess gets wrong.
    entry: Callable[[Sequence[str]], int] = module.main
    return entry(list(extra))


async def _read_max_connections(cfg: Any) -> int | None:
    """The server's own `max_connections`, or `None` if it cannot be read —
    which must not read as "no limit"; the caller says so explicitly."""
    from sentinel.db.engine import Database

    db = Database(cfg)
    try:
        await db.connect()
        value = await db.fetchval("SHOW max_connections")
        return int(value) if value is not None else None
    except Exception:  # noqa: BLE001 - config-check must not crash over this
        return None
    finally:
        await db.close()


# S8 (round 2): `len(SERVICES)` — 14 entries — was never a count of what
# actually holds a pool open continuously. It counted `restoredrill` and
# `patchwindow` (a monthly and a periodic job, not a resident daemon) and
# `scan`, `health`, `maintenance`, `selfcheck`, `reconcile` (systemd-timer
# oneshots that connect, do one pass, and exit) right alongside the seven
# processes that actually sit there holding a pool 24/7. The old docstring
# even SAID restoredrill/patchwindow ran "briefly, not continuously" while
# the code counted them anyway — the number (`14 × pool_max`) was never
# believable on inspection, which is its own failure: a warning line an
# operator cannot mentally check is a warning line they stop reading.
#
# These seven are the ones actually worth multiplying: each is started once
# by systemd and stays up, holding its own pool, for the life of the host.
_PERSISTENT_POOL_SERVICES = ("ingest", "detect", "ai", "web", "beacon", "ship", "telegram")


def _connection_budget_line(cfg: Any) -> str:
    """S8: `pool_max` reads as sane in isolation while the PRODUCT across
    every daemon that opens a pool is what actually competes for the
    server's `max_connections` — confirmed on both production hosts, where
    the server allows 40. `_PERSISTENT_POOL_SERVICES` counts only the
    processes that hold a pool open continuously (the executor and watchdog
    do not use asyncpg at all and are excluded by construction); the timer
    oneshots (`health` every 30s, `selfcheck` every 5min, and the rest of
    `SERVICES` not in this list) each add a SHORT, non-overlapping spike on
    top of the number below, not a standing consumer — worth knowing about
    but not worth inflating the headline number past what an operator can
    sanity-check by eye.

    On the shipped defaults (`database.pool_min=2`/`pool_max=10`,
    `max_connections=40`) this still warns — 7 × 10 = 70 > 40 — which is
    correct: those defaults really do not fit the server's own default limit
    without the operator either raising `max_connections` or lowering
    `pool_max`, and this line exists so that gets noticed at `config-check`
    time, not the first time a timer oneshot cannot get a connection.

    Reads the server's real limit if it is reachable; says plainly that it
    could not if not, rather than silently skipping the check — "could not
    tell" and "fine" must not look the same here either.
    """
    import asyncio

    n = len(_PERSISTENT_POOL_SERVICES)
    budget = n * cfg.database.pool_max
    oneshots = [s for s in SERVICES if s not in _PERSISTENT_POOL_SERVICES]
    note = (f" (plus {len(oneshots)} sarcini pe temporizator — health la 30s, "
            f"selfcheck la 5min ș.a. — care se conectează pe scurt, nu permanent)")
    try:
        limit = asyncio.run(_read_max_connections(cfg))
    except Exception:  # noqa: BLE001 - never let this be why config-check crashes
        limit = None

    if limit is None:
        return (f"conexiuni:  plafon teoretic {budget} ({n} servicii permanente "
                f"× database.pool_max={cfg.database.pool_max}){note}; "
                f"max_connections al serverului nu a putut fi citit — verifică "
                f"manual că serverul îl acceptă")
    if budget > limit:
        return (f"conexiuni:  ATENȚIE — plafonul teoretic {budget} "
                f"({n} servicii permanente × database.pool_max="
                f"{cfg.database.pool_max}) depășește max_connections="
                f"{limit} al serverului PostgreSQL{note}")
    return f"conexiuni:  plafon teoretic {budget}, sub max_connections={limit}{note}"


def _config_check(args: argparse.Namespace) -> int:
    from sentinel.config import get_config, get_secrets

    try:
        cfg = get_config()
    except ConfigError as exc:
        print(f"configuration invalid: {exc}", file=sys.stderr)
        return 1

    secrets = get_secrets()
    required = ["SENTINEL_DB_PASSWORD"]
    if cfg.telegram.enabled:
        required += ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CALLBACK_HMAC_KEY"]
    if cfg.ai.enabled:
        required += ["ANTHROPIC_API_KEY"]
    # Without the shared key the beacon cannot sign, so it says so once and
    # exits 0 — a clean exit that looks identical to "not configured". Naming
    # the missing secret here is the difference between a five-second fix and
    # an evening spent wondering why the watcher never hears anything.
    if cfg.beacon.enabled:
        required += ["SENTINEL_BEACON_SECRET"]
    # Same reasoning as the beacon, and its own key: a shared secret would let
    # root on host A forge host A's rows into host B's history. Without it the
    # shipper exits 0, which is indistinguishable from "not configured" unless
    # something names the missing key.
    if cfg.ship.enabled:
        required += ["SENTINEL_SHIP_SECRET"]
    missing = [k for k in required if not secrets.has(k)]

    print(f"config:   OK  ({cfg.hostname or 'hostname unset'}, tz={cfg.timezone})")
    print(f"secrets:  {'OK' if not missing else 'MISSING: ' + ', '.join(missing)}")
    print(f"auto_block: {'ENABLED' if cfg.response.auto_block.enabled else 'disabled (observe mode)'}")
    print(f"suricata:   {'enabled' if cfg.suricata.enabled else 'disabled (log-only mode)'}")
    print(f"ai:         {'enabled' if cfg.ai.enabled else 'disabled'}")
    print(f"telegram:   {len(cfg.telegram.allowed_chat_ids)} allowed chat id(s)")

    if args.verbose:
        print(f"\nweb:      https://{cfg.web.domain or '<no domain>'} → {cfg.web.bind}:{cfg.web.port}")
        print(f"database: {cfg.database.user}@{cfg.database.host}:{cfg.database.port}/{cfg.database.name}")
        print(_connection_budget_line(cfg))
        if cfg.web.ip_allowlist:
            print(f"web ip allowlist: {', '.join(cfg.web.ip_allowlist)}")
        else:
            print("web ip allowlist: empty — the dashboard accepts any source that "
                  "reaches nginx. Filling this in is the cheapest hardening available.")

    return 1 if missing else 0


def _migrate(args: argparse.Namespace) -> int:
    setup_logging("sentinel-migrate", args.log_level)
    from sentinel.db.migrate import run_migrations

    return run_migrations(dry_run=args.dry_run)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel", description=__doc__)
    parser.add_argument("--log-level", default=None, choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sub = parser.add_subparsers(dest="command", required=True)

    for name in SERVICES:
        # Service subcommands accept their own flags — `sentinel web
        # --create-admin`, `sentinel telegram --send-test`. The service module
        # parses them itself, so this level only needs to stop argparse
        # rejecting them before they get there. It stops there: what this level
        # does not recognise, the service must, or the service refuses.
        sub.add_parser(
            name,
            help=f"run the {name} service",
            add_help=False,
        )

    migrate = sub.add_parser("migrate", help="apply database migrations")
    migrate.add_argument("--dry-run", action="store_true", help="show what would be applied")

    check = sub.add_parser("config-check", help="validate configuration and secrets")
    check.add_argument("-v", "--verbose", action="store_true")

    sub.add_parser("version", help="print the version and exit")
    return parser


def main() -> int:
    # parse_known_args, not parse_args: a service's own flags are its business,
    # and this dispatcher should not need updating every time one gains an option.
    #
    # `extra` is that business, and it is PASSED ON. It used to be assigned to a
    # throwaway and dropped, which meant this dispatcher answered "I do not know
    # what that flag is" by running the subcommand's default action anyway.
    args, extra = build_parser().parse_known_args()

    # The subcommands handled below define their own flags here, so a leftover
    # is a flag nobody will act on — and the action they would fall through to
    # is not harmless: `sentinel migrate --dry-runn` would apply migrations for
    # real while its operator watched for a preview.
    if extra and args.command not in SERVICES:
        print(f"sentinel {args.command}: unrecognised argument(s): "
              f"{' '.join(extra)}", file=sys.stderr)
        return 64  # EX_USAGE

    try:
        if args.command == "version":
            print(__version__)
            return 0
        if args.command == "config-check":
            return _config_check(args)
        if args.command == "migrate":
            return _migrate(args)
        if args.command in SERVICES:
            return _run_service(args.command, args, extra)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 78
    except SentinelError as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130

    print(f"unknown command: {args.command}", file=sys.stderr)
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
