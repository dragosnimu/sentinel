"""CLI dispatcher.

The systemd units invoke subcommands of this. Keeping one entry point means one
place that sets up logging, loads config, and reports a clean startup failure
instead of a traceback in `journalctl`.

    sentinel ingest | detect | ai | telegram | web | scan | health | maintenance
    sentinel migrate [--dry-run]
    sentinel config-check
    sentinel version
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable

from sentinel import __version__
from sentinel.errors import ConfigError, SentinelError
from sentinel.logging_setup import setup_logging

SERVICES = ("ingest", "detect", "ai", "telegram", "web", "scan", "health", "maintenance")


def _run_service(name: str, args: argparse.Namespace) -> int:
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
    entry: Callable[[], int] = module.main
    return entry()


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
        # rejecting them before they get there.
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
    args, _extra = build_parser().parse_known_args()

    try:
        if args.command == "version":
            print(__version__)
            return 0
        if args.command == "config-check":
            return _config_check(args)
        if args.command == "migrate":
            return _migrate(args)
        if args.command in SERVICES:
            return _run_service(args.command, args)
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
