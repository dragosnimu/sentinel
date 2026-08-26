"""`sentinel telegram` — the Telegram bot daemon (long polling), and the test send.

Long polling, not a webhook: there is no inbound port to expose or spoof, and it
keeps working even if nginx or TLS is broken — which is exactly when the operator
most needs the out-of-band channel. The bot is read-only in this phase.

`--send-test` sends ONE message to every allowed chat and exits. It exists for
the last step of the installer, where receiving that message is the end-to-end
proof — config loaded, secrets readable, egress works, token valid, chat id
right — and a green install log proves much less.

It is a real flag now. It used to be a flag nobody had defined: the dispatcher
dropped what it did not recognise, so `sentinel telegram --send-test --message …`
parsed as plain `sentinel telegram` and started a second long-poller against the
token the live unit was already using. Telegram answers one of two pollers with
409 Conflict, and the installer hung on that command until the operator's
session died. Two rules follow from that, and both are load-bearing here:

  * the flags are parsed strictly (`parse_service_args`), so an unknown one
    refuses instead of falling through to polling;
  * the one-shot path RETURNS. It never touches `build_application`, so there is
    no code path on which a test send can become a poller.

Exit codes, because the installer reads them and has to tell three states apart:

    0   every allowed chat got a message_id back from Telegram
    78  telegram is disabled or not configured — nothing was sent, nothing is
        wrong (EX_CONFIG)
    1   the send was attempted and at least one chat did not get it; the reason
        is printed per chat
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence

from sentinel import __version__
from sentinel.config import Config, Secrets, get_config, get_secrets
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.services import parse_service_args

log = get_logger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel telegram", add_help=False)
    parser.add_argument("--send-test", action="store_true",
                        help="send one message to every allowed chat, then exit")
    parser.add_argument("--message", default=None,
                        help="text to send with --send-test")
    return parser


def _send_test(cfg: Config, sec: Secrets, message: str | None) -> int:
    """Send once, report per chat, exit. Never starts anything."""
    from sentinel.telegram.direct import send_to_chats

    token = sec.get("TELEGRAM_BOT_TOKEN")
    # Not "no news is good news": each of these is a distinct reason nothing was
    # sent, and each is printed, because the caller is a human watching an
    # install scroll past.
    if not cfg.telegram.enabled:
        print("telegram is disabled in config; no test message sent")
        return 78
    if not token:
        print("telegram is enabled but TELEGRAM_BOT_TOKEN is missing")
        return 78
    if not cfg.telegram.allowed_chat_ids:
        print("telegram is enabled but allowed_chat_ids is empty; "
              "there is nobody to send to")
        return 78

    text = message or (
        f"Sentinel {__version__}: test de canal. Dacă vezi acest mesaj, "
        "alertele ajung la tine.")
    outcomes = asyncio.run(send_to_chats(token, cfg.telegram.allowed_chat_ids, text))

    for outcome in outcomes:
        print(outcome.describe())
    failed = [o for o in outcomes if not o.ok]
    if failed:
        print(f"{len(failed)} of {len(outcomes)} chat(s) did not receive it")
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_service_args(_build_parser(), argv)

    # Refused rather than ignored. `--message` alone would otherwise be a flag
    # that changes nothing and lets the process fall through to long polling —
    # the exact shape of the bug this file was rewritten for.
    if args.message is not None and not args.send_test:
        print("--message is only meaningful with --send-test")
        return 64  # EX_USAGE

    if args.send_test:
        # No setup_logging: this is a one-shot command whose output the operator
        # is reading, not a daemon whose lines go to journald. Same reasoning as
        # `sentinel web --create-admin`.
        return _send_test(get_config(), get_secrets(), args.message)

    setup_logging("sentinel-telegram")

    cfg = get_config()
    sec = get_secrets()

    if not cfg.telegram.enabled:
        log.info("telegram is disabled in config; nothing to run")
        return 0
    if not sec.get("TELEGRAM_BOT_TOKEN"):
        log.error("telegram enabled but TELEGRAM_BOT_TOKEN is missing")
        return 78
    if not cfg.telegram.allowed_chat_ids:
        log.error("telegram enabled but allowed_chat_ids is empty; refusing to run")
        return 78

    from sentinel.telegram.bot import build_application

    app = build_application(cfg, sec)
    log.info("starting telegram long-polling")
    # run_polling owns the event loop and installs its own signal handlers; it
    # calls post_init (connect DB, start push loop) and post_shutdown (cleanup).
    #
    # allowed_updates MUST include callback_query, or Telegram never delivers a
    # single inline-button tap: block/unblock confirmations, /panic, the blocklist
    # flush, and the one-tap block button on an incident alert would all silently
    # do nothing. "message" alone was exactly that bug. Kept as an explicit list
    # (not Update.ALL_TYPES) so we consciously opt into every update class the
    # handlers actually authorise and process.
    app.run_polling(
        allowed_updates=["message", "callback_query"],
        drop_pending_updates=True,
    )
    return 0
