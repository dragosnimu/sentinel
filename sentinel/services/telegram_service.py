"""`sentinel telegram` — the Telegram bot daemon (long polling).

Long polling, not a webhook: there is no inbound port to expose or spoof, and it
keeps working even if nginx or TLS is broken — which is exactly when the operator
most needs the out-of-band channel. The bot is read-only in this phase.
"""

from __future__ import annotations

import argparse

from sentinel.config import get_config, get_secrets
from sentinel.logging_setup import get_logger, setup_logging

log = get_logger(__name__)


def main() -> int:
    argparse.ArgumentParser(prog="sentinel telegram", add_help=False).parse_known_args()
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
