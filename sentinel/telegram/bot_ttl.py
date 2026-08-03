"""TTL parsing for /block, importable without python-telegram-bot.

Kept out of bot.py's PTB-dependent module so it can be unit-tested on a machine
that has no telegram library. bot.py imports parse_ttl from here.
"""
from __future__ import annotations


def parse_ttl(text: str | None) -> int | None:
    """'1h' / '30m' / '3600' -> seconds. None -> a 24h default, not permanent.

    The permanent check comes FIRST: 'perm' ends in 'm', so a naive minutes
    branch would swallow it and fall back to the default instead of returning
    None (permanent).
    """
    if not text:
        return 86400
    text = text.strip().lower()
    if text in ("perm", "permanent", "0"):
        return None
    try:
        if text.endswith("h"):
            return int(float(text[:-1]) * 3600)
        if text.endswith("m"):
            return int(float(text[:-1]) * 60)
        return int(text)
    except ValueError:
        return 86400
