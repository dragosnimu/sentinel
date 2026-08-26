"""Thin systemd entrypoints.

Each module here exposes `main(argv) -> int` and is invoked by `sentinel <name>`
via the CLI dispatcher, which hands over the arguments it did not consume
itself. Keeping them thin means the daemon lifecycle lives in one place and the
logic stays testable without starting a process.

`argv` is a list, never `None`, when the dispatcher calls: `None` means "read
sys.argv", which is only correct when a module is executed directly.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

# EX_USAGE from sysexits.h. Distinct from argparse's own 2 and from the 78
# (EX_CONFIG) the dispatcher returns for a service that does not exist, so the
# installer and the operator can tell "you typed a flag I do not have" from
# "this build has no such service" and from "the service ran and failed".
EX_USAGE = 64


def parse_service_args(parser: argparse.ArgumentParser,
                       argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse a service's own flags, refusing anything the service does not define.

    Every service here used `parse_known_args()` and threw the unknown half
    away. On a daemon that is the most destructive possible reading of a typo:
    an unrecognised flag becomes "no flags at all", which becomes "start the
    daemon". `sentinel telegram --send-test` — a flag that existed only in the
    installer and in a comment — therefore started a SECOND long-poller against
    the token `sentinel-telegram.service` was already using, and hung the
    installer until the operator's session died. Telegram answers one of two
    pollers with 409 Conflict; nothing else says a word.

    Unknown is not fine. It exits, it says which flag, and it starts nothing.
    """
    args, unknown = parser.parse_known_args(argv)
    if unknown:
        parser.print_usage(sys.stderr)
        print(f"{parser.prog}: unrecognised argument(s): {' '.join(unknown)}",
              file=sys.stderr)
        print("Refusing to run: an unknown flag is not permission to fall "
              "through to the default action.", file=sys.stderr)
        raise SystemExit(EX_USAGE)
    return args
