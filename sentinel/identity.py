"""Which installation this is — one random value per Sentinel host.

An external aggregator receives from N servers. Without a stable per-install
identifier the rows of two hosts are indistinguishable, and the failure is
silent in both directions: two servers reporting the same id merge into one
history, one server reporting two ids forks into two. Neither raises an error
anywhere; the numbers simply stop meaning what they say.

## Why a random value and not something the host already has

* **Not the hostname.** It changes — a rename, a migration, a hosting panel that
  recreates the VPS — and a changed identity is a forked history. It is also
  free reconnaissance on a shared panel: it tells whoever reads it what the
  operator's machines are called.
* **Not `/etc/machine-id`.** A cloned VM inherits it. Duplicate identity is
  exactly the failure a random value avoids, and it is the one that produces no
  fault report at all.

## The file is the authority

`/etc/sentinel/instance_id`, mode 0640 root:sentinel, written once by
`step_secrets` in `deploy/install.sh` and never regenerated. The
`instance_identity` row in the database is a mirror of it, and a disagreement
between the two is the symptom of a backup restored onto a clone —
`check_instance_identity` in `sentinel/selfcheck/checks.py` is what reports it.

## Why reading raises instead of returning ""

An empty string flowing into a report is not an absent identity, it is a
plausible one: it groups every host that failed to read its file into a single
shared bucket on the aggregator, which is the duplicate-identity failure arrived
at from the other side. So there is no fallback value. A caller that can carry
on without an id catches `IdentityError` and says which of its work it is not
doing.

There is deliberately **no environment override** for the path. `sentinel.config`
has `SENTINEL_CONFIG`/`SENTINEL_SECRETS` because an operator legitimately runs
against another config; nobody legitimately runs as another instance, and a knob
that renames a server into another one's history is not worth the convenience.
Tests pass the path explicitly.
"""

from __future__ import annotations

import re
from pathlib import Path

from sentinel.constants import CONFIG_DIR
from sentinel.errors import SentinelError

INSTANCE_ID_PATH = Path(f"{CONFIG_DIR}/instance_id")

# Exactly what `openssl rand -hex 16` produces, and nothing else.
#
# The installer is the only writer, so any other shape is a truncated write, a
# hand-edit, or a different file altogether — none of which may be handed back
# as an identity. The same grammar is enforced twice more, in
# `0022_instance_identity.sql` and in `ensure_instance_id` in install.sh, and
# `tests/security/test_instance_id_is_stable.py` puts one corpus of candidate
# byte strings through all three and demands the same verdict from each. One
# grammar written in three languages with nothing tying them together is how
# 0020 shipped a parser the database refused.
#
# Matched with `fullmatch`, not `match`, and that is not a style choice.
# PostgreSQL's `$` means END OF STRING; Python's `$` also matches just before a
# trailing newline, so `re.match` on "…\n" would accept a value the database's
# CHECK rejects. `fullmatch` requires the pattern to consume the whole string,
# which is exactly PostgreSQL's semantics — and it keeps the pattern text
# byte-identical to the one in the SQL file.
_INSTANCE_ID_RE = re.compile(r"^[0-9a-f]{32}$")

# The six characters bash's `[[:space:]]` recognises in the C locale, and no
# others.
#
# A bare `str.strip()` also strips NBSP, U+2028, and the C1 controls. `install.sh`
# does not, so a file padded with NBSP was read as an identity here and refused
# there: the installer nags about a file that works, forever, and the operator
# has no way to tell which of the two is wrong. The file is written by
# `openssl rand -hex 16 >`, so the only whitespace that can legitimately
# surround it is ASCII.
#
# `\r` is in the set for completeness and is UNREACHABLE as things stand — said
# plainly rather than left as an implied claim. `Path.read_text()` opens in
# text mode with `newline=None`, so universal-newline translation turns every
# CRLF and every lone CR into `\n` before `strip` ever sees the value. It stays
# in the set because it costs nothing and becomes load-bearing the moment
# anyone reads these bytes without that translation — `read_bytes().decode()`,
# or a caller in another language. The installer's side of the same input IS
# exercised: bash's `cat` does see the CR and has to trim it, which is what the
# `crlf` and `lone-cr` candidates in tests/security/test_instance_id_is_stable.py
# actually test.
_ASCII_WS = " \t\n\r\v\f"


class IdentityError(SentinelError):
    """The instance identity could not be read. Never silently substituted."""


def read_instance_id(path: Path | None = None) -> str:
    """The instance id from disk, or `IdentityError` saying what was wrong.

    The path is resolved at call time rather than bound as a default argument,
    so a test can repoint `INSTANCE_ID_PATH` and actually exercise this reader
    instead of a stand-in for it.
    """
    target = Path(path) if path is not None else INSTANCE_ID_PATH
    try:
        raw = target.read_text(encoding="utf-8")
    except FileNotFoundError:
        # The command is the one that is true TODAY, and that matters more than
        # it looks. Until E1.4 the identity was written inside step 27, so this
        # message said `--force-step 27`; the call is now unconditional in
        # `install.sh`, so any deploy creates the file, and step 27 additionally
        # rewrites secrets.env from stdin. Leaving the old advice would have
        # worked by accident while costing a rewrite nobody asked for — and it
        # would have contradicted docs/OPERARE.md §12, which says a plain deploy
        # is enough. Two readers of one file disagreeing is the failure this
        # module spends a page arguing against; a tool disagreeing with its own
        # manual is the same failure with a longer feedback loop.
        raise IdentityError(
            f"{target} does not exist. It is written once, by the installer, and "
            f"never regenerated; a host that does not have it gets it from any "
            f"deploy: ./scripts/deploy.sh --host <host> --user <user>"
        ) from None
    except (OSError, UnicodeDecodeError) as exc:
        # Permission denied belongs here and is worth naming: the file is
        # 0640 root:sentinel, so a daemon that is not in group `sentinel`, or a
        # hand-run as another user, reads nothing. That is "I could not look",
        # not "there is no identity".
        raise IdentityError(f"{target} could not be read: {exc}") from None

    value = raw.strip(_ASCII_WS)
    if not value:
        raise IdentityError(
            f"{target} is empty — no identity has ever been written to it")
    if not _INSTANCE_ID_RE.fullmatch(value):
        # The content is not echoed. A file of the wrong shape is a file whose
        # contents nobody has vouched for, and this message reaches the operator
        # through Telegram; the length is the diagnostic that matters (a
        # truncated write is short, a pasted secret is not 32 characters).
        raise IdentityError(
            f"{target} does not hold an instance id: expected 32 lowercase hex "
            f"characters (openssl rand -hex 16), found {len(value)} character(s) "
            f"of another shape. The content is deliberately not printed."
        )
    return value
