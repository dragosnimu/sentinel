"""Parse sshd log messages into canonical events.

Only the security-relevant lines are kept: authentication successes and
failures, and invalid-user attempts. A brute-force run against SSH is the single
most common thing this box will see, and these three shapes are what reveal it —
who, from where, and whether they got in.

The message text after the source is attacker-influenced (an attacker chooses
the username), so `username` is stored verbatim and never trusted.

## Why every pattern is anchored and greedy on the username

sshd logs the peer's address by substituting the (attacker-chosen) username
into a fixed format string and appending its OWN "from <ip> port <port>" after
it — so everything AFTER that substitution is sshd's, never the attacker's.
Before this anchoring, `_FAILED`/`_ACCEPTED` ran `.search()` over the WHOLE
message with an unanchored, non-greedy username, so a username crafted to
CONTAIN a fake "Failed password for root from <ip> port <n> ssh2" was matched
as if that fake text were the real line, and the genuine "from <ip> port <n>"
sshd appended at the true end was ignored:

    Invalid user x Failed password for root from 203.0.113.9 port 22 ssh2 from <real> port …

used to parse as `auth_fail` from `203.0.113.9` — chosen entirely by the
attacker — while the real peer was invisible. `ssh_bruteforce` then groups by
`src_ip` and the decider can auto-block the forged, innocent third party while
hiding the real attacker completely.

The fix is two-part: (1) every pattern is anchored to the START of the message
(after the optional `sshd[pid]:`/`sshd-session[pid]:` prefix a forwarded copy
of the journal can carry, which the direct journald reader does not add), so a
message has to genuinely BE a Failed/Accepted/Invalid-user line, not merely
CONTAIN one; (2) the username capture is a greedy `.*` rather than one or more
non-whitespace characters, so when a forged username contains its own "from ip
port n" text, backtracking
still finds the LAST such occurrence in the message — the one sshd itself
appended — because greedy matching only gives back as little as it must.

A username containing whitespace or a control character cannot be a real POSIX
account name; it is text an attacker chose to look like something else. Such
events are kept (dropping them silently would hide the attack), but `username`
is replaced with `<invalid>` and `raw["suspicious_username"]` is set, so a
forged line never displays as a normal login attempt in an incident summary or
a Telegram alert. The original text survives in `raw["raw_username"]` for
forensics — verbatim, capped, never interpolated anywhere.
"""

from __future__ import annotations

import re
from datetime import datetime

from sentinel.model.event import Event

# A relayed/forwarded copy of the journal (classic syslog, a shipped mirror)
# can carry the unit's syslog identifier and pid back in front of the message
# text; the journald reader used here does not add it (MESSAGE is already bare
# program text), but nothing stops a forwarded pipeline from doing so. Consumed
# here, optionally, so it can never become part of what the anchor is checked
# against.
_PREFIX = r"^(?:sshd(?:-session)?\[\d+\]:\s*)?"

# Username capture is deliberately `.*` (greedy, DOTALL), not `\S+`: see the
# module docstring for why the LAST "from <ip> port <n>" in the message — the
# one greedy backtracking converges on — is always the one sshd appended
# itself, never attacker-chosen text.
#
# "Failed password for root from 203.0.113.4 port 51234 ssh2"
# "Failed password for invalid user admin from 203.0.113.4 port 51234 ssh2"
_FAILED = re.compile(
    _PREFIX + r"Failed (?P<method>password|publickey) for "
    r"(?:invalid user )?(?P<user>.*) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)",
    re.DOTALL,
)
# "Accepted password for user from 203.0.113.4 port 51234 ssh2"
_ACCEPTED = re.compile(
    _PREFIX + r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>.*) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)",
    re.DOTALL,
)
# "Invalid user admin from 203.0.113.4 port 51234"
_INVALID = re.compile(
    _PREFIX + r"Invalid user (?P<user>.*) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)",
    re.DOTALL,
)

# Whitespace (space, tab, CR, LF, ...) or a C0/DEL control character. A real
# POSIX username never contains either, so finding one means the "username" is
# attacker-chosen text shaped to look like a different log line.
_SUSPICIOUS_USER = re.compile(r"[\s\x00-\x1f\x7f]")

_RAW_USERNAME_CAP = 512


def _sanitize_username(user: str) -> tuple[str, bool]:
    """Returns (username_to_store, suspicious). See module docstring."""
    if _SUSPICIOUS_USER.search(user):
        return "<invalid>", True
    return user, False


def _raw_username_field(user: str, suspicious: bool) -> dict[str, str]:
    if not suspicious:
        return {}
    return {"raw_username": user[:_RAW_USERNAME_CAP]}


def parse_sshd(message: str, ts: datetime) -> Event | None:
    """One sshd journal message -> Event, or None if it is not security-relevant.

    `ts` comes from journald (the authoritative receive time), not from the
    message — the message carries no reliable timestamp of its own.
    """
    m = _FAILED.search(message)
    if m:
        user, suspicious = _sanitize_username(m["user"])
        return Event(
            ts=ts, source="sshd", action="auth_fail",
            src_ip=m["ip"], src_port=int(m["port"]), username=user,
            process="sshd", proto="ssh",
            raw={"auth_method": m["method"], "invalid_user": "invalid user" in message,
                 "suspicious_username": suspicious,
                 **_raw_username_field(m["user"], suspicious)},
        )

    m = _ACCEPTED.search(message)
    if m:
        user, suspicious = _sanitize_username(m["user"])
        return Event(
            ts=ts, source="sshd", action="auth_ok",
            src_ip=m["ip"], src_port=int(m["port"]), username=user,
            process="sshd", proto="ssh",
            raw={"auth_method": m["method"], "suspicious_username": suspicious,
                 **_raw_username_field(m["user"], suspicious)},
        )

    m = _INVALID.search(message)
    if m:
        user, suspicious = _sanitize_username(m["user"])
        return Event(
            ts=ts, source="sshd", action="auth_fail",
            src_ip=m["ip"], src_port=int(m["port"]), username=user,
            process="sshd", proto="ssh",
            raw={"invalid_user": True, "suspicious_username": suspicious,
                 **_raw_username_field(m["user"], suspicious)},
        )

    return None
