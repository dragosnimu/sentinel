"""Parse sshd log messages into canonical events.

Only the security-relevant lines are kept: authentication successes and
failures, and invalid-user attempts. A brute-force run against SSH is the single
most common thing this box will see, and these three shapes are what reveal it —
who, from where, and whether they got in.

The message text after the source is attacker-influenced (an attacker chooses
the username), so `username` is stored verbatim and never trusted.
"""

from __future__ import annotations

import re
from datetime import datetime

from sentinel.model.event import Event

# "Failed password for root from 203.0.113.4 port 51234 ssh2"
# "Failed password for invalid user admin from 203.0.113.4 port 51234 ssh2"
_FAILED = re.compile(
    r"Failed (?P<method>password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
# "Accepted password for user from 203.0.113.4 port 51234 ssh2"
_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
# "Invalid user admin from 203.0.113.4 port 51234"
_INVALID = re.compile(
    r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)


def parse_sshd(message: str, ts: datetime) -> Event | None:
    """One sshd journal message -> Event, or None if it is not security-relevant.

    `ts` comes from journald (the authoritative receive time), not from the
    message — the message carries no reliable timestamp of its own.
    """
    m = _FAILED.search(message)
    if m:
        return Event(
            ts=ts, source="sshd", action="auth_fail",
            src_ip=m["ip"], src_port=int(m["port"]), username=m["user"],
            process="sshd", proto="ssh",
            raw={"auth_method": m["method"], "invalid_user": "invalid user" in message},
        )

    m = _ACCEPTED.search(message)
    if m:
        return Event(
            ts=ts, source="sshd", action="auth_ok",
            src_ip=m["ip"], src_port=int(m["port"]), username=m["user"],
            process="sshd", proto="ssh",
            raw={"auth_method": m["method"]},
        )

    m = _INVALID.search(message)
    if m:
        return Event(
            ts=ts, source="sshd", action="auth_fail",
            src_ip=m["ip"], src_port=int(m["port"]), username=m["user"],
            process="sshd", proto="ssh",
            raw={"invalid_user": True},
        )

    return None
