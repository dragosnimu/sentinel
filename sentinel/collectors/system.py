"""Parse system-security journal messages: sudo, su, and session activity.

SSH tells you who knocked; these tell you what happened after someone got in.
Privilege escalation is the step between "an account is compromised" and "the
host is compromised", so a failed sudo, a su to root, or a burst of either is
worth an event even though none of it is remarkable on its own.

Usernames, TTYs and command strings are attacker-influenced once an account is
taken over — stored verbatim, never trusted, never interpolated into a command.
"""

from __future__ import annotations

import re
from datetime import datetime

from sentinel.model.event import Event

# "deploy : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash"
# TTY is matched separately because it is OPTIONAL — non-interactive sudo (cron,
# `sudo -n`, a deploy script) omits it, and folding it into one pattern either
# drops those lines or lets the leading wildcard swallow the TTY value itself.
_SUDO_CMD = re.compile(
    r"(?P<user>[\w.\-]+) : .*?PWD=(?P<pwd>\S*) ; "
    r"USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.+)$"
)
_SUDO_TTY = re.compile(r"\bTTY=(?P<tty>\S+)")
# "user : 3 incorrect password attempts ; TTY=pts/0 ; ..."
_SUDO_FAIL_COUNT = re.compile(
    r"(?P<user>[\w.\-]+) : (?P<n>\d+) incorrect password attempt")
# "pam_unix(sudo:auth): authentication failure; ... ruser=x rhost= user=y"
_PAM_FAIL = re.compile(
    r"pam_unix\((?P<svc>sudo|su|sshd):auth\): authentication failure;.*?"
    r"(?:ruser=(?P<ruser>\S*))?.*?user=(?P<user>\S+)")
# "session opened for user root(uid=0) by deploy(uid=1000)"
_SU_OPEN = re.compile(
    r"pam_unix\(su(?:-l)?:session\): session opened for user (?P<target>[\w.\-]+)"
    r"(?:\(uid=\d+\))? by (?P<user>[\w.\-]*)")
# "FAILED SU (to root) baduser on pts/0"
_SU_FAIL = re.compile(r"FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)")


def parse_system(message: str, ts: datetime, comm: str) -> Event | None:
    """One journal message from sudo/su -> Event, or None if not relevant.

    `comm` is the originating process (_COMM) so a pam_unix line can be
    attributed to the right service — the text alone is ambiguous.
    """
    if comm == "sudo":
        m = _SUDO_FAIL_COUNT.search(message)
        if m:
            return Event(
                ts=ts, source="sudo", action="auth_fail",
                username=m["user"], process="sudo",
                raw={"reason": "incorrect_password", "attempts": int(m["n"])},
            )
        m = _SUDO_CMD.search(message)
        if m:
            tty = _SUDO_TTY.search(message)
            return Event(
                ts=ts, source="sudo", action="privilege_use",
                username=m["user"], process="sudo",
                # Truncated: a command line can be arbitrarily long and is
                # attacker-controlled once an account is taken over.
                raw={"target_user": m["target"],
                     "tty": tty["tty"] if tty else "none",
                     "pwd": m["pwd"][:200], "command": m["cmd"][:500]},
            )

    if comm in ("su", "su-l"):
        m = _SU_FAIL.search(message)
        if m:
            return Event(
                ts=ts, source="su", action="auth_fail",
                username=m["user"], process="su",
                raw={"target_user": m["target"], "tty": m["tty"]},
            )
        m = _SU_OPEN.search(message)
        if m:
            return Event(
                ts=ts, source="su", action="privilege_use",
                username=m["user"] or "?", process="su",
                raw={"target_user": m["target"]},
            )

    m = _PAM_FAIL.search(message)
    if m and comm in ("sudo", "su", "su-l"):
        return Event(
            ts=ts, source=m["svc"], action="auth_fail",
            username=m["user"], process=comm,
            raw={"reason": "pam_auth_failure"},
        )

    return None
