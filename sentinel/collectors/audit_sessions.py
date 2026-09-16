"""Which audit login sessions still exist on this host, read from /proc.

## The question this answers

A row in `login_sessions` is opened by a `USER_LOGIN` audit record and closed
by a `USER_LOGOUT` one. The second is the record the kernel usually does not
write. Measured on the Ubuntu host on 15 September 2026, in its own database:
**all 17 closed sessions carry `closed_inferred = true`** — every one of them
was closed by the twelve-hour sweeper, not one by a logout anybody saw. The
operator's "🔓 Sesiune încheiată" therefore arrived exactly 12h00m after the
last command, every single time (`summarised_at - closed_at`: 12:00:04,
12:00:09, 12:00:08, 12:00:02, 12:00:01, 12:00:06).

`USER_END` is not the answer and is not on the table: it is the pair of
`USER_START`, PAM emits one per layer (`sudo`, `su`, each auth module), and
the day it sat in `_KEEP` it produced a phantom close one second after login,
1534 orphaned commands out of 14157, and a ghost row per extra close. See
`collectors/auditd.py:_KEEP` and migration `0027_session_close.sql`.

So the end of a session stops being inferred from a record that is usually
absent, and becomes an observation: the audit session id either still has a
process on this host, or it does not.

## Why /proc, and not `loginctl`

Both were read on both hosts on 15 September 2026, minutes apart:

  * Ubuntu host — `loginctl list-sessions`: 2472, 2475, 2484, 2512, 2624.
    `/proc/[0-9]*/sessionid`: those, **plus 2473**, which belongs to that
    user's lingering `systemd --user` and `(sd-pam)` pair;
  * AlmaLinux host — `loginctl`: 42. `/proc`: 42 and 43.

They disagree, and the direction of the disagreement decides it. A session
`/proc` still shows and logind does not is a session with live processes.
Closing it here puts "Sesiune încheiată" on the operator's phone in the next
half-minute about something still running. Of the two readers, the one that
errs towards "still alive" is the one a reaper may be built on.

What leaving it open costs, written in full rather than rounded to zero: after
twelve hours without a command, `close_stale_sessions` closes that same row —
and the summary it produces is the identical "🔓 Sesiune încheiată" about a
session `/proc` still shows alive, just half a day later. That sweeper has no
liveness check, and it cannot grow one where it stands: it runs in
`services/detect_service.py`, the daemon whose `ProtectProc=invisible` sandbox
is measured below to see nothing but its own ten processes. So the residual is
not "a late summary" but "a wrong summary, late" — smaller than sending it
immediately and wrong, and strictly no worse than the behaviour before this
file existed, which is why the trade stands. It is not nothing.

Second reason: logind's session id equals the audit session id only because
logind adopts the audit id when the kernel has audit enabled. `login_sessions`
is keyed on the AUDIT id, which is what this file reads directly — no coupling
between two numbering schemes that has to keep holding.

What /proc costs, said plainly: any process that outlives the login it was
started from keeps that login's session id alive — the `systemd --user` pair
above, a detached `tmux`, a `nohup`. A row with such a key is never reaped
here and waits for the twelve-hour sweeper, which is the same answer as
before this file existed. The trade is deliberate: the reader that is late is
survivable, the reader that is wrong is not.

## Why "I cannot tell" is a state of its own

`sentinel-detect.service` sets `ProtectProc=invisible`. Measured inside that
unit's own mount namespace, as the `sentinel` user it actually runs as
(`nsenter -t <MainPID> -m --setuid <uid sentinel>`):

    cat /proc/1/sessionid          ->  No such file or directory
    ls /proc | grep -c '^[0-9]'    ->  10        (its own processes, nothing else)
    /proc mount options            ->  rw,...,hidepid=invisible

A scan there returns an EMPTY set of live sessions — which, read as fact,
says "every session on this host is over" and closes all of them. That is not
a hypothetical: it is what this module would return today if the detection
daemon called it.

So the scan carries a positive control: `/proc/1/sessionid` must be readable.
PID 1 belongs to root, so under `hidepid=invisible` an unprivileged reader
cannot see it; and on a kernel built without audit support the file does not
exist at all. One probe, both cases. When it fails, the result is
`trusted = False` with an empty set, and `reap_dead_sessions` refuses to touch
a row.

The same measurement on `sentinel-ingest.service`, which sets no
`ProtectProc` — the daemon this runs in: `/proc/1/sessionid` reads back
`4294967295`, 187 process directories visible, the same count the host itself
reports. On the AlmaLinux host, 201.

## Blind in one spot is still blind

The control above catches TOTAL blindness. Partial blindness — `/proc/1` still
answering while one other process refuses — is a different failure and has a
different observable: a process that exited between the listing and the read
has no directory left, so the open fails with `ENOENT`; a process that is
there but whose `sessionid` a security module refuses gives `EACCES`. The
kernel distinguishes them, so this module does too, because folding them
together answers "that session is not alive" about a session that is.

`PermissionError` therefore does not count as a miss: it makes the whole scan
`trusted = False`, exactly like the total case, and `reap_dead_sessions`
touches nothing. No threshold and no judgement about how much blindness is
tolerable — one refused read is enough, because it only takes one to hide the
one session that matters.

This is about the design, not about today's hosts. Measured on 15 September
2026: on the AlmaLinux host `getenforce` and `sestatus` both say SELinux is
disabled and there is no AppArmor (`aa-status`: command not found); on the
Ubuntu host AppArmor is enabled (`aa-status --enabled` exits 0) and the running
`sentinel ingest` processes read `unconfined` from their own
`/proc/<pid>/attr/current`. Neither host can produce an `EACCES` here right
now. A confinement profile added later, by anyone, would — and it would arrive
silently.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from sentinel.db.repo.logins import NO_SESSION

#: Where the kernel publishes its process table. A parameter only so the tests
#: can build a /proc that is missing the pieces this module has to survive.
PROC_ROOT = "/proc"

#: `^[0-9]+$`, deliberately not `\d` and not `str.isdigit()`.
#:
#: Both of those accept Unicode digits in Python — `'٣'.isdigit()` is True and
#: `int('٣')` is 3 — while `session_key` in the database is whatever auditd
#: wrote, plain ASCII. The same rule is written out for the same reason in
#: `db/repo/logins.py:REAL_TTY_SQL`. Nothing in /proc can be named in Arabic
#: digits today; the point is that a value which is not a plain decimal is not
#: a session id, and is skipped instead of being reinterpreted.
_DECIMAL = re.compile(r"^[0-9]+$")


@dataclass(frozen=True)
class LiveAuditSessions:
    """The audit session ids that still have at least one process on this host.

    `trusted` is the reason this is a type and not a set. An empty set means
    two completely different things — "nobody is logged in" and "I was not
    allowed to look" — and a reaper handed the second one as though it were
    the first closes every open session on the host and summarises each one.
    """

    #: Session ids seen alive, normalised the way `ses=` is stored.
    keys: frozenset[str]
    #: True only when the positive control passed, i.e. this process can read
    #: the /proc entry of a process it does not own.
    trusted: bool
    #: Why not, in words that name the cause. Empty when trusted.
    detail: str
    #: How many process entries were read. Reported, not asserted on: a host
    #: with very few processes is unusual, not wrong.
    scanned: int = 0
    #: How many process directories were listed and then were GONE (`ENOENT`)
    #: when their `sessionid` was opened. Processes that exited mid-scan, which
    #: is normal and harmless — a gone process is not evidence about a session.
    #: Counted rather than ignored so that "nothing was reaped" can be read
    #: against how much of the host was actually there to read. Measured on both
    #: hosts on 15 September 2026: the sandboxed daemon saw the same process
    #: count as the host itself, 187 and 201.
    unreadable: int = 0
    #: How many reads were REFUSED (`EACCES`) — the directory was there and the
    #: kernel said no. Never normal: it means the scan is partially blind, and a
    #: partially blind scan can drop exactly the session that is alive. Any
    #: value above zero forces `trusted = False`; the field exists so the
    #: journal can say how many, and so the two causes of "could not read" can
    #: never be added up into one meaningless number again.
    denied: int = 0


def read_live_sessions(proc_root: str | Path = PROC_ROOT) -> LiveAuditSessions:
    """Scan /proc once and report which audit sessions are still alive.

    Never raises: every failure becomes `trusted = False` with a reason, so a
    caller cannot mistake "the scan broke" for "nothing is running".
    """
    root = Path(proc_root)

    # The positive control, before anything else. PID 1 is root's and always
    # exists, so an unprivileged reader that cannot see it cannot see any other
    # user's processes either — see this module's docstring for the measurement
    # under ProtectProc=invisible.
    try:
        pid1 = _read_sessionid(root / "1")
    except PermissionError as exc:
        # The directory is there and the read was refused. Kept apart from the
        # branch below only so the reason in the journal names the right cause;
        # the answer is the same "I cannot tell".
        return LiveAuditSessions(
            frozenset(), False,
            f"{root}/1/sessionid exists but the read was refused ({exc}): a "
            f"security module is confining this process", 0)
    if pid1 is None:
        return LiveAuditSessions(
            frozenset(), False,
            f"{root}/1/sessionid is unreadable: this process cannot see "
            f"processes it does not own (ProtectProc=invisible / hidepid), or "
            f"the kernel has no audit support", 0)

    try:
        entries = sorted(root.iterdir())
    except OSError as exc:
        return LiveAuditSessions(frozenset(), False, f"cannot list {root}: {exc}", 0)

    keys: set[str] = set()
    scanned = 0
    unreadable = 0
    denied = 0
    for entry in entries:
        if not _DECIMAL.match(entry.name):
            continue
        try:
            value = _read_sessionid(entry)
        except PermissionError:
            # EACCES, not ENOENT: this process is STILL THERE and its session
            # id was withheld. Its session may be alive and this scan cannot
            # see it, which is the definition of a partially blind read — see
            # the module docstring. The scan carries on so the count is right,
            # but the verdict below is already decided.
            denied += 1
            continue
        if value is None:
            # A process that exited between the listing and the read. A gone
            # process is not evidence that a session ended — another process of
            # the same session may still be there, and if none is, this scan
            # simply will not list it. Counted, not ignored: see
            # `LiveAuditSessions.unreadable`.
            unreadable += 1
            continue
        scanned += 1
        if value not in NO_SESSION:
            keys.add(value)
    if denied:
        # The keys are still returned: they were read, they are true. What is
        # false is the ABSENCE of any other key, which is the only thing a
        # reaper acts on — hence `trusted = False`, one refusal being enough.
        #
        # The reason carries no count and no pid on purpose: the caller only
        # speaks when the reason CHANGES, and a reason that carries a number
        # which moves every pass would put a warning in the journal every
        # thirty seconds for as long as the confinement lasts. On these hosts
        # the journal lives in RAM (2.79 days of it), so a line every half
        # minute is not free. How many is in `denied`, which the caller logs.
        return LiveAuditSessions(
            frozenset(keys), False,
            "a process entry refused the read (EACCES): a security module is "
            "confining this process, and the set of live sessions is "
            "incomplete", scanned, unreadable, denied)
    return LiveAuditSessions(frozenset(keys), True, "", scanned, unreadable)


def _read_sessionid(proc_pid: Path) -> str | None:
    """The audit session id of one process, or None when the process is gone.

    None means "no information from this process, and none is owed": it exited
    (`ENOENT`), or it wrote something that is not a session id. Neither is
    evidence about a session, so the caller skips it.

    A REFUSED read is not that, and is not returned — it is raised. `EACCES`
    says the process is still there and its session id was withheld, which
    makes the whole scan incomplete in a way no count of misses can express.
    Collapsing the two into one answer is how a live session becomes a dead
    one. The caller turns it into `trusted = False`.
    """
    try:
        raw = (proc_pid / "sessionid").read_text(encoding="ascii", errors="strict")
    except PermissionError:
        raise
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    raw = raw.strip()
    if not _DECIMAL.match(raw):
        return None
    try:
        # Normalised through int so the two spellings of one session cannot miss
        # each other: the database key comes from auditd's `ses=2604`, this one
        # from a kernel file that writes the same number — but a comparison of
        # strings is what decides whether a session is alive, and `02604` would
        # not match.
        return str(int(raw))
    except ValueError:
        # `int()` refuses a decimal string longer than `sys.get_int_max_str_digits()`
        # (4300 by default, CPython ≥ 3.10.7). The kernel writes a u32, so a real
        # /proc cannot reach it — but this function's docstring promises it never
        # raises, and that promise is what lets the caller treat "cannot read" as
        # a state instead of an outage. A ValueError escaping here leaves
        # `maybe_reap_sessions` in `run()`'s error branch every pass: no session
        # is ever closed again, and the only sign is one log line a minute.
        return None
