"""Quiet hours: when the bot stops buzzing, and what buzzes anyway.

An alerting channel that wakes you at 3 a.m. for a port scan is one you will
mute permanently within a week, and a permanently muted channel is worse than no
channel — it looks like coverage and provides none. So this exists to keep the
channel usable, not to make it quieter.

Two mechanisms, deliberately separate:

  * **A recurring window** — "22:00-06:00", the normal case. Set once, applies
    every night.
  * **An ad-hoc mute until a moment** — "/mute 2h", for a maintenance window or
    a deliberately noisy test. Expires on its own; there is no way to mute
    indefinitely, because a mute you have to remember to undo is one you will
    not undo.

## What is never muted

Silence has to be safe. These pass regardless of any window, any ad-hoc mute,
and any configuration:

  * anything at `critical` severity;
  * the watchdog and PANIC — the messages that say your own safety net fired;
  * a patch that failed or rolled back, because something on the host changed
    and then changed back, and that is not information that keeps until morning.

Everything else is *held*, not dropped: the rows keep `notified_at IS NULL` and
go out when the window ends. Losing an alert to a quiet window would make this
feature a way to miss things.

## Time is local

An operator who types "22:00" means 22:00 where they live. The host runs UTC and
the database stores UTC, so the window is evaluated in a named zone — the host's
own by default, overridable in config. Getting this wrong by three hours would
silence exactly the evening hours the operator wanted covered.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sentinel.logging_setup import get_logger

log = get_logger(__name__)

# Severities that ignore every mute. Kept as a frozenset in code rather than in
# config: "which alerts can be silenced" is a safety property, and a
# configuration file is the wrong place to let someone silence the last one.
NEVER_MUTED_SEVERITIES = frozenset({"critical"})

# Notification kinds that ignore every mute, whatever their severity.
NEVER_MUTED_KINDS = frozenset({
    "panic",             # the blocklist was flushed — by you or by the watchdog
    "watchdog",          # the safety net fired
    "patch_failed",      # a patch stopped partway
    "patch_rolled_back",  # the host changed and then changed back
    "lockout",           # you may be locked out right now
})

_WINDOW_RE = re.compile(r"^\s*([0-2]?\d):([0-5]\d)\s*-\s*([0-2]?\d):([0-5]\d)\s*$")
_DURATION_RE = re.compile(r"^\s*(\d{1,4})\s*(m|min|minute|h|o|ora|ore|d|zi|zile)\s*$", re.I)

MAX_ADHOC = timedelta(hours=24)


@dataclass(frozen=True)
class Window:
    """A recurring daily window, in local time. May cross midnight."""

    start: time
    end: time

    def __str__(self) -> str:
        return f"{self.start:%H:%M}-{self.end:%H:%M}"

    @property
    def crosses_midnight(self) -> bool:
        return self.start > self.end

    def contains(self, moment: time) -> bool:
        if self.start == self.end:
            # An empty window, not a 24-hour one. "22:00-22:00" almost certainly
            # means a typo, and reading it as "always silent" would be the worst
            # possible interpretation of an ambiguous input.
            return False
        if self.crosses_midnight:
            return moment >= self.start or moment < self.end
        return self.start <= moment < self.end


def parse_window(text: str) -> Window | None:
    """"22:00-06:00" → Window, or None if it is not one."""
    m = _WINDOW_RE.match(text or "")
    if not m:
        return None
    sh, sm, eh, em = (int(g) for g in m.groups())
    if sh > 23 or eh > 23:
        return None
    return Window(time(sh, sm), time(eh, em))


def parse_duration(text: str) -> timedelta | None:
    """"2h", "30m", "45 minute" → timedelta, capped at 24 hours."""
    m = _DURATION_RE.match(text or "")
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2).lower()
    if unit.startswith(("m",)):
        delta = timedelta(minutes=n)
    elif unit.startswith(("h", "o")):
        delta = timedelta(hours=n)
    else:
        delta = timedelta(days=n)
    if delta <= timedelta(0):
        return None
    # Capped rather than rejected: the intent of "/mute 7d" is clear, and
    # honouring it literally would leave a security channel dark for a week.
    return min(delta, MAX_ADHOC)


def host_zone_name() -> str | None:
    """The host's IANA zone name, or None if it cannot be determined.

    Worth the effort over `datetime.now().astimezone()`, which yields a FIXED
    offset captured at that instant — "+03:00", not "Europe/Bucharest". A fixed
    offset has no DST rules, so on the night the clocks change, the end of a
    22:00-06:00 window is computed an hour wrong. Once a year, in the dark,
    is exactly when nobody is watching.

    Both supported families are covered: Debian writes the name to
    /etc/timezone, RHEL symlinks /etc/localtime into the zoneinfo tree.
    """
    from pathlib import Path

    try:
        text = Path("/etc/timezone").read_text(encoding="utf-8").strip()
        if text:
            return text
    except OSError:
        pass
    try:
        target = Path("/etc/localtime").resolve()
        parts = target.parts
        if "zoneinfo" in parts:
            return "/".join(parts[parts.index("zoneinfo") + 1:]) or None
    except OSError:
        pass
    return None


def zone(name: str | None) -> ZoneInfo | timezone:
    """The zone the window is read in. Falls back loudly, never silently to UTC.

    A three-hour error here silences the wrong three hours — the evening the
    operator wanted covered stays loud and the morning goes quiet.
    """
    for candidate, explicit in ((name, True), (host_zone_name(), False)):
        if not candidate:
            continue
        try:
            return ZoneInfo(candidate)
        except (ZoneInfoNotFoundError, ValueError):
            if explicit:
                log.error("unknown timezone, falling back to host local",
                          extra={"timezone": candidate})
    # Last resort: a fixed offset from the running process. Correct right now,
    # and wrong for one night per year at the DST boundary.
    local = datetime.now().astimezone().tzinfo
    return local if local is not None else timezone.utc


@dataclass(frozen=True)
class MuteState:
    """Why a message is or is not being held, in words fit for a chat reply."""

    muted: bool
    reason: str
    until: datetime | None = None


def evaluate(*, now: datetime, window: Window | None, muted_until: datetime | None,
             tz_name: str | None = None) -> MuteState:
    """Is the channel quiet right now, and until when?"""
    tz = zone(tz_name)
    local = now.astimezone(tz)

    if muted_until is not None and muted_until > now:
        return MuteState(True, "pauză temporară", muted_until)

    if window is not None and window.contains(local.time()):
        return MuteState(True, f"ore de liniște ({window})", _window_end(local, window, tz))

    return MuteState(False, "activ")


def _window_end(local: datetime, window: Window, tz: ZoneInfo | timezone) -> datetime:
    """The next moment this window stops, as an absolute instant.

    Built by replacing the time on a local date and re-attaching the zone rather
    than by adding a duration: on the night a DST change lands inside the
    window, the arithmetic answer is off by an hour and the calendar answer is
    right.
    """
    end_today = local.replace(hour=window.end.hour, minute=window.end.minute,
                              second=0, microsecond=0)
    if end_today <= local:
        end_today += timedelta(days=1)
    return end_today.astimezone(timezone.utc)


def passes_anyway(severity: str | None, kind: str | None = None) -> bool:
    """True when this message must be delivered even inside a quiet window."""
    if kind and kind in NEVER_MUTED_KINDS:
        return True
    return bool(severity) and severity.lower() in NEVER_MUTED_SEVERITIES
