"""Quiet hours — mostly tests about what still gets through.

An alerting channel that wakes you for a port scan gets muted permanently, and a
permanently muted channel is worse than none: it looks like coverage. So this
feature exists to keep the channel usable. Every test below that matters is
about the boundary between "quiet" and "silent", because only one of those is
acceptable in a security tool.
"""
from __future__ import annotations

from datetime import datetime, time, timedelta, timezone

import pytest

from sentinel.telegram import quiet

UTC = timezone.utc
BUCHAREST = "Europe/Bucharest"      # UTC+3 in August


# --- parsing ----------------------------------------------------------------
@pytest.mark.parametrize("text,start,end", [
    ("22:00-06:00", time(22, 0), time(6, 0)),
    ("22:00 - 06:00", time(22, 0), time(6, 0)),
    ("9:30-17:00", time(9, 30), time(17, 0)),
    ("00:00-23:59", time(0, 0), time(23, 59)),
])
def test_windows_parse(text, start, end):
    w = quiet.parse_window(text)
    assert w and w.start == start and w.end == end


@pytest.mark.parametrize("text", [
    "", "22:00", "25:00-06:00", "22:60-06:00", "22-6", "noapte",
    "22:00-06:00; DROP TABLE", "-06:00",
])
def test_nonsense_windows_are_rejected(text):
    assert quiet.parse_window(text) is None


def test_a_window_that_starts_when_it_ends_is_empty_not_eternal():
    """"22:00-22:00" is almost certainly a typo. Reading it as 24 hours of
    silence is the worst available interpretation of an ambiguous input."""
    w = quiet.parse_window("22:00-22:00")
    assert w is not None
    assert not w.contains(time(23, 0))
    assert not w.contains(time(10, 0))


@pytest.mark.parametrize("text,expected", [
    ("2h", timedelta(hours=2)),
    ("30m", timedelta(minutes=30)),
    ("45 minute", timedelta(minutes=45)),
    ("3 ore", timedelta(hours=3)),
    ("1d", timedelta(hours=24)),
])
def test_durations_parse(text, expected):
    assert quiet.parse_duration(text) == expected


def test_a_long_mute_is_capped_not_refused():
    """The intent of "/mute 7d" is perfectly clear. Honouring it literally would
    leave a security channel dark for a week."""
    assert quiet.parse_duration("7d") == quiet.MAX_ADHOC == timedelta(hours=24)


@pytest.mark.parametrize("text", ["", "0h", "abc", "-2h", "2 weeks"])
def test_nonsense_durations_are_rejected(text):
    assert quiet.parse_duration(text) is None


# --- the window that crosses midnight ---------------------------------------
NIGHT = quiet.Window(time(22, 0), time(6, 0))


@pytest.mark.parametrize("moment,inside", [
    (time(21, 59), False),
    (time(22, 0), True),      # inclusive at the start
    (time(23, 30), True),
    (time(0, 0), True),       # over midnight
    (time(3, 0), True),
    (time(5, 59), True),
    (time(6, 0), False),      # exclusive at the end
    (time(12, 0), False),
])
def test_overnight_window_membership(moment, inside):
    assert NIGHT.contains(moment) is inside


def test_daytime_window_does_not_wrap():
    day = quiet.Window(time(9, 0), time(17, 0))
    assert day.contains(time(12, 0))
    assert not day.contains(time(3, 0))
    assert not day.crosses_midnight


# --- local time, not UTC ----------------------------------------------------
def test_the_window_is_read_in_local_time():
    """The host runs UTC and Bucharest is UTC+3 in August. 20:00 UTC is 23:00
    locally — inside a 22:00-06:00 window. Getting this wrong silences three
    hours the operator wanted covered and leaves three they wanted quiet."""
    at_2000_utc = datetime(2026, 8, 4, 20, 0, tzinfo=UTC)
    assert quiet.evaluate(now=at_2000_utc, window=NIGHT, muted_until=None,
                          tz_name=BUCHAREST).muted
    # The same instant read as UTC would be 20:00 — outside the window.
    assert not quiet.evaluate(now=at_2000_utc, window=NIGHT, muted_until=None,
                              tz_name="UTC").muted


def test_the_host_zone_is_resolved_by_name_where_possible(monkeypatch, tmp_path):
    """`datetime.now().astimezone()` yields a FIXED offset — "+03:00", not
    "Europe/Bucharest". A fixed offset has no DST rules, so on the one night a
    year the clocks change, the end of the window is computed an hour wrong."""
    from pathlib import Path

    real_read = Path.read_text
    # Compared as a Path, not a string: on Windows `Path("/etc/timezone")`
    # stringifies with backslashes and the comparison silently never matches.
    etc_timezone = Path("/etc/timezone")

    def fake_read(self, *a, **kw):
        if self == etc_timezone:
            return "Europe/Bucharest\n"
        return real_read(self, *a, **kw)

    monkeypatch.setattr("pathlib.Path.read_text", fake_read)
    assert quiet.host_zone_name() == "Europe/Bucharest"
    # And a zone resolved by name knows about DST, unlike a fixed offset.
    from zoneinfo import ZoneInfo
    assert isinstance(quiet.zone(None), ZoneInfo)


def test_dst_does_not_shift_the_end_of_the_window():
    """Romania leaves EEST at 04:00 on the last Sunday of October. A window
    ending at 06:00 must still end at 06:00 local, not 05:00 or 07:00."""
    night_of_change = datetime(2026, 10, 24, 23, 0, tzinfo=UTC)  # 02:00 EEST
    state = quiet.evaluate(now=night_of_change, window=NIGHT, muted_until=None,
                           tz_name=BUCHAREST)
    assert state.muted
    local_end = state.until.astimezone(quiet.zone(BUCHAREST))
    assert (local_end.hour, local_end.minute) == (6, 0)


def test_a_named_zone_actually_resolves():
    """Guard the guard: without a tzdb, `zone()` falls back to the host and
    every timezone test above silently stops testing anything."""
    assert str(quiet.zone(BUCHAREST)) == BUCHAREST


def test_an_unknown_timezone_falls_back_loudly(caplog):
    """Silently defaulting to UTC would shift the window by hours without
    anyone knowing which hours are actually covered."""
    import logging

    with caplog.at_level(logging.ERROR):
        quiet.zone("Mars/Olympus_Mons")
    assert any("unknown timezone" in r.message for r in caplog.records)


def test_window_end_is_an_absolute_instant_in_the_future():
    now = datetime(2026, 8, 4, 23, 30, tzinfo=UTC)
    state = quiet.evaluate(now=now, window=NIGHT, muted_until=None, tz_name=BUCHAREST)
    assert state.muted and state.until is not None
    assert state.until > now
    assert state.until - now < timedelta(hours=24)


# --- ad-hoc mutes -----------------------------------------------------------
def test_an_expired_adhoc_mute_stops_muting():
    now = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
    past = now - timedelta(minutes=1)
    assert not quiet.evaluate(now=now, window=None, muted_until=past).muted


def test_an_active_adhoc_mute_wins_outside_any_window():
    now = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
    future = now + timedelta(hours=1)
    state = quiet.evaluate(now=now, window=NIGHT, muted_until=future, tz_name=BUCHAREST)
    assert state.muted and state.until == future


def test_no_mute_at_all_is_the_default():
    assert not quiet.evaluate(now=datetime(2026, 8, 4, 12, 0, tzinfo=UTC),
                              window=None, muted_until=None).muted


# --- what is never muted ----------------------------------------------------
def test_critical_always_passes():
    assert quiet.passes_anyway("critical")
    assert quiet.passes_anyway("CRITICAL")


@pytest.mark.parametrize("sev", ["info", "low", "medium", "high", None, ""])
def test_everything_below_critical_can_be_held(sev):
    assert not quiet.passes_anyway(sev)


@pytest.mark.parametrize("kind", [
    "panic", "watchdog", "patch_failed", "patch_rolled_back", "lockout",
])
def test_the_safety_net_firing_is_never_silenced(kind):
    """These say your own protections fired, or that the host changed and then
    changed back. None of it keeps until morning."""
    assert quiet.passes_anyway("low", kind)
    assert quiet.passes_anyway(None, kind)


def test_the_never_muted_list_lives_in_code_not_config():
    """"Which alerts can be silenced" is a safety property. A config file is the
    wrong place to let someone silence the last one."""
    import inspect

    src = inspect.getsource(quiet)
    assert "NEVER_MUTED_SEVERITIES = frozenset" in src
    cfg = (__import__("pathlib").Path(__file__).resolve().parents[2]
           / "deploy" / "config" / "sentinel.yaml.tmpl").read_text(encoding="utf-8")
    assert "never_muted" not in cfg.lower()


# --- the push loop ----------------------------------------------------------
def test_quiet_hours_hold_alerts_rather_than_dropping_them():
    """`notified_at` stays NULL, so the batch goes out when the window lifts.
    Dropping would turn a convenience into a way to miss things."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot._push_incidents)
    held = src.split("all_quiet", 1)[1].split("threshold", 1)[0]
    assert "mark_notified" not in held, "an alert is marked sent while nobody was told"
    assert "return" in held


def test_a_backlog_arrives_as_one_message():
    """Waking up to sixty notifications is functionally the same as waking up
    to none."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    assert bot.DIGEST_FLOOR >= 5
    assert "_push_incident_digest" in inspect.getsource(bot._push_incidents)


def test_a_broken_preferences_query_alerts_anyway():
    """Failing open is the only safe direction: a database error must not
    silence a security channel."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot._push_loop)
    handler = src.split("except Exception", 1)[1].split("for name, fn", 1)[0]
    assert "quiet_chats = set()" in handler


def test_the_window_is_resolved_once_per_cycle():
    """Three sources must agree on whether it is quiet, and a slow cycle must
    not straddle the end of the window and send half a batch under the old
    answer."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot._push_loop)
    assert src.count("_quiet_chats(") == 1
    assert "await fn(app, cfg, db, quiet_chats)" in src


def test_patch_failures_are_flagged_as_unmutable():
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot._push_executions)
    assert "patch_rolled_back" in src and "patch_failed" in src
    assert "kind=kind" in src


# --- the command ------------------------------------------------------------
def test_mute_is_registered_with_an_unmute_escape_hatch():
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot.build_application)
    assert 'CommandHandler("mute"' in src
    assert 'CommandHandler("unmute"' in src


def test_unmute_clears_both_mechanisms():
    """An operator who says "stop muting" and still gets silence from the other
    mechanism has been handed a control that lies."""
    import inspect

    from sentinel.db.repo import chats
    src = inspect.getsource(chats.clear_all_mutes)
    assert "quiet_hours = NULL" in src and "muted_until = NULL" in src


def test_a_viewer_cannot_mute_anything():
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot.cmd_mute)
    assert "_can_act(cfg, chat_id)" in src
    assert src.index("_can_act") < src.index("context.args")


def test_mute_is_per_chat_not_global():
    """A shared setting would let one operator silence another's phone."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot.cmd_mute)
    assert "chat_id = update.effective_chat.id" in src
    assert "set_quiet_hours(db, chat_id" in src


def test_the_migration_does_not_silence_anyone():
    """A migration that quietly muted an existing installation overnight would
    be a security change nobody asked for."""
    from pathlib import Path

    sql = (Path(__file__).resolve().parents[2] / "sentinel" / "db" / "migrations"
           / "0015_quiet_hours.sql").read_text(encoding="utf-8")
    assert "UPDATE telegram_chats" not in sql
    assert "DEFAULT '22:00" not in sql
