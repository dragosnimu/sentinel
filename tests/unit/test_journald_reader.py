"""The journald reader, and the silence it has to notice about itself.

A collector that stops collecting looks exactly like a quiet night. This one did
that in production for 21 hours: the service stayed `active`, restarted zero
times, logged nothing, and the other three collectors in the same poll loop
stayed current — while SSH authentication went unwatched.

`systemd` is not installed on a development machine, so the real Reader is
replaced here by a fake. That is not a weakness of these tests: the bug was in
when the wrapper decides to throw its reader away, and that decision is the
thing being tested.
"""
from __future__ import annotations

import sys
import types
from datetime import datetime, timezone

import pytest

NOW = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)


class FakeReader:
    """Stands in for systemd.journal.Reader.

    `entries` is what the next iteration will yield. Setting it to [] models the
    failure: a reader that has stopped producing while the journal keeps filling.
    """

    def __init__(self):
        self.entries: list[dict] = []
        self.matches: list[tuple] = []
        self.disjunctions = 0
        self.sought: list[str] = []
        self.closed = False
        self.tailed = 0

    def add_match(self, **kw):
        self.matches.append(tuple(kw.items()))

    def add_disjunction(self):
        self.disjunctions += 1

    def seek_cursor(self, cursor):
        self.sought.append(cursor)

    def seek_tail(self):
        self.tailed += 1

    def get_next(self):
        return {}

    def get_previous(self):
        return {}

    def process(self):
        return None

    def close(self):
        self.closed = True

    def __iter__(self):
        out, self.entries = self.entries, []
        return iter(out)


@pytest.fixture
def reader_cls(monkeypatch):
    """Install a fake `systemd.journal` and hand back the list of built readers."""
    built: list[FakeReader] = []

    def _Reader():
        r = FakeReader()
        built.append(r)
        return r

    fake = types.ModuleType("systemd")
    fake.journal = types.ModuleType("systemd.journal")
    fake.journal.Reader = _Reader
    monkeypatch.setitem(sys.modules, "systemd", fake)
    monkeypatch.setitem(sys.modules, "systemd.journal", fake.journal)
    return built


def _entry(cursor: str, message: str = "Failed password for root", comm: str = "sshd-session"):
    return {"MESSAGE": message, "__REALTIME_TIMESTAMP": NOW,
            "__CURSOR": cursor, "_COMM": comm}


def _make(reader_cls):
    from sentinel.collectors.journald_reader import JournaldReader
    return JournaldReader([{"_COMM": "sshd-session"}, {"_COMM": "sudo"}])


# --- matching ---------------------------------------------------------------
def test_match_groups_are_or_ed(reader_cls):
    _make(reader_cls)
    r = reader_cls[0]
    assert r.matches == [(("_COMM", "sshd-session"),), (("_COMM", "sudo"),)]
    assert r.disjunctions == 1      # between the groups, not before the first


# --- the stuck reader -------------------------------------------------------
def test_a_stuck_reader_is_rebuilt(reader_cls):
    """The whole reason this file exists. Enough empty polls in a row and the
    reader is thrown away, because a reader that has stopped producing never
    starts again on its own."""
    from sentinel.collectors.journald_reader import REBUILD_AFTER_EMPTY_POLLS

    jr = _make(reader_cls)
    reader_cls[0].entries = [_entry("cursor-1")]
    assert len(jr.read_new()) == 1          # gives it a cursor to resume from

    for _ in range(REBUILD_AFTER_EMPTY_POLLS):
        assert jr.read_new() == []
    assert len(reader_cls) == 1, "rebuilt too early"

    jr.read_new()                            # this poll trips the threshold
    assert len(reader_cls) == 2, "never rebuilt"
    assert reader_cls[0].closed
    assert jr.rebuilds == 1


def test_a_rebuild_resumes_from_the_cursor_not_the_tail(reader_cls):
    """Falling back to the tail would silently drop everything written while
    the reader was stuck — a recoverable fault turned into a permanent hole."""
    from sentinel.collectors.journald_reader import REBUILD_AFTER_EMPTY_POLLS

    jr = _make(reader_cls)
    reader_cls[0].entries = [_entry("cursor-42")]
    jr.read_new()
    for _ in range(REBUILD_AFTER_EMPTY_POLLS + 1):
        jr.read_new()

    fresh = reader_cls[1]
    assert fresh.sought == ["cursor-42"]
    assert fresh.tailed == 0


def test_no_rebuild_without_a_cursor(reader_cls):
    """Before the first entry there is nothing to resume from, and rebuilding
    would just re-seek to the tail forever on a genuinely idle host."""
    from sentinel.collectors.journald_reader import REBUILD_AFTER_EMPTY_POLLS

    jr = _make(reader_cls)
    for _ in range(REBUILD_AFTER_EMPTY_POLLS * 2):
        jr.read_new()
    assert len(reader_cls) == 1


def test_the_counter_resets_when_entries_arrive(reader_cls):
    """A quiet night must not accumulate towards a rebuild."""
    from sentinel.collectors.journald_reader import REBUILD_AFTER_EMPTY_POLLS

    jr = _make(reader_cls)
    reader_cls[0].entries = [_entry("c1")]
    jr.read_new()
    for _ in range(REBUILD_AFTER_EMPTY_POLLS - 1):
        jr.read_new()
    reader_cls[0].entries = [_entry("c2")]
    assert len(jr.read_new()) == 1
    assert jr.empty_polls == 0

    for _ in range(REBUILD_AFTER_EMPTY_POLLS):
        jr.read_new()
    assert len(reader_cls) == 1, "rebuilt despite recent activity"


def test_the_rebuild_is_logged_as_an_error(reader_cls, caplog):
    """It is not routine. If this shows up in the journal, the host is hitting
    the failure and the operator should know."""
    import logging

    from sentinel.collectors.journald_reader import REBUILD_AFTER_EMPTY_POLLS

    jr = _make(reader_cls)
    reader_cls[0].entries = [_entry("c1")]
    jr.read_new()
    with caplog.at_level(logging.ERROR):
        for _ in range(REBUILD_AFTER_EMPTY_POLLS + 1):
            jr.read_new()
    assert any("rebuilding" in r.message for r in caplog.records)


# --- cursor handling --------------------------------------------------------
def test_the_cursor_advances_past_entries_that_are_not_returned(reader_cls):
    """The cursor records what was LOOKED at. Tying it to what was stored would
    make every rebuild re-read the same uninteresting entries."""
    jr = _make(reader_cls)
    reader_cls[0].entries = [
        {"MESSAGE": "", "__CURSOR": "c-empty", "__REALTIME_TIMESTAMP": NOW, "_COMM": "sudo"},
    ]
    assert jr.read_new() == []          # nothing worth returning
    reader_cls[0].entries = []
    from sentinel.collectors.journald_reader import REBUILD_AFTER_EMPTY_POLLS
    for _ in range(REBUILD_AFTER_EMPTY_POLLS + 1):
        jr.read_new()
    assert reader_cls[1].sought == ["c-empty"]


def test_seek_without_a_cursor_starts_at_the_tail(reader_cls):
    """A first run must not ingest the entire history of the journal."""
    jr = _make(reader_cls)
    jr.seek(None)
    assert reader_cls[0].tailed == 1


def test_an_unusable_cursor_falls_back_to_the_tail(reader_cls):
    jr = _make(reader_cls)

    def _boom(cursor):
        raise ValueError("cursor from a vacuumed boot")

    reader_cls[0].seek_cursor = _boom
    jr.seek("s=deadbeef;i=1;b=2")
    assert reader_cls[0].tailed == 1


def test_limit_is_respected(reader_cls):
    jr = _make(reader_cls)
    reader_cls[0].entries = [_entry(f"c{i}") for i in range(10)]
    assert len(jr.read_new(limit=3)) == 3


def test_bytes_fields_are_decoded(reader_cls):
    """journald returns bytes for anything it could not validate as UTF-8, and
    a hostile username is exactly such a field."""
    jr = _make(reader_cls)
    reader_cls[0].entries = [{
        "MESSAGE": b"Failed password for \xff\xfe",
        "__CURSOR": "c1", "__REALTIME_TIMESTAMP": NOW, "_COMM": b"sshd-session",
    }]
    (message, _, _, comm), = jr.read_new()
    assert isinstance(message, str) and isinstance(comm, str)
    assert comm == "sshd-session"


def test_a_naive_timestamp_is_treated_as_utc(reader_cls):
    jr = _make(reader_cls)
    reader_cls[0].entries = [{
        "MESSAGE": "x", "__CURSOR": "c1", "_COMM": "sudo",
        "__REALTIME_TIMESTAMP": datetime(2026, 8, 4, 12, 0),
    }]
    (_, ts, _, _), = jr.read_new()
    assert ts.tzinfo is timezone.utc
