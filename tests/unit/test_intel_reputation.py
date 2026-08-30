"""Reputation feeds: fetch, cap, circuit-breaker, and freshness.

Each test names the operator-visible failure it prevents. No live database —
`_FakeDB`/`_FakeConn` answer exactly the calls this module makes, in the same
style `tests/unit/test_decider.py` and `tests/unit/test_intrusion.py` already
use for their own repo-layer stubs.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime, timedelta, timezone

from sentinel.intel import reputation


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
class _FakeConn:
    """What `db.transaction()` yields — records every call, never touches
    anything real."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    async def execute(self, sql, *args):
        self.calls.append(("execute", sql, args))
        return "OK"

    async def executemany(self, sql, rows):
        self.calls.append(("executemany", sql, rows))


class _FakeDB:
    """Answers by SQL substring — same convention as `_StubDB` in
    test_decider.py and `_DB` in test_intrusion.py."""

    def __init__(self, *, feeds_rows=None, failure_row=None):
        self.feeds_rows = feeds_rows or []
        self.failure_row = failure_row
        self.executed: list[tuple] = []
        self.transactions: list[_FakeConn] = []
        self.fetch_calls = 0

    async def fetch(self, sql, *args):
        self.fetch_calls += 1
        if "SELECT name, url, format FROM intel_feeds" in sql:
            return self.feeds_rows
        return []

    async def fetchrow(self, sql, *args):
        if "RETURNING failures" in sql:
            return self.failure_row
        return None

    async def execute(self, sql, *args):
        self.executed.append((sql, args))
        return "UPDATE 1"

    @contextlib.asynccontextmanager
    async def transaction(self):
        conn = _FakeConn()
        self.transactions.append(conn)
        yield conn


# ---------------------------------------------------------------------------
# _parse_plain_list
# ---------------------------------------------------------------------------
def test_parse_plain_list_ignores_comments_blanks_and_trailing_notes():
    """A `#`/`;` comment line or a trailing annotation must not become a
    bogus network entry — that would silently widen a feed's coverage to
    addresses it never actually published."""
    text = (
        "# header comment\n"
        "\n"
        "198.51.100.0/24\n"
        "; another style of comment\n"
        "203.0.113.5 ; observed 2026-08-29\n"
        "not-an-address\n"
    )
    assert reputation._parse_plain_list(text) == {"198.51.100.0/24", "203.0.113.5/32"}


# ---------------------------------------------------------------------------
# MAX_ENTRIES_PER_FEED: refuse, never truncate
# ---------------------------------------------------------------------------
def test_a_feed_over_the_cap_is_refused_not_truncated(monkeypatch):
    """A feed returning more entries than the cap must be REFUSED whole — the
    same argument as `trivy_fs.MAX_FINDINGS`: a truncated write would still
    stamp `last_success` and look like a clean refresh while covering only a
    fraction of what the feed actually publishes, destroying the previous
    good mirror with the very refresh meant to update it."""
    monkeypatch.setattr(reputation, "MAX_ENTRIES_PER_FEED", 2)

    async def _fake_fetch(url, fmt):
        return {"198.51.100.1/32", "198.51.100.2/32", "198.51.100.3/32"}

    monkeypatch.setattr(reputation, "_fetch_feed", _fake_fetch)
    db = _FakeDB(failure_row={"failures": 1})
    n = run(reputation._refresh_one(db, {"name": "f1", "url": "x", "format": "plain"}))
    assert n == -1
    # The previous mirror must never be touched: no transaction opened at all.
    assert db.transactions == []


def test_a_feed_under_the_cap_is_written(monkeypatch):
    """Falsifies the refusal the other way: a feed within the cap must still
    write its entries and stamp success — a guard that never lets anything
    through is as broken as one that lets everything through."""
    monkeypatch.setattr(reputation, "MAX_ENTRIES_PER_FEED", 10)

    async def _fake_fetch(url, fmt):
        return {"198.51.100.1/32", "198.51.100.2/32"}

    monkeypatch.setattr(reputation, "_fetch_feed", _fake_fetch)
    db = _FakeDB()
    n = run(reputation._refresh_one(db, {"name": "f1", "url": "x", "format": "plain"}))
    assert n == 2
    assert len(db.transactions) == 1
    kinds = [c[0] for c in db.transactions[0].calls]
    assert kinds == ["execute", "executemany", "execute"]  # DELETE, INSERT, UPDATE


def test_a_fetch_exception_is_a_refusal_not_a_crash(monkeypatch):
    """A dead URL or a network blip must not raise out of `_refresh_one` —
    `refresh_all` (and the maintenance step around it) must survive one bad
    feed exactly like every other isolated maintenance step does."""
    async def _boom(url, fmt):
        raise OSError("connection refused")

    monkeypatch.setattr(reputation, "_fetch_feed", _boom)
    db = _FakeDB(failure_row={"failures": 1})
    n = run(reputation._refresh_one(db, {"name": "f1", "url": "x", "format": "plain"}))
    assert n == -1
    assert db.transactions == []


# ---------------------------------------------------------------------------
# Circuit breaker: three consecutive failures, and only three
# ---------------------------------------------------------------------------
def test_circuit_breaker_trips_on_the_third_failure():
    """A feed hammering a dead URL every hour must stop after three failures
    — without this, a feed that will never recover retries forever and the
    operator never sees anything change."""
    db = _FakeDB(failure_row={"failures": reputation.CIRCUIT_FAILURES})
    run(reputation._record_failure(db, "f1", "boom"))
    trip_calls = [a for sql, a in db.executed if "disabled_until" in sql]
    assert trip_calls, "third failure must set disabled_until"


def test_circuit_breaker_does_not_trip_before_the_third_failure():
    """Falsifies the trip the other way: one or two failures must not
    disable the feed, or a single transient DNS blip would silently stop a
    feed for an hour."""
    db = _FakeDB(failure_row={"failures": reputation.CIRCUIT_FAILURES - 1})
    run(reputation._record_failure(db, "f1", "boom"))
    trip_calls = [a for sql, a in db.executed if "disabled_until" in sql]
    assert not trip_calls


# ---------------------------------------------------------------------------
# refresh_all: which feeds it touches
# ---------------------------------------------------------------------------
def test_refresh_all_only_touches_the_returned_feeds(monkeypatch):
    """`refresh_all` must call `_refresh_one` exactly for what the query
    returns — the enabled/not-tripped filter lives in the SQL predicate
    (`WHERE enabled AND (disabled_until IS NULL OR disabled_until <= now())`),
    and this pins that `refresh_all` neither adds nor drops feeds around it."""
    called: list[str] = []

    async def _fake_refresh_one(db, feed):
        called.append(feed["name"])
        return 5

    monkeypatch.setattr(reputation, "_refresh_one", _fake_refresh_one)
    db = _FakeDB(feeds_rows=[
        {"name": "feed-a", "url": "x", "format": "plain"},
        {"name": "feed-b", "url": "y", "format": "plain"},
    ])
    result = run(reputation.refresh_all(db))
    assert called == ["feed-a", "feed-b"]
    assert result == {"feed-a": 5, "feed-b": 5}


# ---------------------------------------------------------------------------
# Freshness: _is_fresh, and lookup()/snapshot() built on it
# ---------------------------------------------------------------------------
def test_is_fresh_within_the_window():
    now = datetime(2026, 8, 30, tzinfo=timezone.utc)
    last_success = now - timedelta(hours=reputation.MAX_FEED_AGE_H - 1)
    assert reputation._is_fresh(last_success, now=now)


def test_is_fresh_past_the_window_is_stale():
    """A feed last refreshed successfully more than MAX_FEED_AGE_H ago no
    longer describes the internet of today — this is the freshness guard
    CLAUDE.md's task explicitly requires, and its absence is what would let a
    month-old blocklist keep lowering the auto-block threshold forever."""
    now = datetime(2026, 8, 30, tzinfo=timezone.utc)
    last_success = now - timedelta(hours=reputation.MAX_FEED_AGE_H + 1)
    assert not reputation._is_fresh(last_success, now=now)


def test_is_fresh_never_succeeded_is_stale():
    assert not reputation._is_fresh(None)


def _feeds_rows(fresh_ts, stale_ts):
    return [
        {"name": "fresh-feed", "category": "botnet", "confidence": 80,
         "last_success": fresh_ts},
        {"name": "stale-feed", "category": "drop", "confidence": 90,
         "last_success": stale_ts},
    ]


def test_lookup_ignores_a_stale_feed():
    """A hostile match on a feed that has not refreshed in over
    MAX_FEED_AGE_H hours must not surface a category — otherwise a feed whose
    URL moved, or one the operator stopped fetching, keeps lowering the
    auto-block threshold on data nobody has re-validated in weeks."""
    now = datetime.now(timezone.utc)
    fresh_ts = now - timedelta(hours=1)
    stale_ts = now - timedelta(hours=reputation.MAX_FEED_AGE_H + 1)

    async def _fake_fetch(sql, *args):
        if "SELECT name, category, confidence, last_success FROM intel_feeds" in sql:
            return _feeds_rows(fresh_ts, stale_ts)
        if "SELECT DISTINCT feed_name FROM intel_feed_entries" in sql:
            names, _ip = args
            # Both feeds "contain" the address in this fake — the only thing
            # that can exclude stale-feed is the freshness filter upstream.
            return [{"feed_name": n} for n in names]
        return []

    db = _FakeDB()
    db.fetch = _fake_fetch  # type: ignore[method-assign]
    cats = run(reputation.lookup(db, "198.51.100.7"))
    assert cats == ["botnet"]  # never "drop" — that feed is stale


def test_lookup_rejects_a_malformed_ip_without_touching_the_db():
    """A malformed address must never reach the containment query — asyncpg
    would raise on an invalid `::inet` cast, turning a bad input into a
    crashed detection pass instead of an empty answer."""
    db = _FakeDB()
    assert run(reputation.lookup(db, "not-an-ip")) == []
    assert db.fetch_calls == 0


def test_snapshot_excludes_a_stale_feeds_entries():
    """What `enrich.reputation.ReputationEnricher` loads into memory must
    never include a stale feed's ranges — the in-memory cache would otherwise
    keep tagging events with a category the freshness guard retired."""
    now = datetime.now(timezone.utc)
    fresh_ts = now - timedelta(hours=1)
    stale_ts = now - timedelta(hours=reputation.MAX_FEED_AGE_H + 1)

    async def _fake_fetch(sql, *args):
        if "SELECT name, category, confidence, last_success FROM intel_feeds" in sql:
            return _feeds_rows(fresh_ts, stale_ts)
        if "SELECT feed_name, network FROM intel_feed_entries" in sql:
            (names,) = args
            return [{"feed_name": n, "network": "198.51.100.0/24"} for n in names]
        return []

    db = _FakeDB()
    db.fetch = _fake_fetch  # type: ignore[method-assign]
    rows = run(reputation.snapshot(db))
    assert rows == [("198.51.100.0/24", "botnet", 80)]


def test_snapshot_and_lookup_agree_on_no_fresh_feeds():
    """When nothing is fresh (the shipped default: no feed enabled), both
    functions must answer empty without ever reaching the entries query —
    the ships-empty state must cost nothing and find nothing, never error."""
    db = _FakeDB()  # feeds_rows=[] -> _fresh_feeds returns {}
    assert run(reputation.snapshot(db)) == []
    assert run(reputation.lookup(db, "198.51.100.7")) == []
