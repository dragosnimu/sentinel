"""In-memory reputation enrichment at ingestion — cost, correctness, and reload
cadence. See `sentinel/enrich/reputation.py`'s docstring for the measurement
behind the design pinned here.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sentinel.enrich.reputation import ReputationEnricher
from sentinel.model.event import Event


def run(coro):
    return asyncio.run(coro)


def _event(src_ip: str | None) -> Event:
    return Event(ts=datetime.now(timezone.utc), source="sshd", action="auth_fail",
                 src_ip=src_ip)


class _FakeDB:
    """`maybe_refresh` only ever calls `sentinel.intel.reputation.snapshot`,
    monkeypatched in each test — this class exists purely so a `Database`-
    shaped object can be passed without importing asyncpg."""


def test_host_entry_is_found():
    """The common case — most public blocklists are one IP per line — must be
    an O(1) dict hit, not a scan; correctness first, cost is pinned below."""
    enr = ReputationEnricher()
    enr._load([("198.51.100.7/32", "botnet", 80)])
    ev = _event("198.51.100.7")
    enr.enrich(ev)
    assert ev.reputation == ["botnet"]


def test_range_entry_is_found():
    """A genuine CIDR feed (Spamhaus-DROP-shaped) must still match an address
    inside the range, via the bucketed scan path."""
    enr = ReputationEnricher()
    enr._load([("198.51.100.0/24", "drop", 90)])
    ev = _event("198.51.100.200")
    enr.enrich(ev)
    assert ev.reputation == ["drop"]


def test_address_outside_every_entry_is_not_tagged():
    """Falsifies both matches above the other way: an address that is on
    neither the host list nor inside any range must leave `reputation` empty
    — a match here would mean every event gets tagged regardless of content,
    which is exactly the false-positive flood a wrong enricher would cause."""
    enr = ReputationEnricher()
    enr._load([("198.51.100.7/32", "botnet", 80), ("203.0.113.0/24", "drop", 90)])
    ev = _event("192.0.2.55")
    enr.enrich(ev)
    assert ev.reputation == []


def test_multiple_categories_are_combined_and_deduplicated():
    enr = ReputationEnricher()
    enr._load([("198.51.100.7/32", "botnet", 80), ("198.51.100.0/24", "drop", 90)])
    ev = _event("198.51.100.7")
    enr.enrich(ev)
    assert ev.reputation == ["botnet", "drop"]


def test_no_source_ip_is_a_no_op():
    """A raw event with no attributable address (e.g. a local audit action)
    must not crash the enricher and must not gain a spurious category."""
    enr = ReputationEnricher()
    enr._load([("198.51.100.7/32", "botnet", 80)])
    ev = _event(None)
    enr.enrich(ev)
    assert ev.reputation == []


def test_empty_snapshot_is_available_false_and_a_cheap_no_op():
    """The shipped default — no feed enabled, `snapshot()` returns nothing —
    must leave the enricher `available=False` and `enrich()` a no-op, not an
    exception, since this is what every ingest poll does on a fresh install."""
    enr = ReputationEnricher()
    assert enr.available is False
    ev = _event("198.51.100.7")
    enr.enrich(ev)
    assert ev.reputation == []


# ---------------------------------------------------------------------------
# Reload cadence: the whole reason this class exists instead of a per-event
# database call (see the module docstring's cost measurement).
# ---------------------------------------------------------------------------
def test_maybe_refresh_loads_on_first_call(monkeypatch):
    calls = {"n": 0}

    async def _fake_snapshot(db):
        calls["n"] += 1
        return [("198.51.100.7/32", "botnet", 80)]

    monkeypatch.setattr("sentinel.intel.reputation.snapshot", _fake_snapshot)
    enr = ReputationEnricher()
    run(enr.maybe_refresh(_FakeDB()))
    assert calls["n"] == 1
    assert enr.available is True


def test_maybe_refresh_does_not_reload_within_the_interval(monkeypatch):
    """This is the cost guard: a per-event database call was rejected
    precisely because of its volume (~55 000 events/day). If `maybe_refresh`
    reloaded on every call instead of respecting `_RELOAD_INTERVAL_S`, calling
    it once per `poll_once` (as `sentinel-ingest` does) would silently become
    the exact per-event database hit the design exists to avoid."""
    calls = {"n": 0}

    async def _fake_snapshot(db):
        calls["n"] += 1
        return []

    monkeypatch.setattr("sentinel.intel.reputation.snapshot", _fake_snapshot)
    enr = ReputationEnricher()
    run(enr.maybe_refresh(_FakeDB()))
    for _ in range(50):
        run(enr.maybe_refresh(_FakeDB()))
    assert calls["n"] == 1


def test_maybe_refresh_reloads_after_the_interval(monkeypatch):
    """Falsifies the guard above the other way: the cache must not freeze
    forever — a feed refreshed hourly by `sentinel-maintenance` must reach
    this process's memory eventually."""
    import sentinel.enrich.reputation as mod

    calls = {"n": 0}

    async def _fake_snapshot(db):
        calls["n"] += 1
        return []

    monkeypatch.setattr("sentinel.intel.reputation.snapshot", _fake_snapshot)
    monkeypatch.setattr(mod, "_RELOAD_INTERVAL_S", 0)
    enr = ReputationEnricher()
    run(enr.maybe_refresh(_FakeDB()))
    run(enr.maybe_refresh(_FakeDB()))
    assert calls["n"] == 2


def test_a_reload_failure_keeps_the_previous_snapshot(monkeypatch):
    """A briefly unreachable database must not blank the cache — "the feed
    lookup failed" and "this address has no reputation" are different facts,
    and only the second one may silently do nothing (CLAUDE.md's guiding
    distinction, applied here)."""
    import sentinel.enrich.reputation as mod

    async def _ok_snapshot(db):
        return [("198.51.100.7/32", "botnet", 80)]

    monkeypatch.setattr("sentinel.intel.reputation.snapshot", _ok_snapshot)
    enr = ReputationEnricher()
    run(enr.maybe_refresh(_FakeDB()))
    assert enr.available is True

    async def _boom_snapshot(db):
        raise OSError("database unreachable")

    monkeypatch.setattr("sentinel.intel.reputation.snapshot", _boom_snapshot)
    monkeypatch.setattr(mod, "_RELOAD_INTERVAL_S", 0)  # force the retry to fire
    run(enr.maybe_refresh(_FakeDB()))
    ev = _event("198.51.100.7")
    enr.enrich(ev)
    assert ev.reputation == ["botnet"]  # previous snapshot, not wiped
