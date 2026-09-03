"""`check_rollup_reconcile` — the operator's only window onto the silent loss
in `event_rollup_1h` described in `maintenance_service`'s module docstring.

These tests drive the check itself (branching, boundary arithmetic, the two
"do not raise a false alarm" edges) with the repo functions it calls stubbed
out — `hourly_gaps`'s own SQL correctness is proven separately, against a real
translated SQLite, in `test_rollup_reconcile_sql.py`. Testing both layers
matters here: a stub can make the branching look right while the underlying
query is wrong, and a correct query is worthless if the caller feeds it the
wrong boundary.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sentinel.analytics import reports as report_repo
from sentinel.db.repo import rollups as rollup_repo
from sentinel.selfcheck import checks


def run(coro):
    return asyncio.run(coro)


def _async(value):
    async def _f(*a, **k):
        return value
    return _f


class _DB:
    """Never actually queried by the check itself — every DB read the check
    performs goes through the two repo functions, which are stubbed below."""


def test_registered_in_checks():
    names = [name for name, _fn in checks.CHECKS]
    assert "rollup_reconcile" in names
    assert dict(checks.CHECKS)["rollup_reconcile"] is checks.check_rollup_reconcile


# ---------------------------------------------------------------------------
# Ok / degraded / unknown branching
# ---------------------------------------------------------------------------
def test_ok_when_rollup_agrees_with_raw(monkeypatch):
    """A synced rollup — the common case — must not sit on the panel forever
    as a red or unknown finding; withdrawing it wrongly on a synced host would
    itself be the kind of false alarm the module docstring warns about."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(rollup_repo.GapReport()))

    results = run(checks.check_rollup_reconcile(_DB()))
    assert len(results) == 1
    assert results[0].key == "rollup:reconcile"
    assert results[0].status == "ok"
    assert not results[0].bad


def test_degraded_with_the_real_measured_gap(monkeypatch):
    """The 24 August numbers from the incident report, run through the check:
    3 gap hours, 3 956 463 missing rows, oldest at 04:00. `degraded`, never
    `down` — nothing currently running has stopped because of this."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 25, 0, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    report = rollup_repo.GapReport(
        hours=[
            rollup_repo.GapHour(datetime(2026, 8, 24, 4, 0, tzinfo=timezone.utc), 1385, 6),
            rollup_repo.GapHour(datetime(2026, 8, 24, 5, 0, tzinfo=timezone.utc), 977, 6),
        ],
        total_hours=3, total_missing=3_956_463)
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(report))

    results = run(checks.check_rollup_reconcile(_DB()))
    assert len(results) == 1
    r = results[0]
    assert r.status == "degraded"
    assert r.bad
    assert r.facts["gap_hours"] == 3
    assert r.facts["rows_missing"] == 3_956_463
    assert r.facts["oldest_gap"] == "2026-08-24T04:00:00+00:00"


def test_unknown_when_rollup_never_ran_but_raw_has_data(monkeypatch):
    """`raw_events` has rows, `event_rollup_1h` has never been written at all —
    the check cannot establish `upper` and must not guess `ok` or `degraded`
    with nothing to compare against."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": True, "latest": None}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    called = []
    monkeypatch.setattr(rollup_repo, "hourly_gaps",
                        lambda *a, **k: called.append(1) or _async(rollup_repo.GapReport())())

    results = run(checks.check_rollup_reconcile(_DB()))
    assert results[0].status == "unknown"
    assert not called, "hourly_gaps was queried with no rollup watermark to bound it"


def test_ok_on_a_fresh_install_with_nothing_yet(monkeypatch):
    """Neither table has anything — a fresh install, not a fault. `ok`, the
    same way `check_restore_drill` treats a host with no restore points yet."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": True, "latest": None}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(None))

    results = run(checks.check_rollup_reconcile(_DB()))
    assert results[0].status == "ok"
    assert results[0].facts["raw_exists"] is False


# ---------------------------------------------------------------------------
# The two boundaries: no false alarm on the open hour, none on expired raw
# ---------------------------------------------------------------------------
def test_upper_bound_is_the_rollup_watermark_hour_truncated(monkeypatch):
    """`rollup_coverage()["latest"]` can carry minutes/seconds if a caller
    upstream ever stops truncating; the check must still hand `hourly_gaps` an
    hour-aligned `upper`, or a partial hour just short of the boundary could
    leak through as comparable when it is still being rewritten every pass."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 7, 43, 12, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))

    seen = {}

    async def _capture(db, *, lower, upper, limit):
        seen["lower"] = lower
        seen["upper"] = upper
        return rollup_repo.GapReport()

    monkeypatch.setattr(rollup_repo, "hourly_gaps", _capture)
    run(checks.check_rollup_reconcile(_DB()))

    assert seen["upper"] == datetime(2026, 8, 24, 7, 0, 0, tzinfo=timezone.utc), (
        "the open hour was not excluded — check_rollup_reconcile passed a "
        "non-hour-aligned upper bound")


def test_empty_window_is_ok_without_querying(monkeypatch):
    """Raw coverage caught up to (or past) the rollup watermark — nothing is
    settled yet to compare. Must not even call `hourly_gaps`: an empty window
    querying real Postgres would just waste a pass, and `hourly_gaps` itself
    already refuses it, so a call here would only prove the check ignores
    that contract."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc)))  # == upper: nothing settled

    called = []
    monkeypatch.setattr(rollup_repo, "hourly_gaps",
                        lambda *a, **k: called.append(1) or _async(rollup_repo.GapReport())())

    results = run(checks.check_rollup_reconcile(_DB()))
    assert results[0].status == "ok"
    assert not called
