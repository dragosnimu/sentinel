"""`check_rollup_reconcile` — the operator's only window onto the silent loss
in `event_rollup_1h` described in `maintenance_service`'s module docstring.

Round 2 changed what this check DOES: it used to call `hourly_gaps` itself,
recomputing a whole-window aggregate on the self-check's own cadence — the
same shape as a previously measured incident where a five-minute check kept
re-running an expensive aggregate that only needed computing once an hour.
It now reads the row `maintenance_service.repair_rollup_gaps` already
persists once an hour to `rollup_reconcile_runs`. These tests drive that
reading — the branching over `status`, staleness, and the exception path —
with `rollup_repo.latest_reconcile_run` stubbed; `hourly_gaps`'s own SQL
correctness is proven separately, against a real translated SQLite, in
`test_rollup_reconcile_sql.py`.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from sentinel.db.repo import rollups as rollup_repo
from sentinel.selfcheck import checks


def run(coro):
    return asyncio.run(coro)


def _async(value):
    async def _f(*a, **k):
        return value
    return _f


def _run(**over) -> rollup_repo.ReconcileRun:
    base = dict(
        checked_at=datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc),
        status="ok", raw_exists=True,
        window_lower=datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc),
        window_upper=datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc),
        gap_hours=0, rows_missing=0, worst_bucket=None, worst_missing=0,
        hours_repaired=0)
    base.update(over)
    return rollup_repo.ReconcileRun(**base)


class _DB:
    """Never actually queried by the check itself — every DB read the check
    performs goes through `latest_reconcile_run`, which is stubbed below."""


def test_registered_in_checks():
    names = [name for name, _fn in checks.CHECKS]
    assert "rollup_reconcile" in names
    assert dict(checks.CHECKS)["rollup_reconcile"] is checks.check_rollup_reconcile


def _now(monkeypatch, moment: datetime) -> None:
    """`check_rollup_reconcile` reads `datetime.now(timezone.utc)` to judge
    staleness — inject it instead of depending on the wall clock, per the
    project's no-clock-dependency rule."""
    class _Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return moment
    monkeypatch.setattr(checks, "datetime", _Clock)


# ---------------------------------------------------------------------------
# It reads the persisted row — it does not recompute
# ---------------------------------------------------------------------------
def test_it_never_calls_hourly_gaps_itself(monkeypatch):
    """Decision 4 of round 2: the check must not rescan `raw_events`/
    `event_rollup_1h` on its own cadence. If it ever calls `hourly_gaps`
    again, this fails loudly instead of quietly reintroducing the
    five-minute-rescan shape."""
    _now(monkeypatch, datetime(2026, 8, 24, 12, 30, tzinfo=timezone.utc))
    monkeypatch.setattr(rollup_repo, "latest_reconcile_run", _async(_run()))
    called = []
    monkeypatch.setattr(
        rollup_repo, "hourly_gaps",
        lambda *a, **k: called.append(1) or _async(rollup_repo.GapReport())())

    run(checks.check_rollup_reconcile(_DB()))
    assert not called, "check_rollup_reconcile called hourly_gaps directly"


# ---------------------------------------------------------------------------
# Ok / degraded / unknown branching, read straight from the persisted status
# ---------------------------------------------------------------------------
def test_ok_when_last_pass_found_nothing(monkeypatch):
    _now(monkeypatch, datetime(2026, 8, 24, 12, 30, tzinfo=timezone.utc))
    monkeypatch.setattr(rollup_repo, "latest_reconcile_run", _async(_run(status="ok")))

    results = run(checks.check_rollup_reconcile(_DB()))
    assert len(results) == 1
    assert results[0].key == "rollup:reconcile"
    assert results[0].status == "ok"
    assert not results[0].bad


def test_degraded_names_the_worst_hour_not_the_oldest(monkeypatch):
    """Round 2, item 5: the text must surface the hour with the most missing
    rows, not the oldest one — a 2-row gap at 04:00 must not push a
    2 900 000-row gap at 06:00 out of the message."""
    now = datetime(2026, 8, 25, 8, 0, tzinfo=timezone.utc)
    _now(monkeypatch, now)
    worst = datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(rollup_repo, "latest_reconcile_run", _async(_run(
        status="gaps", gap_hours=15, rows_missing=4_245_910,
        worst_bucket=worst, worst_missing=2_900_000, hours_repaired=8,
        window_lower=datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc),
        window_upper=datetime(2026, 8, 25, 7, 0, tzinfo=timezone.utc),
        checked_at=now - timedelta(minutes=5))))

    results = run(checks.check_rollup_reconcile(_DB()))
    r = results[0]
    assert r.status == "degraded"
    assert r.bad
    assert "06:00" in r.detail
    assert "2.900.000" in r.detail or "2,900,000" in r.detail or "2 900 000" in r.detail
    assert "04:00" not in r.detail, (
        "textul a numit ora cea mai veche, nu cea mai gravă")
    assert r.facts["gap_hours"] == 15
    assert r.facts["rows_missing"] == 4_245_910
    assert r.facts["worst_bucket"] == worst.isoformat()
    assert r.facts["worst_missing"] == 2_900_000
    assert r.facts["hours_repaired_last_pass"] == 8


def test_unknown_when_rollup_never_ran_but_raw_has_data(monkeypatch):
    _now(monkeypatch, datetime(2026, 8, 24, 12, 30, tzinfo=timezone.utc))
    monkeypatch.setattr(rollup_repo, "latest_reconcile_run", _async(_run(
        status="never_ran", raw_exists=True, window_lower=None, window_upper=None)))

    results = run(checks.check_rollup_reconcile(_DB()))
    assert results[0].status == "unknown"


def test_ok_on_a_fresh_install_with_nothing_yet(monkeypatch):
    _now(monkeypatch, datetime(2026, 8, 24, 12, 30, tzinfo=timezone.utc))
    monkeypatch.setattr(rollup_repo, "latest_reconcile_run", _async(_run(
        status="never_ran", raw_exists=False, window_lower=None, window_upper=None)))

    results = run(checks.check_rollup_reconcile(_DB()))
    assert results[0].status == "ok"
    assert results[0].facts["raw_exists"] is False


def test_ok_when_the_window_is_still_empty(monkeypatch):
    _now(monkeypatch, datetime(2026, 8, 24, 12, 30, tzinfo=timezone.utc))
    monkeypatch.setattr(rollup_repo, "latest_reconcile_run", _async(_run(
        status="empty_window", window_lower=None, window_upper=None)))

    results = run(checks.check_rollup_reconcile(_DB()))
    assert results[0].status == "ok"


# ---------------------------------------------------------------------------
# No row at all, and a stale row — "unknown" or the check can lie
# ---------------------------------------------------------------------------
def test_unknown_when_no_row_has_ever_been_written(monkeypatch):
    """`repair_rollup_gaps` has never completed a pass — not the same as
    `status == "never_ran"`, which is itself a persisted, dated observation.
    `None` here means no observation exists at all, and guessing `ok` would
    be exactly the intention-over-effect mistake this whole feature exists
    to repair."""
    _now(monkeypatch, datetime(2026, 8, 24, 12, 30, tzinfo=timezone.utc))
    monkeypatch.setattr(rollup_repo, "latest_reconcile_run", _async(None))

    results = run(checks.check_rollup_reconcile(_DB()))
    assert results[0].status == "unknown"


def test_unknown_when_the_persisted_row_is_stale(monkeypatch):
    """`sentinel-maintenance.timer` stopped running this step — the row is 6
    hours old, well past `RECONCILE_STALE_HOURS`. Trusting a stale `ok` would
    show a clean bill of health for a check that has not actually looked in
    hours; that is the exact bug `check_restore_drill`'s staleness branch
    already exists to prevent, repeated here on new material."""
    now = datetime(2026, 8, 24, 18, 0, tzinfo=timezone.utc)
    _now(monkeypatch, now)
    stale_at = now - timedelta(hours=6)
    monkeypatch.setattr(rollup_repo, "latest_reconcile_run", _async(_run(
        status="ok", checked_at=stale_at)))

    results = run(checks.check_rollup_reconcile(_DB()))
    assert results[0].status == "unknown"
    assert results[0].facts["age_hours"] == 6.0


def test_a_recent_row_just_inside_the_staleness_window_is_trusted(monkeypatch):
    """The mirror of the previous test — falsifies it from the other side. A
    row from 1 hour ago (well under `RECONCILE_STALE_HOURS`) must be trusted
    as current, or `sentinel-maintenance` would need to run faster than once
    an hour just to keep this check quiet."""
    now = datetime(2026, 8, 24, 18, 0, tzinfo=timezone.utc)
    _now(monkeypatch, now)
    monkeypatch.setattr(rollup_repo, "latest_reconcile_run", _async(_run(
        status="ok", checked_at=now - timedelta(hours=1))))

    results = run(checks.check_rollup_reconcile(_DB()))
    assert results[0].status == "ok"


def test_a_row_exactly_at_the_staleness_boundary_is_still_trusted(monkeypatch):
    """The exact edge, not just a point safely on either side: at precisely
    `RECONCILE_STALE_HOURS` (3.0h, no fuzz — `sentinel-maintenance` runs at
    :03, so a single missed pass ages a row by at most ~2h and two missed
    passes push it well past 3h; the boundary itself should never be reached
    in normal operation, which is exactly why nothing else exercises it) the
    row is still ON TIME, per `age_h > RECONCILE_STALE_HOURS` (strict). A
    mutation to `>=` would flip only this one point from trusted to
    `unknown`, and every other staleness test in this file is far enough from
    the edge to stay green regardless."""
    now = datetime(2026, 8, 24, 18, 0, tzinfo=timezone.utc)
    _now(monkeypatch, now)
    monkeypatch.setattr(rollup_repo, "latest_reconcile_run", _async(_run(
        status="ok", checked_at=now - timedelta(hours=3))))

    results = run(checks.check_rollup_reconcile(_DB()))
    assert results[0].status == "ok", (
        "un rând vechi de exact RECONCILE_STALE_HOURS a fost tratat ca "
        "învechit — granița e `>`, nu `>=`")


# ---------------------------------------------------------------------------
# The exception branch — reachable whenever the read itself fails
# ---------------------------------------------------------------------------
def test_unknown_when_the_persisted_row_cannot_be_read(monkeypatch):
    """`rollup_reconcile_runs` missing (pre-migration), or any other read
    failure, must not be swallowed into a false `ok` — and must not crash the
    whole self-check group either; `unknown` with the error text is what lets
    an operator act on it."""
    async def _boom(db):
        raise RuntimeError("relation \"rollup_reconcile_runs\" does not exist")
    monkeypatch.setattr(rollup_repo, "latest_reconcile_run", _boom)

    results = run(checks.check_rollup_reconcile(_DB()))
    assert len(results) == 1
    assert results[0].status == "unknown"
    assert "rollup_reconcile_runs" in results[0].detail
