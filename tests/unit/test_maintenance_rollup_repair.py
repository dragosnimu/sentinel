"""`repair_rollup_gaps` — the repair half of the watermark defect described in
`maintenance_service`'s module docstring: an hour the watermark has already
left behind never gets reaggregated on its own, however late rows for it
arrive. Detection (`check_rollup_reconcile`) and its own repo query
(`hourly_gaps`) are proven elsewhere; these tests drive the repair step's
branching and its use of the two SQL rollup functions.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.analytics import reports as report_repo
from sentinel.db.repo import rollups as rollup_repo
from sentinel.services import maintenance_service as ms


def run(coro):
    return asyncio.run(coro)


def _async(value):
    async def _f(*a, **k):
        return value
    return _f


class _DB:
    """Records every `fetchval` call so tests can inspect what was asked for,
    in what order — the thing a SQL-substring stub cannot show."""

    def __init__(self):
        self.calls: list[tuple[str, tuple]] = []

    async def fetchval(self, sql, *args):
        self.calls.append((sql, args))
        return 1


# ---------------------------------------------------------------------------
# The step is wired into the run, in the right place
# ---------------------------------------------------------------------------
def test_step_runs_after_rollup_events_and_before_retention():
    """Repair reads `raw_events` for the target hours — it has to run before
    retention can drop the partition it needs, and after the forward
    catch-up it is not a substitute for."""
    consts = ms.run.__code__.co_consts
    order = [c for c in consts if isinstance(c, str)
             and c in ("rollup_events", "repair_rollup_gaps", "retention_partitions")]
    assert order.index("rollup_events") < order.index("repair_rollup_gaps") < \
           order.index("retention_partitions")


# ---------------------------------------------------------------------------
# The two "nothing to do yet" edges
# ---------------------------------------------------------------------------
def test_nothing_to_repair_when_rollup_never_ran(monkeypatch):
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": True, "latest": None}))
    called = []
    monkeypatch.setattr(report_repo, "raw_coverage",
                        lambda *a, **k: called.append(1) or _async(None)())

    detail, facts = run(ms.repair_rollup_gaps(_DB()))
    assert facts["hours_repaired"] == 0
    assert not called, "raw_coverage was read with no rollup watermark to bound against"


def test_nothing_to_repair_when_the_window_is_empty(monkeypatch):
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc)))  # == upper
    called = []
    monkeypatch.setattr(rollup_repo, "hourly_gaps",
                        lambda *a, **k: called.append(1) or _async(rollup_repo.GapReport())())

    detail, facts = run(ms.repair_rollup_gaps(_DB()))
    assert facts["hours_repaired"] == 0
    assert not called


def test_nothing_to_repair_when_no_gap_is_found(monkeypatch):
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(rollup_repo.GapReport()))

    db = _DB()
    detail, facts = run(ms.repair_rollup_gaps(db))
    assert facts["hours_repaired"] == 0
    assert db.calls == [], "no gap found — nothing should have been reaggregated"


# ---------------------------------------------------------------------------
# The actual repair: minute before hour, per gap, oldest first
# ---------------------------------------------------------------------------
def _fixed_gap_report(*buckets: datetime, total_hours: int | None = None) -> rollup_repo.GapReport:
    hours = [rollup_repo.GapHour(b, 10, 1) for b in buckets]
    return rollup_repo.GapReport(
        hours=hours, total_hours=total_hours or len(hours),
        total_missing=9 * len(hours))


def test_each_gap_hour_reaggregates_the_minute_table_before_the_hour_table(monkeypatch):
    """`sentinel_rollup_events_1h` reads FROM `event_rollup_1m`, never from
    `raw_events` (0017_partition_fixes.sql) — reaggregating only the hour
    would still read the same incomplete minute data the watermark already
    skipped. Both must run, minute first, for every gap hour."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 8, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    bucket = datetime(2026, 8, 24, 4, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(_fixed_gap_report(bucket)))

    db = _DB()
    detail, facts = run(ms.repair_rollup_gaps(db))

    assert facts["hours_repaired"] == 1
    sqls = [c[0] for c in db.calls]
    assert len(sqls) == 2
    assert "sentinel_rollup_events_1m" in sqls[0]
    assert "sentinel_rollup_events_1h" in sqls[1]
    for sql, args in db.calls:
        assert args == (bucket, bucket + timedelta(hours=1))


def test_gap_hours_are_repaired_oldest_first(monkeypatch):
    """An old gap races raw retention — the source rows for it disappear
    first. Reordering this would mean the hours least likely to still be
    repairable are repaired last."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 26, 0, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    b1 = datetime(2026, 8, 23, 5, 0, tzinfo=timezone.utc)
    b2 = datetime(2026, 8, 24, 4, 0, tzinfo=timezone.utc)
    b3 = datetime(2026, 8, 25, 9, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(_fixed_gap_report(b1, b2, b3)))

    db = _DB()
    detail, facts = run(ms.repair_rollup_gaps(db))

    assert facts["hours_repaired"] == 3
    # 2 SQL calls (1m, 1h) per hour, in bucket order.
    starts = [db.calls[i][1][0] for i in range(0, len(db.calls), 2)]
    assert starts == [b1, b2, b3]


def test_repair_reports_how_many_gap_hours_are_still_left(monkeypatch):
    """`hourly_gaps` is called with `limit=MAX_GAP_REPAIR_HOURS`, so a bigger
    backlog than that comes back truncated. A capped repair that goes quiet
    about the remainder is the exact bug `drain_default` already had to
    solve — the fix has to be visible in this step's own facts too."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 26, 0, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    seen_limit = {}

    async def _capture(db, *, lower, upper, limit):
        seen_limit["limit"] = limit
        b = datetime(2026, 8, 23, 5, 0, tzinfo=timezone.utc)
        return _fixed_gap_report(b, total_hours=25)  # far more than the sample returned

    monkeypatch.setattr(rollup_repo, "hourly_gaps", _capture)

    db = _DB()
    detail, facts = run(ms.repair_rollup_gaps(db))

    assert seen_limit["limit"] == ms.MAX_GAP_REPAIR_HOURS
    assert facts["hours_repaired"] == 1
    assert facts["hours_left"] == 24
    assert "rămase" in detail
