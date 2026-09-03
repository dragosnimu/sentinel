"""`repair_rollup_gaps` — the repair half of the watermark defect described in
`maintenance_service`'s module docstring: an hour the watermark has already
left behind never gets reaggregated on its own, however late rows for it
arrive. Detection (`check_rollup_reconcile`) reads the row this step persists;
`hourly_gaps`'s own SQL correctness is proven separately against a real
translated SQLite in `test_rollup_reconcile_sql.py`. These tests drive the
repair step's branching, its persisted state, and — the round 2 finding — the
SIZE of the SQL statements it issues.
"""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

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
    """Records every `fetchval`/`execute` call so tests can inspect what was
    asked for, in what order and at what SIZE — the thing a SQL-substring
    stub cannot show, and the exact thing round 2 needed and did not have."""

    def __init__(self):
        self.calls: list[tuple[str, tuple]] = []      # fetchval: the 1m/1h SQL
        self.inserts: list[tuple[str, tuple]] = []     # execute: the persisted row

    async def fetchval(self, sql, *args):
        self.calls.append((sql, args))
        return 1

    async def execute(self, sql, *args):
        self.inserts.append((sql, args))
        return "INSERT 0 1"


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
# Every branch persists a row — `check_rollup_reconcile` reads it instead of
# recomputing (round 2, decision 4)
# ---------------------------------------------------------------------------
def test_never_ran_branch_persists_its_own_status(monkeypatch):
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": True, "latest": None}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))  # raw HAS data

    db = _DB()
    detail, facts = run(ms.repair_rollup_gaps(db))
    assert facts["hours_repaired"] == 0
    assert len(db.inserts) == 1
    sql, args = db.inserts[0]
    assert "rollup_reconcile_runs" in sql
    assert args[0] == "never_ran"
    assert args[1] is True, "raw_exists a fost scris greșit — raw_coverage a întors o dată"


def test_empty_window_branch_persists_its_own_status(monkeypatch):
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc)))  # == upper

    db = _DB()
    run(ms.repair_rollup_gaps(db))
    assert len(db.inserts) == 1
    sql, args = db.inserts[0]
    assert args[0] == "empty_window"


def test_no_gap_found_branch_persists_ok(monkeypatch):
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(rollup_repo.GapReport()))

    db = _DB()
    run(ms.repair_rollup_gaps(db))
    assert db.calls == [], "no gap found — nothing should have been reaggregated"
    assert len(db.inserts) == 1
    assert db.inserts[0][1][0] == "ok"


def _fixed_gap_report(*buckets: datetime, total_hours: int | None = None,
                      worst_bucket=None, worst_missing=0) -> rollup_repo.GapReport:
    hours = [rollup_repo.GapHour(b, 10, 1) for b in buckets]
    return rollup_repo.GapReport(
        hours=hours, total_hours=total_hours or len(hours),
        total_missing=9 * len(hours),
        worst_bucket=worst_bucket or (buckets[0] if buckets else None),
        worst_missing=worst_missing or 9)


def test_fully_processed_window_persists_ok_not_the_pre_repair_gap_count(monkeypatch):
    """When every gap hour the window has (`total_hours`) fits inside this
    pass's batch (`len(repaired) == total_hours`), the whole window has just
    been proven fixed — persisting the pre-repair `status="gaps"` here would
    show the operator a problem for an extra hour after it was already gone."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 8, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    bucket = datetime(2026, 8, 24, 4, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(_fixed_gap_report(bucket)))

    db = _DB()
    run(ms.repair_rollup_gaps(db))
    assert len(db.inserts) == 1
    _, args = db.inserts[0]
    assert args[0] == "ok"
    assert args[4] == 0, "gap_hours ar trebui 0 — fereastra a fost reparată integral"


def test_truncated_batch_persists_the_pre_repair_totals(monkeypatch):
    """When the batch is capped, we do not know the exact post-repair state
    without a second full-window scan — the thing this whole design change
    exists to avoid. Persisting the PRE-repair totals is honestly
    conservative: it never UNDERSTATES what is still wrong."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 26, 0, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    bucket = datetime(2026, 8, 24, 4, 0, tzinfo=timezone.utc)
    worst = datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc)
    report = _fixed_gap_report(bucket, total_hours=15, worst_bucket=worst, worst_missing=2_900_000)
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(report))

    db = _DB()
    run(ms.repair_rollup_gaps(db))
    assert len(db.inserts) == 1
    _, args = db.inserts[0]
    status, raw_exists, w_lo, w_hi, gap_hours, rows_missing, w_bucket, w_missing, repaired = args
    assert status == "gaps"
    assert gap_hours == 15
    assert w_bucket == worst
    assert w_missing == 2_900_000
    assert repaired == 1


# ---------------------------------------------------------------------------
# The actual repair: minute-sliced, minute before hour, per gap, oldest first
# ---------------------------------------------------------------------------
def test_each_gap_hour_reaggregates_every_minute_before_the_hour_call(monkeypatch):
    """`sentinel_rollup_events_1h` reads FROM `event_rollup_1m`, never from
    `raw_events` (0017_partition_fixes.sql) — reaggregating only the hour
    would still read the same incomplete minute data the watermark already
    skipped. Every minute slice must run, and all of them before the hour
    call."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 8, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    bucket = datetime(2026, 8, 24, 4, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(_fixed_gap_report(bucket)))

    db = _DB()
    detail, facts = run(ms.repair_rollup_gaps(db))

    assert facts["hours_repaired"] == 1
    minute_slices = [c for c in db.calls if "sentinel_rollup_events_1m" in c[0]]
    hour_calls = [c for c in db.calls if "sentinel_rollup_events_1h" in c[0]]
    assert len(hour_calls) == 1
    expected_slices = timedelta(hours=1) // ms.GAP_REPAIR_SLICE
    assert len(minute_slices) == expected_slices
    # every minute call before the single hour call
    assert db.calls.index(hour_calls[0]) == len(db.calls) - 1
    # the slices cover the hour, back to back, without gaps or overlap
    starts = [a[0] for _, a in minute_slices]
    ends = [a[1] for _, a in minute_slices]
    assert starts[0] == bucket
    assert ends[-1] == bucket + timedelta(hours=1)
    assert starts[1:] == ends[:-1]
    # the hour call spans the whole hour, not a slice
    assert hour_calls[0][1] == (bucket, bucket + timedelta(hours=1))


def test_no_single_sql_statement_gets_a_whole_hour_interval(monkeypatch):
    """The round 2 blocker, made permanent as a test: `sentinel_rollup_events_1m`
    on a full hour of the incident's worst hour (4 329 065 rows) measured
    67-70s on the real host, over `statement_timeout_ms` (30 000ms,
    `sentinel/db/engine.py`) — the connection kills the statement, and because
    `hourly_gaps` always retries the oldest remaining gap first, every
    following pass died on the exact same hour, forever. No `_1m` call issued
    by this step is allowed to span more than `GAP_REPAIR_SLICE`; only `_1h`
    — cheap, bounded by (asset, source, action) pairs per hour, not raw row
    count — may span a full hour."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 25, 0, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    worst_hour = datetime(2026, 8, 24, 14, 0, tzinfo=timezone.utc)  # the measured 4.3M-row hour
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(_fixed_gap_report(worst_hour)))

    db = _DB()
    run(ms.repair_rollup_gaps(db))

    offenders = [
        (sql, args) for sql, args in db.calls
        if "sentinel_rollup_events_1m" in sql and (args[1] - args[0]) > ms.GAP_REPAIR_SLICE
    ]
    assert not offenders, (
        "a single sentinel_rollup_events_1m call spans more than "
        f"{ms.GAP_REPAIR_SLICE} — this is exactly the statement that timed out "
        f"at 30s on the real host's worst hour: {offenders}")


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
    hour_calls = [a[0] for sql, a in db.calls if "sentinel_rollup_events_1h" in sql]
    assert hour_calls == [b1, b2, b3]


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


# ---------------------------------------------------------------------------
# The persisted row's columns match the migration that defines them
# ---------------------------------------------------------------------------
def test_persisted_columns_match_the_migration():
    """A column renamed on one side and not the other is invisible to every
    stub-based test above (they never touch a real table) and would only
    surface on the real host as `column "..." does not exist` — the exact
    failure class `test_beacon_sql_schema.py` exists to catch for the beacon.
    This is the same check for `_persist_reconcile`, without needing a live
    Postgres: the column LIST in the INSERT must be a subset of the columns
    the migration actually declares."""
    src = ms.__file__
    text = Path(src).read_text(encoding="utf-8")
    m = re.search(
        r"INSERT INTO rollup_reconcile_runs\s*\(([^)]+)\)", text)
    assert m, "INSERT INTO rollup_reconcile_runs not found in maintenance_service.py"
    inserted = {c.strip() for c in m.group(1).replace("\n", " ").split(",")}

    migration = (
        Path(src).resolve().parents[1] / "db" / "migrations" / "0044_rollup_reconcile_runs.sql"
    )
    mig_text = migration.read_text(encoding="utf-8")
    table = re.search(
        r"CREATE TABLE rollup_reconcile_runs\s*\((.*?)\n\);", mig_text, re.S)
    assert table, "0044_rollup_reconcile_runs.sql: CREATE TABLE not found"
    declared = set()
    for line in table.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("--"):
            continue
        first = line.split()[0].rstrip(",")
        if first and not first.startswith("("):
            declared.add(first)

    missing = inserted - declared
    assert not missing, (
        f"_persist_reconcile inserts columns the migration never declares: {missing}")
