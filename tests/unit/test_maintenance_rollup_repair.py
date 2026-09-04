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

import asyncpg
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


class _FailingDB(_DB):
    """Like `_DB`, but a `sentinel_rollup_events_1m` call whose `(start, end)`
    args satisfy `should_fail` raises `asyncio.TimeoutError` instead of
    succeeding — the exact exception shape `command_timeout` produces on the
    real connection (empty `str()`, see `maintenance_service`'s module
    docstring), used to drive the per-hour isolation and the halve-on-timeout
    retry without a real, slow Postgres."""

    def __init__(self, should_fail):
        super().__init__()
        self._should_fail = should_fail

    async def fetchval(self, sql, *args):
        self.calls.append((sql, args))
        if "sentinel_rollup_events_1m" in sql and self._should_fail(args):
            raise asyncio.TimeoutError()
        return 1


class _QueryCanceledDB(_FailingDB):
    """Like `_FailingDB`, but raises `asyncpg.exceptions.QueryCanceledError`
    instead of `asyncio.TimeoutError` — the OTHER shape a cancelled statement
    can take on the real connection, when the kernel answers the cancel
    before asyncio's own `command_timeout` fires (`_repair_minutes`'s
    docstring). Every other test in this file only ever raises
    `asyncio.TimeoutError`, so a mutation that drops `QueryCanceledError`
    from `_repair_minutes`'s `except` tuple would leave this repository
    green everywhere else while silently losing the halve-and-retry for
    this exact failure mode in production."""

    async def fetchval(self, sql, *args):
        self.calls.append((sql, args))
        if "sentinel_rollup_events_1m" in sql and self._should_fail(args):
            # A real QueryCanceledError from the server always carries a
            # message (e.g. "canceling statement due to statement timeout");
            # an empty one would make `str(exc)` itself raise inside
            # asyncpg, which is not the failure mode this class exists to
            # reproduce.
            raise asyncpg.exceptions.QueryCanceledError(
                "canceling statement due to statement timeout")
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
                      worst_bucket=None, worst_missing=0,
                      raw_n: int = 10) -> rollup_repo.GapReport:
    """`raw_n` defaults to a trivially light hour (10 rows) for tests that
    only care about branching/persistence, not about the per-statement SLICE
    `_gap_repair_slices` picks — pass a realistic `raw_n` (e.g. the measured
    4 329 065-row incident hour) for tests that assert on the SIZE of the
    `sentinel_rollup_events_1m` calls issued."""
    hours = [rollup_repo.GapHour(b, raw_n, 1) for b in buckets]
    return rollup_repo.GapReport(
        hours=hours, total_hours=total_hours or len(hours),
        total_missing=(raw_n - 1) * len(hours),
        worst_bucket=worst_bucket or (buckets[0] if buckets else None),
        worst_missing=worst_missing or (raw_n - 1))


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
# The measured, absolute bound this whole design leans on
# ---------------------------------------------------------------------------
#: Round 3's verifier measured 14 544 ms for the incident's worst hour
#: (24.08 14:00, 4 329 065 rows) sliced at one minute, worst slice (14:45)
#: 1 821 ms — WARM: from repeated runs against the same, already-cached
#: slice. Measured again on 3 September 2026 with real host load and a
#: single active connection (no contention) — COLD, the regime the timer
#: actually runs in: the SAME slice (14:45, 549 401 rows) cost
#: 17 513-30 015+ ms, sometimes literally OVER `statement_timeout_ms`
#: (30 000 ms) rather than comfortably under it. One minute is therefore
#: still the FLOOR `sentinel_rollup_events_1m` can be sliced at
#: (`GAP_REPAIR_SLICE` — going under it overwrites instead of summing, see
#: that constant's comment in `maintenance_service.py`), but it is not, by
#: itself, proof of staying under the timeout for every hour — that is why
#: `repair_rollup_gaps` also isolates a failing hour instead of letting it
#: block the rest (`test_one_failing_hour_does_not_block_the_rest_of_the_batch`
#: below) rather than leaning on the slice size alone. This is a LITERAL, not
#: `ms.GAP_REPAIR_SLICE`, on purpose: round 3 proved that a threshold
#: measured against the constant it is supposed to police is not a guard —
#: mutating `GAP_REPAIR_SLICE` from one minute to one hour moved the
#: threshold with it, and both tests below stayed green while the code
#: emitted exactly the whole-hour statement that timed out at 67-70s.
_MEASURED_SAFE_SLICE = timedelta(minutes=1)


def test_gap_repair_slice_does_not_exceed_the_measured_safe_bound():
    """`GAP_REPAIR_SLICE` itself, checked against the measured fact rather
    than trusted blindly by every other test that imports it. Falsified by
    round 3's own mutation: setting `GAP_REPAIR_SLICE = timedelta(hours=1)`
    must fail THIS test on its own, with no other test needed — one minute
    is the floor `event_rollup_1m`'s own grain allows (see the module note
    above); a slice coarser than that has not been measured against it."""
    assert ms.GAP_REPAIR_SLICE <= _MEASURED_SAFE_SLICE, (
        f"GAP_REPAIR_SLICE ({ms.GAP_REPAIR_SLICE}) exceeds the one-minute "
        f"floor ({_MEASURED_SAFE_SLICE}) that `event_rollup_1m`'s own "
        f"grain allows without corrupting data on overwrite")


# ---------------------------------------------------------------------------
# The actual repair: minute-sliced, minute before hour, per gap, oldest first
# ---------------------------------------------------------------------------
def test_each_gap_hour_reaggregates_every_minute_before_the_hour_call(monkeypatch):
    """`sentinel_rollup_events_1h` reads FROM `event_rollup_1m`, never from
    `raw_events` (0017_partition_fixes.sql) — reaggregating only the hour
    would still read the same incomplete minute data the watermark already
    skipped. Every minute slice must run, and all of them before the hour
    call — checked against the LITERAL `_MEASURED_SAFE_SLICE`, not
    `ms.GAP_REPAIR_SLICE`: a slice count or size derived from the constant
    under test would still look self-consistent if the constant were mutated
    to one hour (a single "slice" spanning the whole gap) — exactly the
    mutation round 3's verifier caught this test's previous body missing.
    `raw_n` is set to the measured incident density (4 329 065) on purpose:
    `_gap_repair_slices` would otherwise legitimately batch a light hour into
    fewer, wider calls — see `test_light_hour_batches_into_one_statement`
    for that behaviour, which this test must NOT exercise."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 8, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    bucket = datetime(2026, 8, 24, 4, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(
        _fixed_gap_report(bucket, raw_n=4_329_065)))

    db = _DB()
    detail, facts = run(ms.repair_rollup_gaps(db))

    assert facts["hours_repaired"] == 1
    minute_slices = [c for c in db.calls if "sentinel_rollup_events_1m" in c[0]]
    hour_calls = [c for c in db.calls if "sentinel_rollup_events_1h" in c[0]]
    assert len(hour_calls) == 1
    # Absolute, not `ms.GAP_REPAIR_SLICE` — see the module note above.
    for _, (s, e) in minute_slices:
        assert e - s <= _MEASURED_SAFE_SLICE, (
            f"slice {s}-{e} ({e - s}) exceeds the measured-safe bound "
            f"{_MEASURED_SAFE_SLICE}")
    # A 1-hour gap sliced no coarser than the measured-safe bound needs at
    # LEAST this many slices — arithmetic on the literal bound, not on the
    # constant under test, so a `GAP_REPAIR_SLICE` mutated to something
    # coarser (e.g. one hour, collapsing this to a single slice) is caught
    # here even if the per-slice duration check above were ever weakened.
    min_slices = timedelta(hours=1) // _MEASURED_SAFE_SLICE
    assert len(minute_slices) >= min_slices, (
        f"only {len(minute_slices)} slices for a 1-hour gap — fewer than the "
        f"{min_slices} a bound of {_MEASURED_SAFE_SLICE} requires")
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
    """The round 2 blocker, made permanent as a test — and, after round 3,
    anchored to a LITERAL rather than to `ms.GAP_REPAIR_SLICE`: measuring a
    threshold against the constant it is supposed to police means mutating
    the constant moves the threshold with it, and the test stays green.
    Round 3's verifier proved this exact failure: `GAP_REPAIR_SLICE` mutated
    from one minute to one hour made this test's previous body (which
    compared against `ms.GAP_REPAIR_SLICE`) pass while emitting the one
    whole-hour statement that costs 67-70s on the real host's worst hour
    (4 329 065 rows), against a 30 000ms connection timeout
    (`statement_timeout_ms`, `sentinel/config.py`). No `_1m` call issued by
    this step is allowed to span more than the literal one-minute bound
    below; only `_1h` — cheap, bounded by (asset, source, action) pairs per
    hour, not raw row count — may span a full hour. `raw_n` carries the
    actual measured 4 329 065 rows this time (round 2/3 never needed a
    realistic count; `_gap_repair_slices` now does)."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 25, 0, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    worst_hour = datetime(2026, 8, 24, 14, 0, tzinfo=timezone.utc)  # the measured 4.3M-row hour
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(
        _fixed_gap_report(worst_hour, raw_n=4_329_065)))

    db = _DB()
    run(ms.repair_rollup_gaps(db))

    max_slice = timedelta(minutes=1)  # literal, on purpose — NOT ms.GAP_REPAIR_SLICE
    offenders = [
        (sql, args) for sql, args in db.calls
        if "sentinel_rollup_events_1m" in sql and (args[1] - args[0]) > max_slice
    ]
    assert not offenders, (
        "a single sentinel_rollup_events_1m call spans more than "
        f"{max_slice} — this is exactly the statement that timed out "
        f"at 30s on the real host's worst hour: {offenders}")


# ---------------------------------------------------------------------------
# The slice adapts to the hour's own density (`raw_n`), not a fixed size
# picked for the worst hour — see `GAP_REPAIR_ROW_TARGET`'s comment for the
# two measured facts the threshold sits between.
# ---------------------------------------------------------------------------
def test_gap_repair_slices_batches_a_normal_hour_into_one_statement():
    """An ordinary hour (~14 000 rows, see `maintenance_service`'s module
    docstring) must not cost 60 database round trips just because the slice
    picked for the worst hour of an incident was one minute. Literal
    expected value, not `ms.GAP_REPAIR_ROW_TARGET` — a threshold checked
    against the constant it polices would stay green if that constant moved."""
    assert ms._gap_repair_slices(14_000) == 60


def test_gap_repair_slices_stays_at_one_minute_for_the_incident_hour():
    """The measured incident hour (4 329 065 rows) must still get the finest
    grain the table allows — batching it up would reintroduce the round 2
    disaster (a multi-million-row statement) through the density estimate
    instead of through `GAP_REPAIR_SLICE` directly."""
    assert ms._gap_repair_slices(4_329_065) == 1


def test_gap_repair_slices_falls_between_the_two_measured_facts():
    """A density between the safe slice (13 767 rows/minute, 3 027 ms) and
    the one that timed out (549 401 rows/minute) must batch a FEW minutes
    per statement, not 60 and not 1 — proving the threshold actually varies
    with density instead of being a disguised constant."""
    assert ms._gap_repair_slices(600_000) == 5


def test_light_hour_batches_into_one_statement(monkeypatch):
    """The other half of `test_no_single_sql_statement_gets_a_whole_hour_interval`:
    a light hour is legitimately safe to reaggregate in one statement, and
    failing to batch it would mean every ordinary hourly pass pays 60 round
    trips for a query that costs milliseconds — see `GAP_REPAIR_ROW_TARGET`."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 8, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    bucket = datetime(2026, 8, 24, 4, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(
        _fixed_gap_report(bucket, raw_n=14_000)))

    db = _DB()
    detail, facts = run(ms.repair_rollup_gaps(db))

    minute_slices = [a for sql, a in db.calls if "sentinel_rollup_events_1m" in sql]
    assert len(minute_slices) == 1, (
        f"a 14 000-row hour was sliced into {len(minute_slices)} statements "
        "instead of one — the slice did not adapt to the hour's density")
    (s, e) = minute_slices[0]
    assert (s, e) == (bucket, bucket + timedelta(hours=1))
    assert facts["hours_repaired"] == 1


# ---------------------------------------------------------------------------
# One hour's failure must not block the rest of the sample, and progress
# must still be persisted — the bug active in production on 3 September 2026:
# hour 14:00 failed every pass, its `asyncio.TimeoutError` propagated out of
# `repair_rollup_gaps` before any `_persist_reconcile` call, so the pass
# looked like it never ran even though 745 000 rows had already been fixed,
# and the 14 newer hours behind it were never attempted at all.
# ---------------------------------------------------------------------------
def test_one_failing_hour_does_not_block_the_rest_of_the_batch(monkeypatch):
    """A gap hour that cannot be repaired (persistent timeout, e.g. the
    single-minute density is itself too heavy) must not stop the newer hours
    in the same sample from being tried — `hourly_gaps` always returns the
    OLDEST gaps first, so without isolation a permanently-stuck oldest hour
    would starve every hour behind it, forever."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 25, 0, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    bad = datetime(2026, 8, 24, 14, 0, tzinfo=timezone.utc)
    good = datetime(2026, 8, 24, 15, 0, tzinfo=timezone.utc)
    report = rollup_repo.GapReport(
        hours=[rollup_repo.GapHour(bad, 4_329_065, 0), rollup_repo.GapHour(good, 14_000, 0)],
        total_hours=2, total_missing=4_343_065,
        worst_bucket=bad, worst_missing=4_329_065)
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(report))

    def _should_fail(args):
        start, _end = args
        return bad <= start < bad + timedelta(hours=1)

    db = _FailingDB(_should_fail)
    detail, facts = run(ms.repair_rollup_gaps(db))

    assert facts["hours_repaired"] == 1, "the good hour must be repaired even though the bad one failed"
    assert good.isoformat() in facts["hours"]
    assert facts["hours_failed"], "the failed hour must be named, not silently dropped"
    assert facts["hours_failed"][0]["bucket"] == bad.isoformat()
    assert facts["hours_failed"][0]["detail"], (
        "an asyncio.TimeoutError has an empty str() — the detail must fall "
        "back to something non-empty, or the log entry is the same blank "
        "'detail': '' that hid this bug in production")
    hour_calls = [a for sql, a in db.calls if "sentinel_rollup_events_1h" in sql]
    assert (good, good + timedelta(hours=1)) in hour_calls
    assert (bad, bad + timedelta(hours=1)) not in hour_calls, (
        "_1h must never be called for an hour whose minutes were not all "
        "written successfully")
    assert len(db.inserts) == 1, (
        "a row must still be persisted to rollup_reconcile_runs even though "
        "one hour failed — this is the exact production bug: zero rows "
        "persisted despite 745 000 real rows having been repaired")
    assert db.inserts[0][1][0] == "gaps"


def test_a_too_wide_batch_halves_down_to_minutes_and_still_succeeds(monkeypatch):
    """A wrong density guess (a low hourly average hiding one much heavier
    minute) must not leave the whole hour unrepaired just because the first
    statement chosen for it was too wide — halving has to actually recover,
    not just give up at the first failure.

    Coverage gap closed here (a real mutation on 4 September 2026 defeated
    the test's previous body): deleting the SECOND recursive call in
    `_repair_minutes` (`maintenance_service.py`, the
    `await _repair_minutes(db, mid, end, n_slices - half)` line) makes
    halving repair only the LEFT half of every split it takes, converging on
    a single leading minute while abandoning the rest of the hour. That still
    produces wide attempts, still produces at least one narrow (successful)
    call, and still calls `_1h` and counts the hour as `hours_repaired` — so
    a test that only checks THAT halving happened, never WHAT it covered,
    stays green while `event_rollup_1m` is left with 59 of 60 minutes
    unrepaired and `_1h` is aggregated over that hole. The fix mirrors
    `test_each_gap_hour_reaggregates_every_minute_before_the_hour_call`'s own
    coverage check, applied only to the successful (narrow) calls — a failed
    wide attempt wrote nothing, so it must not count as coverage."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 8, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    bucket = datetime(2026, 8, 24, 4, 0, tzinfo=timezone.utc)
    # raw_n=100 -> _gap_repair_slices picks a single whole-hour statement.
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(
        _fixed_gap_report(bucket, raw_n=100)))

    def _should_fail(args):
        start, end = args
        return (end - start) > timedelta(minutes=1)  # only the wide attempts fail

    db = _FailingDB(_should_fail)
    detail, facts = run(ms.repair_rollup_gaps(db))

    assert facts["hours_repaired"] == 1, "halving should have recovered the hour, not abandoned it"
    minute_slices = [a for sql, a in db.calls if "sentinel_rollup_events_1m" in sql]
    wide_attempts = [(s, e) for s, e in minute_slices if (e - s) > timedelta(minutes=1)]
    narrow_calls = [(s, e) for s, e in minute_slices if (e - s) == timedelta(minutes=1)]
    assert wide_attempts, (
        "the first attempt must be wider than one minute, or this test does "
        "not actually exercise the halving path")
    assert narrow_calls, "halving must eventually reach one-minute statements"
    assert any("sentinel_rollup_events_1h" in sql for sql, _ in db.calls)
    # THE gap this test now closes: not just that narrow calls happened, but
    # that they cover the ENTIRE hour, back to back, without gaps. Only the
    # successful (narrow, one-minute) calls count as coverage — a wide
    # attempt that raised wrote nothing to `event_rollup_1m`.
    starts = sorted(s for s, _ in narrow_calls)
    ends = sorted(e for _, e in narrow_calls)
    assert starts[0] == bucket, (
        "the successful minute slices must start at the hour's own first minute")
    assert ends[-1] == bucket + timedelta(hours=1), (
        "the successful minute slices stop short of the end of the hour — "
        "halving repaired only part of it while `_1h` was still called and "
        "the hour was still counted as repaired")
    assert starts[1:] == ends[:-1], (
        "the successful minute slices must tile the hour back to back, "
        "without gaps or overlaps between them")


def test_a_single_minute_that_never_succeeds_is_not_split_further(monkeypatch):
    """Below one minute, `sentinel_rollup_events_1m` would overwrite instead
    of summing (`event_rollup_1m`'s bucket is `date_trunc('minute', ts)`,
    upserted with `SET n = EXCLUDED.n` — see `GAP_REPAIR_SLICE`'s comment).
    A minute that fails even alone must therefore stop halving and leave the
    hour named-unrepaired, not invent a sub-minute slice that would silently
    drop half its rows."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 25, 0, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    bucket = datetime(2026, 8, 24, 14, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(
        _fixed_gap_report(bucket, raw_n=4_329_065)))

    db = _FailingDB(lambda args: True)  # every _1m call fails, at any size
    detail, facts = run(ms.repair_rollup_gaps(db))

    assert facts["hours_repaired"] == 0
    assert facts["hours_failed"][0]["bucket"] == bucket.isoformat()
    minute_slices = [a for sql, a in db.calls if "sentinel_rollup_events_1m" in sql]
    assert len(minute_slices) == 1, (
        "a minute that fails even alone must not be split further — no "
        f"retry below the table's own grain, but got {len(minute_slices)} attempts")
    assert minute_slices[0] == (bucket, bucket + timedelta(minutes=1))
    assert not any("sentinel_rollup_events_1h" in sql for sql, _ in db.calls), (
        "_1h must not be called when the hour's minutes were never all written")


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


def test_query_canceled_error_triggers_the_same_halving_as_timeout(monkeypatch):
    """`asyncpg.exceptions.QueryCanceledError` is the OTHER exception shape a
    cancelled statement can raise on the real connection (see
    `_repair_minutes`'s docstring) — every other test in this file only ever
    raises `asyncio.TimeoutError`. A mutation dropping `QueryCanceledError`
    from `_repair_minutes`'s `except` tuple leaves the rest of the suite
    green while this exact failure mode skips halving entirely: the
    exception propagates straight out of `_repair_hour` and the per-hour
    `try/except` in `repair_rollup_gaps` marks a RECOVERABLE hour as failed
    instead of repairing it."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 8, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    bucket = datetime(2026, 8, 24, 4, 0, tzinfo=timezone.utc)
    # raw_n=100 -> _gap_repair_slices picks a single whole-hour statement,
    # same setup as the TimeoutError halving test above.
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(
        _fixed_gap_report(bucket, raw_n=100)))

    def _should_fail(args):
        start, end = args
        return (end - start) > timedelta(minutes=1)

    db = _QueryCanceledDB(_should_fail)
    detail, facts = run(ms.repair_rollup_gaps(db))

    assert facts["hours_repaired"] == 1, (
        "QueryCanceledError must trigger the same halve-and-retry as "
        "asyncio.TimeoutError — a recoverable hour was marked failed instead")
    assert not facts["hours_failed"]


# ---------------------------------------------------------------------------
# Nothing repaired is not success — operator decision, 4 September 2026. A
# pass where every sampled hour failed used to report `ok: true` at the step
# level, the failure visible only as a `WARNING` log line. Before per-hour
# isolation existed, the same collapse exited the step non-zero and systemd
# showed the unit `failed` in `systemctl` — the signal regressed exactly when
# the isolation that fixed the OTHER production bug was added.
# ---------------------------------------------------------------------------
def test_step_reports_failure_when_nothing_was_repaired_but_something_failed(monkeypatch):
    """Prevents the unit going quiet on a total failure: with every gap hour
    in the sample failing, the pass must not exit as `ok`, or an operator
    reading `systemctl status` sees a healthy unit while zero rows got
    fixed and the gap keeps racing raw retention."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 25, 0, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    b1 = datetime(2026, 8, 24, 14, 0, tzinfo=timezone.utc)
    b2 = datetime(2026, 8, 24, 15, 0, tzinfo=timezone.utc)
    report = rollup_repo.GapReport(
        hours=[rollup_repo.GapHour(b1, 4_329_065, 0), rollup_repo.GapHour(b2, 4_329_065, 0)],
        total_hours=2, total_missing=8_658_130,
        worst_bucket=b1, worst_missing=4_329_065)
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(report))

    db = _FailingDB(lambda args: True)  # every _1m call fails, at any size
    step_report = ms.Report()
    result = run(ms._step(step_report, "repair_rollup_gaps", ms.repair_rollup_gaps(db)))

    assert result.ok is False, (
        "a pass that repaired zero hours out of a fully-failed sample must "
        "not report ok=True at the step level")
    assert step_report.failed, "Report.failed must be non-empty so `_main` exits 1"
    assert "ok" not in result.facts, (
        "\"ok\" must be consumed by _step, not leak into the stored facts "
        "next to StepResult.ok")


def test_step_stays_ok_when_at_least_one_hour_was_repaired(monkeypatch):
    """The new failure signal must not fire on a PARTIAL success — that is
    exactly the isolation behaviour decision 2 keeps unchanged. Reusing the
    production bug's own scenario (one stuck hour, one good hour behind it)."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 25, 0, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    bad = datetime(2026, 8, 24, 14, 0, tzinfo=timezone.utc)
    good = datetime(2026, 8, 24, 15, 0, tzinfo=timezone.utc)
    report = rollup_repo.GapReport(
        hours=[rollup_repo.GapHour(bad, 4_329_065, 0), rollup_repo.GapHour(good, 14_000, 0)],
        total_hours=2, total_missing=4_343_065,
        worst_bucket=bad, worst_missing=4_329_065)
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(report))

    def _should_fail(args):
        start, _end = args
        return bad <= start < bad + timedelta(hours=1)

    db = _FailingDB(_should_fail)
    step_report = ms.Report()
    result = run(ms._step(step_report, "repair_rollup_gaps", ms.repair_rollup_gaps(db)))

    assert result.ok is True, "a partial success must not be reported as a failed step"
    assert not step_report.failed


def test_step_stays_ok_when_there_is_nothing_to_repair(monkeypatch):
    """The new failure signal must not fire when there was simply nothing
    wrong — a healthy gapless pass must not start showing up as `failed`."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(rollup_repo.GapReport()))

    db = _DB()
    step_report = ms.Report()
    result = run(ms._step(step_report, "repair_rollup_gaps", ms.repair_rollup_gaps(db)))

    assert result.ok is True
    assert not step_report.failed


# ---------------------------------------------------------------------------
# Time budget on the sample — operator decision, 4 September 2026. A low
# hourly average hiding one much heavier minute can cost up to seven
# halvings (~30s each) for a SINGLE hour; eight such hours would outrun the
# unit's own TimeoutStartSec (900s, `deploy/systemd/sentinel-maintenance.service`)
# before `_persist_reconcile` ever runs — see `GAP_REPAIR_TIME_BUDGET_S`'s
# comment for the full arithmetic. The clock is injected so this does not
# depend on real elapsed time.
# ---------------------------------------------------------------------------
def test_time_budget_defers_remaining_hours_to_the_next_pass(monkeypatch):
    """Prevents the unit being killed mid-repair: without a budget on the
    sample, a run of slow hours can keep going past `TimeoutStartSec` before
    writing anything to `rollup_reconcile_runs` — the exact defect this step
    exists to fix, reintroduced through the SAMPLE instead of through a
    single SQL statement. Hours past the budget must be named as deferred,
    not silently dropped, and picked up oldest-first on the next pass."""
    monkeypatch.setattr(report_repo, "rollup_coverage", _async(
        {"never_ran": False, "latest": datetime(2026, 8, 27, 0, 0, tzinfo=timezone.utc)}))
    monkeypatch.setattr(report_repo, "raw_coverage", _async(
        datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)))
    b1 = datetime(2026, 8, 24, 4, 0, tzinfo=timezone.utc)
    b2 = datetime(2026, 8, 24, 5, 0, tzinfo=timezone.utc)
    b3 = datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(rollup_repo, "hourly_gaps", _async(_fixed_gap_report(b1, b2, b3)))

    # started_at=0.0; check before b1: 0.0 (within budget); check before b2:
    # 400.0 (300s literal budget already spent) -> b2 and b3 deferred.
    clock_readings = iter([0.0, 0.0, 400.0])

    def fake_clock():
        try:
            return next(clock_readings)
        except StopIteration:
            return 400.0

    avertismente: list[dict] = []
    monkeypatch.setattr(ms.log, "warning",
                        lambda msg, **kw: avertismente.append(kw.get("extra") or {}))

    db = _DB()
    detail, facts = run(ms.repair_rollup_gaps(db, now_monotonic=fake_clock))

    assert facts["hours_repaired"] == 1, (
        "only the hour whose turn came before the time budget ran out "
        "should have been attempted")
    assert facts["hours_deferred"] == [b2.isoformat(), b3.isoformat()], (
        "hours past the time budget must be named as deferred, not "
        "silently dropped from the count")
    assert "amânate de plafonul de timp" in detail
    hour_calls = [a[0] for sql, a in db.calls if "sentinel_rollup_events_1h" in sql]
    assert hour_calls == [b1], (
        "no _1h call should have been issued for the deferred hours")
    # Orele amânate sunt încă DE FĂCUT, deci intră în restul raportat prin
    # `hours_left`. Scăzându-le, restul devine ZERO aici (3 − 1 − 2), `if left:`
    # nu se mai declanșează, și avertismentul „mai rămân ore" dispare cu totul
    # — tocmai tăcerea pe care pasul ăsta există ca s-o repare, fiindcă orele
    # rămase concurează cu retenția brutului.
    #
    # Literalul 2, nu `total_hours - hours_repaired`: o aserțiune scrisă cu
    # aceeași aritmetică pe care o păzește trece indiferent ce face codul.
    cu_rest = [a for a in avertismente if "hours_left" in a]
    assert cu_rest, (
        "cu ore amânate, avertismentul «mai rămân ore» trebuie emis; altfel "
        f"restul de făcut nu ajunge nicăieri. Avertismente: {avertismente}")
    assert cu_rest[0]["hours_left"] == 2, (
        f"restul trebuie să numere orele amânate: {cu_rest[0]}")


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
