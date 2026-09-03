"""Reconciliation between `event_rollup_1h` and the raw rows it summarizes.

`maintenance_service.rollup_events` advances a watermark forward and never
revisits an hour once it has passed it — see that module's docstring for why
(the watermark is derived from the data itself, on purpose). A row ingested
with a `ts` inside an hour the watermark has already left is therefore never
rolled up, silently, no matter how much later it arrives. This module answers
one question: which already-settled hours does that leave wrong, and by how
much — nothing here writes anything.

## The trap this has to avoid

`event_rollup_1h` keeps history for longer than `raw_events` does
(`rollup_1h_days` vs `raw_events_days` in `sentinel.config`), on purpose — that
is what a rollup is for. So an hour where the aggregate has rows and the raw
table has none is not a gap, it is retention doing its job, and comparing
outside the window where raw data is actually known to still exist would
report that every night, forever. Callers MUST derive `lower` from where raw
data provably still lives (`analytics.reports.raw_coverage`, read from the
partition catalog) and never from a retention setting, which says what SHOULD
be kept, not what IS.

The comparison is therefore one-directional by construction: it only ever
flags `raw_n > rollup_n`. The opposite direction is never a finding.

## Who calls this, and how often

`maintenance_service.repair_rollup_gaps` calls it once per hourly pass and
persists what it finds to `rollup_reconcile_runs` (migration 0044).
`sentinel/selfcheck/checks.py::check_rollup_reconcile` reads that persisted row
— it does NOT call `hourly_gaps` itself. A self-check that reruns a
whole-window aggregate on its own cadence (every few minutes) rather than
reading what the hourly job already computed is the exact shape of a
previously measured incident: the dashboard went slow because its own
five-minute check kept re-running expensive aggregates over `raw_events`.
Measured cost of this query at the real 728h window: 1.5-2s warm, 13-15s cold
— cheap once an hour, not cheap 288 times a day for an answer that only
changes once an hour.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sentinel.db.engine import Database

#: The query both `maintenance_service.py` and (indirectly, through the row it
#: persists) `sentinel/selfcheck/checks.py` rely on, kept in one place so "what
#: counts as a gap" is defined exactly once. All four aggregates —
#: `count(*) OVER()`, `sum(...) OVER()`, and the two `first_value(...) OVER
#: (ORDER BY ...)` calls that find the WORST hour — are computed over the FULL
#: matching set before `LIMIT` clips the returned rows (window functions run
#: before `LIMIT` in the standard, and Postgres follows it), so `total_hours`,
#: `total_missing`, `worst_bucket` and `worst_missing` stay accurate even when
#: `limit` is small and only a sample of the actual gap hours comes back.
#: `tests/unit/test_rollup_reconcile_sql.py` runs this exact text against a
#: translated SQLite to prove the mismatch logic and both guarantees, not just
#: that the table names are right.
HOURLY_GAPS_SQL = """
    WITH raw_h AS (
        SELECT date_trunc('hour', ts) AS bucket, count(*) AS raw_n
          FROM raw_events
         WHERE ts >= $1 AND ts < $2
         GROUP BY 1
    ), roll_h AS (
        SELECT bucket, sum(n) AS rollup_n
          FROM event_rollup_1h
         WHERE bucket >= $1 AND bucket < $2
         GROUP BY 1
    ), gaps AS (
        SELECT raw_h.bucket AS bucket,
               raw_h.raw_n AS raw_n,
               COALESCE(roll_h.rollup_n, 0)::bigint AS rollup_n
          FROM raw_h
          LEFT JOIN roll_h ON roll_h.bucket = raw_h.bucket
         WHERE raw_h.raw_n > COALESCE(roll_h.rollup_n, 0)
    )
    SELECT bucket, raw_n, rollup_n,
           count(*) OVER() AS total_hours,
           sum(raw_n - rollup_n) OVER() AS total_missing,
           first_value(bucket) OVER (
               ORDER BY (raw_n - rollup_n) DESC, bucket ASC) AS worst_bucket,
           first_value(raw_n - rollup_n) OVER (
               ORDER BY (raw_n - rollup_n) DESC, bucket ASC) AS worst_missing
      FROM gaps
     ORDER BY bucket ASC
     LIMIT $3
"""


@dataclass(frozen=True)
class GapHour:
    bucket: datetime
    raw_n: int
    rollup_n: int

    @property
    def missing(self) -> int:
        return self.raw_n - self.rollup_n


@dataclass(frozen=True)
class GapReport:
    """`hours` is a sample, oldest first, bounded by the caller's `limit` — the
    order a repair should act in, because an old gap races raw retention.

    `total_hours` and `total_missing` describe the WHOLE window, not just the
    sample. `worst_bucket`/`worst_missing` name the single hour with the most
    missing rows across the WHOLE window too, which is not necessarily in
    `hours` at all if the true worst hour is not among the oldest `limit` —
    the two questions ("what do I fix first" and "what is actually the worst
    of this") have different answers, and collapsing them showed the oldest
    hour's tiny gap to an operator while a multi-million-row gap sat unnamed a
    few hours later in the same window.
    """

    hours: list[GapHour] = field(default_factory=list)
    total_hours: int = 0
    total_missing: int = 0
    worst_bucket: datetime | None = None
    worst_missing: int = 0

    @property
    def truncated(self) -> bool:
        return self.total_hours > len(self.hours)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


async def hourly_gaps(
    db: Database, *, lower: datetime, upper: datetime, limit: int
) -> GapReport:
    """Hours in `[lower, upper)` where `event_rollup_1h` undercounts `raw_events`.

    `upper` MUST be an hour the rollup watermark has already left behind (see
    the module docstring of `maintenance_service` — `max(bucket)` in
    `event_rollup_1h`, hour-truncated). Anything at or after that bucket may
    simply not have been rolled up YET by the run in progress, which is lag,
    not loss, and comparing it here would report a normal catch-up backlog as
    permanent data loss. `lower` MUST come from where raw data is actually
    known to still exist (see the module docstring) rather than a retention
    setting.

    An empty window (`lower >= upper`) returns an empty, zeroed report rather
    than querying — there is nothing yet for the watermark to have settled.
    """
    if lower >= upper:
        return GapReport()
    rows = await db.fetch(HOURLY_GAPS_SQL, lower, upper, limit)
    if not rows:
        return GapReport()
    hours = [
        GapHour(_as_utc(r["bucket"]), int(r["raw_n"]), int(r["rollup_n"]))
        for r in rows
    ]
    head = rows[0]
    return GapReport(
        hours=hours,
        total_hours=int(head["total_hours"]),
        total_missing=int(head["total_missing"]),
        worst_bucket=_as_utc(head["worst_bucket"]) if head["worst_bucket"] is not None else None,
        worst_missing=int(head["worst_missing"] or 0),
    )


@dataclass(frozen=True)
class ReconcileRun:
    """One row of `rollup_reconcile_runs` — what `repair_rollup_gaps` found
    and did on its last completed pass, and when. `sentinel/selfcheck/checks.py`
    reads this instead of calling `hourly_gaps` itself; see this module's
    "Who calls this" section for why."""

    checked_at: datetime
    status: str            # 'never_ran' | 'empty_window' | 'ok' | 'gaps'
    raw_exists: bool
    window_lower: datetime | None
    window_upper: datetime | None
    gap_hours: int
    rows_missing: int
    worst_bucket: datetime | None
    worst_missing: int
    hours_repaired: int


async def latest_reconcile_run(db: Database) -> ReconcileRun | None:
    """The most recent row, or `None` if `repair_rollup_gaps` has never
    completed a pass. `None` is not the same as `status == 'never_ran'`: the
    latter is itself a persisted, dated observation ("checked, and there was
    nothing to check yet"); `None` means no observation exists at all."""
    row = await db.fetchrow(
        """
        SELECT checked_at, status, raw_exists, window_lower, window_upper,
               gap_hours, rows_missing, worst_bucket, worst_missing, hours_repaired
          FROM rollup_reconcile_runs
         ORDER BY checked_at DESC
         LIMIT 1
        """)
    if row is None:
        return None
    return ReconcileRun(
        checked_at=_as_utc(row["checked_at"]),
        status=row["status"],
        raw_exists=bool(row["raw_exists"]),
        window_lower=_as_utc(row["window_lower"]) if row["window_lower"] is not None else None,
        window_upper=_as_utc(row["window_upper"]) if row["window_upper"] is not None else None,
        gap_hours=int(row["gap_hours"]),
        rows_missing=int(row["rows_missing"]),
        worst_bucket=_as_utc(row["worst_bucket"]) if row["worst_bucket"] is not None else None,
        worst_missing=int(row["worst_missing"] or 0),
        hours_repaired=int(row["hours_repaired"]),
    )
