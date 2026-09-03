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
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sentinel.db.engine import Database

#: The query both `sentinel/selfcheck/checks.py` and `maintenance_service.py`
#: run, kept in one place so "what counts as a gap" is defined exactly once.
#: `count(*) OVER()` / `sum(...) OVER()` are computed over the FULL matching
#: set before `LIMIT` clips the returned rows (window functions run before
#: `LIMIT` in the standard, and Postgres follows it) — so `total_hours` and
#: `total_missing` stay accurate even when `limit` is small and only a sample
#: of the actual gap hours comes back. `tests/unit/test_rollup_reconcile_sql.py`
#: runs this exact text against a translated SQLite to prove both the mismatch
#: logic and that guarantee, not just that the table names are right.
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
           sum(raw_n - rollup_n) OVER() AS total_missing
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
    """`hours` is a sample, oldest first, bounded by the caller's `limit`.

    `total_hours` and `total_missing` describe the WHOLE window, not just the
    sample — that split exists so a caller can act on a bounded batch
    (`maintenance_service.repair_rollup_gaps`) while still reporting the true
    size of what is left (`truncated`).
    """

    hours: list[GapHour] = field(default_factory=list)
    total_hours: int = 0
    total_missing: int = 0

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
    return GapReport(
        hours=hours,
        total_hours=int(rows[0]["total_hours"]),
        total_missing=int(rows[0]["total_missing"]),
    )
