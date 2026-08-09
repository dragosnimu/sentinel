"""The report aggregation layer.

Every test here names a way the reports page could lie to the operator. The two
that matter most, because they are the ones that look fine on screen:

  * a bucket the database no longer holds rendered as a bar of height zero,
    which reads as "nothing attacked us that month" when the truth is "that
    month was dropped by retention";
  * a time series built from `raw_events` instead of the hourly rollup, which
    turns opening a report into a scan of a month of daily partitions on the
    same database detection is trying to read.

A stub DB records the SQL it is handed and answers from canned rows — enough to
pin which table a query reads and which columns it groups by, without a live
PostgreSQL. It does not and cannot prove the SQL is accepted by Postgres; the
statements are exercised against the real database by the verifier.
"""

from __future__ import annotations

import ast
import asyncio
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.analytics import reports

REPO = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 9, 14, 37, tzinfo=timezone.utc)


def run(coro):
    return asyncio.run(coro)


class _StubDB:
    """Records every statement, answers from `fetch_map` / `row_map` / `val_map`
    keyed on a distinctive SQL fragment."""

    def __init__(self, fetch_map=None, row_map=None, val_map=None):
        self.fetch_map = fetch_map or {}
        self.row_map = row_map or {}
        self.val_map = val_map or {}
        self.sql: list[str] = []

    async def fetch(self, sql, *a):
        self.sql.append(sql)
        for needle, rows in self.fetch_map.items():
            if needle in sql:
                return rows
        return []

    async def fetchrow(self, sql, *a):
        self.sql.append(sql)
        for needle, row in self.row_map.items():
            if needle in sql:
                return row
        return None

    async def fetchval(self, sql, *a):
        self.sql.append(sql)
        for needle, val in self.val_map.items():
            if needle in sql:
                return val
        return None


# ---------------------------------------------------------------------------
# Bucket arithmetic
# ---------------------------------------------------------------------------
def test_week_buckets_start_on_monday_like_postgres():
    """The chart labels a bar "week of X" but the SQL fills it with
    `date_trunc('week', …)`, which is Monday-based. If Python truncated to
    Sunday, every weekly bar would be labelled with one week and filled with
    another, and nothing on the page would say so."""
    # 9 Aug 2026 is a Sunday.
    assert NOW.weekday() == 6
    start = reports.truncate(NOW, "week")
    assert start.weekday() == 0                     # Monday
    assert start == datetime(2026, 8, 3, tzinfo=timezone.utc)


def test_month_and_year_truncation_land_on_the_first():
    assert reports.truncate(NOW, "month") == datetime(2026, 8, 1, tzinfo=timezone.utc)
    assert reports.truncate(NOW, "year") == datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_month_step_crosses_the_year_boundary_both_ways():
    """Naive month arithmetic (month ± 1) throws on December and January. A
    report opened in January would 500 instead of showing last year."""
    jan = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert reports.advance(jan, "month", -1) == datetime(2025, 12, 1, tzinfo=timezone.utc)
    dec = datetime(2026, 12, 1, tzinfo=timezone.utc)
    assert reports.advance(dec, "month", 1) == datetime(2027, 1, 1, tzinfo=timezone.utc)


def test_month_step_from_a_31_day_month_does_not_overflow():
    """31 January minus a month is not 31 February. Anchoring on day 1 is what
    keeps the bucket list from raising ValueError halfway through building."""
    starts = reports.bucket_starts("month", now=datetime(2026, 3, 31, tzinfo=timezone.utc),
                                   count=4)
    assert [s.month for s in starts] == [12, 1, 2, 3]
    assert all(s.day == 1 for s in starts)


def test_bucket_list_is_contiguous_ascending_and_ends_with_now():
    starts = reports.bucket_starts("day", now=NOW, count=5)
    assert len(starts) == 5
    assert starts == sorted(starts)
    assert starts[-1] == reports.truncate(NOW, "day")
    for a, b in zip(starts, starts[1:]):
        assert reports.advance(a, "day", 1) == b


def test_every_declared_bucket_stays_under_fifty_columns():
    """A chart with hundreds of columns is unreadable AND makes the aggregate
    scan grow for nothing. The span is the only thing bounding either."""
    assert reports.BUCKETS, "the bucket table came out empty"
    for key, spec in reports.BUCKETS.items():
        assert 0 < spec.span <= 50, f"{key} charts {spec.span} buckets"
        # The key IS the date_trunc field. A mismatch would truncate on one unit
        # and lay the axis out on another.
        assert spec.unit == key


# ---------------------------------------------------------------------------
# Unknown is not zero
# ---------------------------------------------------------------------------
def _starts(count=5, unit="day"):
    return reports.bucket_starts(unit, now=NOW, count=count)


def test_buckets_before_retention_are_unknown_not_zero():
    """THE failure this module exists to prevent. `event_rollup_1h` is trimmed
    after 400 days and `raw_events` partitions after 30; a bucket older than
    what is kept must not draw a zero bar, because a zero bar says "nothing
    happened" about a period nobody can see any more."""
    starts = _starts(5)
    series = reports.build_series(
        [], unit="day", starts=starts,
        known_from=starts[2], complete_to=NOW + timedelta(days=1),
        known_to=NOW + timedelta(days=1), fallbacks=reports.NO_FALLBACK,
    )
    assert series.state[0] == reports.UNKNOWN
    assert series.state[1] == reports.UNKNOWN
    assert series.state[2] == reports.KNOWN
    assert series.has_unknown


def test_the_bucket_where_coverage_begins_is_partial_not_whole():
    """Coverage starting mid-bucket means that bucket holds part of its own
    history. Calling it `known` would present a truncated count as complete."""
    starts = _starts(5)
    mid = starts[2] + timedelta(hours=6)
    series = reports.build_series(
        [], unit="day", starts=starts, known_from=mid,
        complete_to=NOW + timedelta(days=1), known_to=NOW + timedelta(days=1), fallbacks=reports.NO_FALLBACK)
    assert series.state[2] == reports.PARTIAL
    assert series.state[3] == reports.KNOWN


def _rollup_cov(*, earliest: datetime, latest: datetime, now: datetime | None = None) -> dict:
    """`rollup_coverage()` over the shape PostgreSQL really returns.

    `max(bucket)` is always on a bucket boundary, because `bucket` is
    `date_trunc('hour', …)`. The first version of the guard below handed
    `build_series` a mid-hour edge instead — a shape the router cannot produce —
    so it passed while the newest column of every hourly chart was rendered as
    "no data kept". The coverage dict is therefore built by the real function,
    from a boundary-aligned value, and the edges by the real `event_edges`.
    """
    db = _StubDB(row_map={"FROM event_rollup_1h": {"earliest": earliest, "latest": latest}})
    return run(reports.rollup_coverage(db, now=now)) if now else run(
        reports.rollup_coverage(db))


def test_rollup_coverage_reaches_the_end_of_the_last_bucket_not_its_start():
    """`event_rollup_1h.bucket` is a bucket START. Treating `max(bucket)` as the
    edge of the data understates coverage by exactly one hour — which is the
    whole newest column of an hourly chart."""
    latest = datetime(2026, 8, 9, 6, tzinfo=timezone.utc)
    cov = _rollup_cov(earliest=latest - timedelta(days=40), latest=latest)
    assert cov["latest"] == latest
    assert cov["covered_to"] == datetime(2026, 8, 9, 7, tzinfo=timezone.utc)

    now = datetime(2026, 8, 9, 6, 37, tzinfo=timezone.utc)
    known_from, complete_to, known_to = reports.event_edges(cov, now=now)
    assert known_to == cov["covered_to"]      # data reaches an hour past the row
    assert complete_to == latest              # but is only FINAL up to the row


def test_the_newest_aggregated_hour_is_drawn_not_hatched():
    """The failure the verifier caught on the live host: a bucket holding 100
    events rendered as a hatched "no data kept" column, with no drill-down link,
    while the page header total disagreed with the sum of the bars — on the page
    whose stated purpose is that unknown and zero are different things.

    Built from `rollup_coverage` → `event_edges` → `build_series`, which is the
    exact chain the handler runs.
    """
    now = datetime(2026, 8, 9, 6, 37, tzinfo=timezone.utc)
    starts = reports.bucket_starts("hour", now=now, count=6)
    cov = _rollup_cov(earliest=starts[0], latest=starts[-1])
    known_from, complete_to, known_to = reports.event_edges(cov, now=now)

    series = reports.build_series(
        [_row(starts[-1], "nginx", 100)], unit="hour", starts=starts,
        known_from=known_from, complete_to=complete_to, known_to=known_to, fallbacks=reports.NO_FALLBACK)

    assert series.state[-1] == reports.PARTIAL, series.state
    chart = reports.build_chart(series, drill={"kind": "events", "dim": "source",
                                               "bucket": "hour"})
    assert chart.gaps == []
    assert [s.n for s in chart.segments] == [100]
    assert chart.segments[0].href, "the newest bucket lost its drill-down link"


def test_the_current_day_is_drawn_even_in_the_first_hour_of_the_day():
    """The daily version of the same bug, which fired deterministically once a
    day: at 00:xx UTC `max(bucket)` equals the start of today's day bucket, so
    `start >= known_to` held and today was hatched."""
    now = datetime(2026, 8, 9, 0, 12, tzinfo=timezone.utc)
    starts = reports.bucket_starts("day", now=now, count=5)
    cov = _rollup_cov(earliest=starts[0], latest=reports.truncate(now, "hour"))
    known_from, complete_to, known_to = reports.event_edges(cov, now=now)
    series = reports.build_series(
        [_row(starts[-1], "sshd", 7)], unit="day", starts=starts,
        known_from=known_from, complete_to=complete_to, known_to=known_to, fallbacks=reports.NO_FALLBACK)
    assert series.state[-1] == reports.PARTIAL
    assert reports.build_chart(series).gaps == []


def test_the_current_bucket_is_partial_because_it_is_still_filling():
    """Today is not over, and the newest rollup row is rewritten by the next
    maintenance pass. Drawing either as a finished bar invites "attacks dropped
    today" from a day that is four hours old."""
    now = datetime(2026, 8, 9, 6, 37, tzinfo=timezone.utc)
    starts = reports.bucket_starts("day", now=now, count=5)
    cov = _rollup_cov(earliest=starts[0], latest=reports.truncate(now, "hour"))
    known_from, complete_to, known_to = reports.event_edges(cov, now=now)
    series = reports.build_series(
        [], unit="day", starts=starts,
        known_from=known_from, complete_to=complete_to, known_to=known_to, fallbacks=reports.NO_FALLBACK)
    assert series.state[-1] == reports.PARTIAL
    assert series.state[-2] == reports.KNOWN


def test_a_stale_rollup_marks_the_hours_it_has_not_reached_as_pending():
    """When the aggregation has not reached a bucket, the rows are still in
    `raw_events` — nothing was deleted. `pending`, not `unknown`."""
    now = datetime(2026, 8, 9, 6, 37, tzinfo=timezone.utc)
    starts = reports.bucket_starts("hour", now=now, count=6)
    cov = _rollup_cov(earliest=starts[0], latest=starts[2])      # stopped at 03:00
    known_from, complete_to, known_to = reports.event_edges(cov, now=now)
    series = reports.build_series(
        [], unit="hour", starts=starts,
        known_from=known_from, complete_to=complete_to, known_to=known_to, fallbacks=reports.NO_FALLBACK)
    assert series.state[:2] == [reports.KNOWN, reports.KNOWN]
    assert series.state[2] == reports.PARTIAL       # the half-written watermark hour
    assert series.state[3:] == [reports.PENDING] * 3
    assert not series.has_unknown


def test_the_newest_hour_is_pending_when_the_rollup_has_not_written_it_yet():
    """The live state the verifier caught at 07:35 UTC: `max(bucket)` was 06:00
    because the maintenance run fired at 07:00:07, seven seconds into the hour,
    before a single minute bucket for 07:00 existed. Retention is 400 days and
    `retention_rollups` had trimmed nothing — yet the column was hatched "fără
    date păstrate".

    The timer's start second drifts across runs (:00:06, :02:16, :03:07 in the
    journal), so this is the common case, not an edge one. A hatch that appears
    at the right-hand edge most hours is a hatch nobody reads — and it is the
    only mark that says a month really was dropped.
    """
    now = datetime(2026, 8, 9, 7, 35, tzinfo=timezone.utc)
    starts = reports.bucket_starts("hour", now=now, count=4)
    cov = _rollup_cov(earliest=starts[0] - timedelta(days=40),
                      latest=datetime(2026, 8, 9, 6, tzinfo=timezone.utc))
    known_from, complete_to, known_to = reports.event_edges(cov, now=now)
    series = reports.build_series(
        [_row(s, "nginx", 40) for s in starts[:-1]], unit="hour", starts=starts,
        known_from=known_from, complete_to=complete_to, known_to=known_to, fallbacks=reports.NO_FALLBACK)

    assert series.state[-1] == reports.PENDING
    assert not series.has_unknown, "nothing was deleted; nothing may be hatched"
    assert series.has_pending

    chart = reports.build_chart(series)
    kinds = [g.kind for g in chart.gaps]
    assert kinds == [reports.PENDING]
    assert "încă neagregat" in chart.gaps[0].title
    assert "fără date păstrate" not in chart.gaps[0].title


def test_the_thirty_to_ninety_day_band_is_recoverable_and_says_so():
    """The band the verifier measured, and the claim that was wrong in it.

    `sentinel_rollup_events_1h` reads `FROM event_rollup_1m` — it never touches
    `raw_events` — and the retentions are 30 days of raw, 90 of minutes. So a
    bucket 40 days old that the hourly rollup never reached has no raw detail
    and every one of its minutes still on disk: one repaired maintenance run
    rebuilds the bar exactly.

    It used to be hatched and described as "nu a mai rămas nimic de arătat",
    which points the operator at writing the period off instead of at restarting
    the timer. Reproduced as a rollup outage does it: the hourly table stalled
    90 days back, the minute table full.
    """
    now = datetime(2026, 8, 9, 6, 37, tzinfo=timezone.utc)
    starts = reports.bucket_starts("day", now=now, count=30)
    fb = reports.Fallbacks(
        raw_from=reports.truncate(now - timedelta(days=25), "day"),
        minute_from=reports.truncate(now - timedelta(days=90), "day"),
    )
    cov = _rollup_cov(earliest=now - timedelta(days=400),
                      latest=reports.truncate(now - timedelta(days=90), "hour"),
                      now=now)
    known_from, complete_to, known_to = reports.event_edges(cov, now=now)
    series = reports.build_series(
        [], unit="day", starts=starts,
        known_from=known_from, complete_to=complete_to, known_to=known_to,
        fallbacks=fb)

    # Nothing was aggregated, and nothing is beyond recovery: the minute table
    # covers all 30 days.
    assert series.covered_buckets == 0
    assert series.missed_buckets == 0
    assert series.pending_buckets == len(starts)

    chart = reports.build_chart(
        series, drill={"kind": "events", "dim": "source", "bucket": "day"})
    assert all(g.kind == reports.PENDING for g in chart.gaps)

    without_detail = [g for g in chart.gaps
                      if reports.advance(_gap_start(g, series), "day", 1) <= fb.raw_from]
    with_detail = [g for g in chart.gaps if g not in without_detail]
    assert without_detail and with_detail, "the scenario produced only one kind"

    for g in without_detail:
        # No list of events to offer, so no link — but the bar is coming back.
        assert g.href is None
        assert "detaliul brut a expirat" in g.title
        assert "se reface din tabela de minute" in g.title
        assert "nu a mai rămas nimic" not in g.title
    for g in with_detail:
        assert g.href
        assert "datele brute există" in g.title


def _gap_start(gap, series):
    """Recover a gap's bucket start from its x position."""
    n = len(series.starts)
    plot_w = reports.CHART_W - reports.PAD_L - reports.PAD_R
    slot = plot_w / n
    i = round((gap.x - reports.PAD_L - (slot - gap.w) / 2) / slot)
    return series.starts[i]


def test_beyond_the_minute_table_the_loss_really_is_final():
    """The other side of the same edge. Past `rollup_1m_days` there is nothing
    left to rebuild from, and `MISSED` may say so — now checked against the
    table the hourly rollup is actually built from."""
    now = datetime(2026, 8, 9, 6, 37, tzinfo=timezone.utc)
    starts = reports.bucket_starts("month", now=now, count=18)
    minute_from = reports.truncate(now - timedelta(days=90), "day")
    fb = reports.Fallbacks(
        raw_from=reports.truncate(now - timedelta(days=25), "day"),
        minute_from=minute_from)
    cov = _rollup_cov(earliest=now - timedelta(days=400),
                      latest=reports.truncate(now - timedelta(days=200), "hour"),
                      now=now)
    known_from, complete_to, known_to = reports.event_edges(cov, now=now)
    series = reports.build_series(
        [], unit="month", starts=starts,
        known_from=known_from, complete_to=complete_to, known_to=known_to,
        fallbacks=fb)

    assert series.missed_buckets and series.pending_buckets
    for s, state in zip(series.starts, series.state):
        if state in (reports.MISSED, reports.PENDING):
            end = reports.advance(s, "month", 1)
            expected = reports.MISSED if end <= minute_from else reports.PENDING
            assert state == expected, f"{s.isoformat()} -> {state}"

    chart = reports.build_chart(
        series, drill={"kind": "events", "dim": "source", "bucket": "month"})
    for g in (g for g in chart.gaps if g.kind == reports.MISSED):
        assert g.href is None
        assert "nu a mai rămas nimic" in g.title
        assert "datele brute există" not in g.title


def test_an_unknown_minute_edge_never_produces_a_final_verdict():
    """`minute_coverage` returns None when the table cannot be read. "We could
    not ask" must not render as "it is gone" — the same rule that already holds
    for the raw edge."""
    now = datetime(2026, 8, 9, 6, 37, tzinfo=timezone.utc)
    starts = reports.bucket_starts("year", now=now, count=3)
    cov = _rollup_cov(earliest=now - timedelta(days=400),
                      latest=reports.truncate(now - timedelta(days=300), "hour"),
                      now=now)
    known_from, complete_to, known_to = reports.event_edges(cov, now=now)
    series = reports.build_series(
        [], unit="year", starts=starts,
        known_from=known_from, complete_to=complete_to, known_to=known_to,
        fallbacks=reports.Fallbacks(raw_from=reports.truncate(now, "day"),
                                    minute_from=None))
    assert series.missed_buckets == 0
    assert reports.PENDING in series.state


def test_an_unreadable_partition_catalog_makes_no_claim_either_way():
    """`raw_coverage` returns None when the catalog cannot answer. "Unknown" is
    not "available": the tooltip stops asserting the rows exist, while the link
    stays — the drill page reads the edge itself and reports what it found."""
    now = datetime(2026, 8, 9, 7, 35, tzinfo=timezone.utc)
    starts = reports.bucket_starts("hour", now=now, count=4)
    cov = _rollup_cov(earliest=now - timedelta(days=40),
                      latest=datetime(2026, 8, 9, 6, tzinfo=timezone.utc), now=now)
    known_from, complete_to, known_to = reports.event_edges(cov, now=now)
    series = reports.build_series(
        [], unit="hour", starts=starts,
        known_from=known_from, complete_to=complete_to, known_to=known_to,
        fallbacks=reports.NO_FALLBACK)
    assert series.state[-1] == reports.PENDING      # not MISSED: we cannot tell
    gap = reports.build_chart(
        series, drill={"kind": "events", "dim": "source", "bucket": "hour"}).gaps[-1]
    assert "poate exista" in gap.title
    assert "datele brute există" not in gap.title
    assert gap.href


def test_every_column_falls_into_exactly_one_of_the_four_blank_or_covered_kinds():
    """All four kinds at once — the shape a long chart takes when the aggregate
    has been trimmed at one end and the timer has stalled at the other. The
    counts have to keep adding up to the column count, because the summary
    sentence is built from them."""
    now = datetime(2026, 8, 9, 6, 37, tzinfo=timezone.utc)
    starts = reports.bucket_starts("month", now=now, count=18)
    # Trimmed at 400 days, stalled 200 days back, minutes kept 90: that gap
    # between the stall and the minute edge is where MISSED lives, and it only
    # exists because the two edges are different tables.
    cov = _rollup_cov(earliest=reports.truncate(now - timedelta(days=400), "day"),
                      latest=reports.truncate(now - timedelta(days=200), "hour"),
                      now=now)
    known_from, complete_to, known_to = reports.event_edges(cov, now=now)
    series = reports.build_series(
        [], unit="month", starts=starts,
        known_from=known_from, complete_to=complete_to, known_to=known_to,
        fallbacks=reports.Fallbacks(
            raw_from=reports.truncate(now - timedelta(days=25), "day"),
            minute_from=reports.truncate(now - timedelta(days=90), "day")))

    kinds = {reports.UNKNOWN: series.unknown_buckets,
             reports.MISSED: series.missed_buckets,
             reports.PENDING: series.pending_buckets,
             "covered": series.covered_buckets}
    assert all(v > 0 for v in kinds.values()), kinds
    assert sum(kinds.values()) == len(starts)


def test_retention_still_produces_the_loud_unknown_mark():
    """The hatch has to keep meaning something where it applies."""
    starts = _starts(4)
    series = reports.build_series(
        [], unit="day", starts=starts, known_from=starts[2],
        complete_to=NOW, known_to=NOW, fallbacks=reports.NO_FALLBACK)
    assert series.state[:2] == [reports.UNKNOWN, reports.UNKNOWN]
    chart = reports.build_chart(series)
    assert {g.kind for g in chart.gaps} == {reports.UNKNOWN}
    assert "fără date păstrate" in chart.gaps[0].title


def test_an_empty_chart_counts_what_it_can_and_cannot_speak_for():
    """A young install is always the mixed case: some buckets covered and truly
    zero, the rest older than anything kept. Blaming retention for all of them
    turns "no patch has been applied in the 11 days we have" — which is
    actionable — into "data missing", which is not. On a `year` chart two
    columns stay uncovered for another two years, so every live-but-empty table
    got the wrong sentence."""
    starts = _starts(30)
    series = reports.build_series(
        [], unit="day", starts=starts, known_from=starts[19],
        complete_to=NOW, known_to=NOW, fallbacks=reports.NO_FALLBACK)
    assert series.empty
    assert series.covered_buckets == 11
    assert series.unknown_buckets == 19
    assert series.pending_buckets == 0
    assert series.covered_buckets + series.unknown_buckets == len(starts)


def test_the_header_total_always_equals_the_sum_of_the_drawn_bars():
    """The observable symptom of the blocker was `4800` in the header over
    `4700` worth of bars. Whatever the edges say, a page that contradicts itself
    is a page nobody can trust — so this holds for every state combination."""
    now = datetime(2026, 8, 9, 6, 37, tzinfo=timezone.utc)
    starts = reports.bucket_starts("hour", now=now, count=6)
    rows = [_row(s, "nginx", 100 + i) for i, s in enumerate(starts)]
    for latest_i in range(len(starts)):
        cov = _rollup_cov(earliest=starts[0], latest=starts[latest_i])
        known_from, complete_to, known_to = reports.event_edges(cov, now=now)
        series = reports.build_series(
            rows, unit="hour", starts=starts,
            known_from=known_from, complete_to=complete_to, known_to=known_to, fallbacks=reports.NO_FALLBACK)
        chart = reports.build_chart(series)
        assert sum(s.n for s in chart.segments) == series.grand_total, latest_i


def test_a_bucket_that_holds_rows_is_never_rendered_as_a_gap():
    """Belt and braces over the edge arithmetic. `state` is inferred from
    coverage; a row count is the database stating what it holds. If they ever
    disagree again, the direct evidence wins — drawing "we kept nothing here"
    over a hundred real events is the worse of the two lies."""
    starts = _starts(3)
    series = reports.build_series(
        [_row(starts[0], "x", 5)], unit="day", starts=starts,
        # Deliberately impossible edges: coverage claims the whole span is gone.
        known_from=starts[-1] + timedelta(days=10),
        complete_to=starts[-1] + timedelta(days=10),
        known_to=starts[-1] + timedelta(days=10), fallbacks=reports.NO_FALLBACK)
    assert series.state[0] == reports.PARTIAL
    assert series.state[1:] == [reports.UNKNOWN, reports.UNKNOWN]
    assert reports.build_chart(series).segments


def test_no_coverage_at_all_means_everything_is_unknown():
    """A rollup that has never run answers `min(bucket) = NULL`. Every bucket is
    then unknown — the page must not render a flat zero line and let the
    operator conclude the server is quiet."""
    starts = _starts(4)
    series = reports.build_series([], unit="day", starts=starts,
                                  known_from=None, complete_to=None, known_to=None, fallbacks=reports.NO_FALLBACK)
    assert set(series.state) == {reports.UNKNOWN}


def test_a_covered_bucket_with_no_rows_is_a_real_zero():
    """The other side of the same coin: inside the covered range, empty really
    does mean nothing happened, and it must be drawn as such."""
    starts = _starts(3)
    series = reports.build_series(
        [], unit="day", starts=starts,
        known_from=starts[0] - timedelta(days=1),
        complete_to=NOW + timedelta(days=1), known_to=NOW + timedelta(days=1), fallbacks=reports.NO_FALLBACK)
    assert set(series.state) == {reports.KNOWN}
    assert not series.has_unknown
    assert series.empty


# ---------------------------------------------------------------------------
# Series shape
# ---------------------------------------------------------------------------
def _row(b, k, n):
    return {"b": b.replace(tzinfo=None), "k": k, "n": n}


def test_a_quiet_bucket_keeps_its_column():
    """Postgres returns no row for a bucket with no events. If the series only
    held the rows it received, a quiet Tuesday would vanish and Wednesday would
    slide into its place — the shape of the week would be a fiction."""
    starts = _starts(4)
    series = reports.build_series(
        [_row(starts[0], "sshd", 5), _row(starts[3], "sshd", 7)],
        unit="day", starts=starts, known_from=starts[0],
        complete_to=NOW + timedelta(days=1), known_to=NOW + timedelta(days=1), fallbacks=reports.NO_FALLBACK)
    assert series.counts["sshd"] == [5, 0, 0, 7]
    assert series.per_bucket == [5, 0, 0, 7]
    assert series.grand_total == 12


def test_severity_keeps_its_rank_order_not_its_volume_order():
    """If bands were ordered by count, `critical` would jump up and down the
    stack between buckets and the chart would be unreadable at a glance."""
    starts = _starts(2)
    series = reports.build_series(
        [_row(starts[0], "info", 900), _row(starts[0], "critical", 1)],
        unit="day", starts=starts, known_from=starts[0],
        complete_to=NOW + timedelta(days=1), known_to=NOW + timedelta(days=1), fallbacks=reports.NO_FALLBACK,
        key_order=reports.SEVERITY_ORDER)
    assert series.keys.index("critical") < series.keys.index("info")


def test_the_tail_is_folded_into_altele_and_is_not_clickable():
    """A stacked bar with twenty bands is a colour-matching puzzle. The fold is
    fine; a drill-down link on the folded band would not be — there is no single
    filter that reproduces "altele", so the link would return the wrong rows."""
    starts = _starts(1)
    rows = [_row(starts[0], f"s{i}", 10 - i) for i in range(10)]
    series = reports.build_series(
        rows, unit="day", starts=starts, known_from=starts[0],
        complete_to=NOW + timedelta(days=1), known_to=NOW + timedelta(days=1),
        fallbacks=reports.NO_FALLBACK, top=3)
    assert series.keys == ["s0", "s1", "s2", "altele"]
    assert series.totals["altele"] == sum(10 - i for i in range(3, 10))
    assert series.grand_total == sum(10 - i for i in range(10))   # nothing lost

    chart = reports.build_chart(series, drill={"kind": "events", "dim": "source",
                                               "bucket": "day"})
    folded = [s for s in chart.segments if s.key == "altele"]
    assert folded and all(s.href is None for s in folded)
    assert all(s.href for s in chart.segments if s.key != "altele")


def test_an_unlabelled_category_never_becomes_a_link_to_nothing():
    """`COALESCE(col, '')` turns a NULL category into an empty key. Linking it
    would produce `value=` and a drill-down that silently means something else."""
    starts = _starts(1)
    series = reports.build_series(
        [_row(starts[0], None, 3)], unit="day", starts=starts,
        known_from=starts[0], complete_to=NOW + timedelta(days=1),
        known_to=NOW + timedelta(days=1), fallbacks=reports.NO_FALLBACK)
    chart = reports.build_chart(series, drill={"kind": "events", "dim": "source",
                                               "bucket": "day"})
    assert chart.segments and chart.segments[0].href is None
    assert chart.segments[0].label == "necunoscut"


# ---------------------------------------------------------------------------
# Chart geometry
# ---------------------------------------------------------------------------
def _chart_with(values, states=None):
    starts = _starts(len(values))
    rows = [_row(s, "x", v) for s, v in zip(starts, values) if v]
    known_from = starts[0] if states is None else states
    return reports.build_chart(reports.build_series(
        rows, unit="day", starts=starts, known_from=known_from,
        complete_to=NOW + timedelta(days=1), known_to=NOW + timedelta(days=1), fallbacks=reports.NO_FALLBACK))


def test_bars_stay_inside_the_plot_area():
    """An off-by-one in the stacking arithmetic draws bars over the axis labels
    or off the top of the viewBox, and SVG clips silently — the chart just looks
    wrong, with no error anywhere."""
    chart = _chart_with([3, 17, 0, 9, 17])
    for seg in chart.segments:
        assert seg.y >= reports.PAD_T - 0.05, seg
        assert seg.y + seg.h <= chart.baseline + 0.05, seg
        assert seg.x >= reports.PAD_L - 0.05
        assert seg.x + seg.w <= reports.CHART_W - reports.PAD_R + 0.05


def test_the_tallest_bucket_fills_the_plot_and_a_half_bucket_is_half_as_tall():
    chart = _chart_with([10, 20])
    plot_h = reports.CHART_H - reports.PAD_T - reports.PAD_B
    by_x = sorted(chart.segments, key=lambda s: s.x)
    assert by_x[1].h == pytest.approx(plot_h, abs=0.2)
    assert by_x[0].h == pytest.approx(plot_h / 2, abs=0.2)


def test_an_unknown_bucket_draws_a_hatch_and_no_bar():
    """The visual half of "unknown is not zero". A gap column must be present
    and must not be confused for a category."""
    starts = _starts(4)
    series = reports.build_series(
        [_row(starts[3], "x", 5)], unit="day", starts=starts,
        known_from=starts[3], complete_to=NOW + timedelta(days=1),
        known_to=NOW + timedelta(days=1), fallbacks=reports.NO_FALLBACK)
    chart = reports.build_chart(series)
    assert len(chart.gaps) == 3
    assert len(chart.segments) == 1
    # Every gap sits where a bar would have, so the axis stays aligned.
    assert all(g.h > 0 and g.w > 0 for g in chart.gaps)
    assert "fără date" in chart.gaps[0].title


def test_a_partial_bucket_says_so_in_its_tooltip():
    starts = _starts(2)
    series = reports.build_series(
        [_row(s, "x", 4) for s in starts], unit="day", starts=starts,
        known_from=starts[0], complete_to=NOW, known_to=NOW, fallbacks=reports.NO_FALLBACK)
    chart = reports.build_chart(series)
    tips = [s.title for s in chart.segments]
    assert any("interval incomplet" in t for t in tips)
    assert any("interval incomplet" not in t for t in tips)


def test_drill_links_carry_the_bucket_start_and_the_category():
    starts = _starts(2)
    series = reports.build_series(
        [_row(starts[1], "nginx", 4)], unit="day", starts=starts,
        known_from=starts[0], complete_to=NOW + timedelta(days=1),
        known_to=NOW + timedelta(days=1), fallbacks=reports.NO_FALLBACK)
    chart = reports.build_chart(series, drill={"kind": "events", "dim": "source",
                                               "bucket": "day"})
    href = chart.segments[0].href
    assert href.startswith("/reports/drill?")
    assert "kind=events" in href and "dim=source" in href and "value=nginx" in href
    # The start must round-trip: the drill handler rejects anything that is not
    # an exact bucket boundary, so a lossy format here breaks every link.
    from urllib.parse import parse_qs, urlparse
    got = parse_qs(urlparse(href).query)["start"][0]
    assert datetime.fromisoformat(got) == starts[1]


def test_axis_ticks_are_thinned_but_always_include_the_newest_bucket():
    starts = reports.bucket_starts("hour", now=NOW, count=48)
    series = reports.build_series([], unit="hour", starts=starts,
                                  known_from=starts[0], complete_to=NOW, known_to=NOW, fallbacks=reports.NO_FALLBACK)
    chart = reports.build_chart(series, tick_fmt="%d.%m %H:%M")
    assert 0 < len(chart.ticks) <= 13
    assert chart.ticks[-1].label == starts[-1].strftime("%d.%m %H:%M")


# ---------------------------------------------------------------------------
# Which table each query reads
# ---------------------------------------------------------------------------
def test_the_event_series_reads_the_rollup_and_never_raw_events():
    """The whole reason this page can exist. A year of history out of
    `raw_events` is a scan of 365 daily partitions on the database that
    detection reads from — the report would be the reason detection stalled."""
    db = _StubDB()
    run(reports.events_rows(db, unit="day", start=NOW - timedelta(days=30),
                            end=NOW, dim="source"))
    sql = " ".join(db.sql)
    assert "event_rollup_1h" in sql
    assert "raw_events" not in sql


def test_only_the_event_drill_down_touches_raw_events_and_it_is_limited():
    db = _StubDB()
    run(reports.drill_events(db, start=NOW - timedelta(hours=1), end=NOW,
                             dim="source", value="nginx"))
    sql = " ".join(db.sql)
    assert "FROM raw_events" in sql
    assert "LIMIT" in sql


def test_incident_series_buckets_on_when_the_incident_opened():
    """On `last_detection_at` an incident that stays open for three weeks walks
    across the chart, and "how many incidents did March bring" answers with
    incidents that started in January."""
    db = _StubDB()
    run(reports.incidents_rows(db, unit="week", start=NOW - timedelta(days=60),
                               end=NOW, dim="severity"))
    sql = " ".join(db.sql)
    assert "first_detection_at" in sql
    assert "last_detection_at" not in sql


def test_patch_series_counts_real_applies_only():
    """A dry run executes nothing. Counting one as a patch lets the page report
    work that never happened on the host."""
    db = _StubDB()
    run(reports.patches_rows(db, unit="day", start=NOW - timedelta(days=7), end=NOW))
    assert "mode = 'apply'" in " ".join(db.sql)


def _sql_literals(path: Path) -> list[str]:
    """Every string constant in a module that looks like a SQL statement.

    Parsed, not grepped: the module docstring and several comments discuss
    `date_trunc` in prose, and a text search would score the wording instead of
    the query.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if re.search(r"\bSELECT\b", node.value) and re.search(r"\bFROM\b", node.value):
                out.append(node.value)
        elif isinstance(node, ast.JoinedStr):
            # f-string SQL: the {column} interpolation makes it a JoinedStr, so
            # its constant halves have to be stitched back together.
            text = "".join(v.value for v in node.values
                           if isinstance(v, ast.Constant) and isinstance(v.value, str))
            if re.search(r"\bSELECT\b", text) and re.search(r"\bFROM\b", text):
                out.append(text)
    return out


def test_every_bucketed_query_truncates_in_utc_explicitly():
    """`date_trunc` on a `timestamptz` truncates in the SESSION time zone, and
    nothing in engine.py pins one. On a host whose PostgreSQL defaults to a
    local zone, "days" would silently begin at 03:00 and the page would never
    say so. Converting with `AT TIME ZONE 'UTC'` first removes the question."""
    calls = [c for sql in _sql_literals(REPO / "sentinel" / "analytics" / "reports.py")
             for c in re.findall(r"date_trunc\([^)]*\)", sql)]
    # Prose is excluded on purpose: the module docstring and the comments talk
    # about date_trunc, and a lint that matched those would pass or fail on the
    # wording rather than on the SQL.
    assert len(calls) >= 3, f"only {len(calls)} date_trunc calls found in SQL — the scan is broken"
    for call in calls:
        assert "AT TIME ZONE 'UTC'" in call, f"untruncated session-zone call: {call}"


def test_the_utc_lint_would_catch_the_bug_it_is_guarding():
    """Guard the guard: feed it the shape that would ship without the cast."""
    bad = "date_trunc($1::text, bucket) AS b"
    assert re.findall(r"date_trunc\([^)]*\)", bad)
    assert "AT TIME ZONE 'UTC'" not in re.findall(r"date_trunc\([^)]*\)", bad)[0]


def test_breakdown_columns_are_whitelisted_not_taken_from_the_request():
    """The GROUP BY column is an identifier, so it is interpolated, not bound.
    It may only ever come from these tables — a value off the query string
    reaching that f-string would be an injection point."""
    for table in (reports.EVENT_DIMS, reports.INCIDENT_DIMS, reports.PATCH_DIMS):
        assert table, "a dimension table came out empty"
    with pytest.raises(KeyError):
        run(reports.events_rows(_StubDB(), unit="day", start=NOW, end=NOW,
                                dim="source; DROP TABLE raw_events"))


# ---------------------------------------------------------------------------
# rule_family is derived from the fingerprint — pin the invariant that allows it
# ---------------------------------------------------------------------------
def _leading_literal(node: ast.AST) -> str | None:
    """The constant prefix of a string node, including f-strings."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    return None


def _rule_pairs() -> list[tuple[str, str, str]]:
    """(file, rule_id, rule_family) for every detection spec in the tree."""
    pairs: list[tuple[str, str, str]] = []
    for path in sorted((REPO / "sentinel" / "detect").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            if "rule_id" not in kw or "rule_family" not in kw:
                continue
            rid = _leading_literal(kw["rule_id"])
            fam = _leading_literal(kw["rule_family"])
            if rid and fam:
                pairs.append((path.name, rid, fam))
    return pairs


def test_every_rule_id_starts_with_its_own_family():
    """`INCIDENT_DIMS["rule_family"]` reads the family out of the incident's
    fingerprint — `split_part(split_part(fingerprint, ':', 1), '.', 1)` — rather
    than joining every incident to `detections` for a column it already carries.
    That is only correct while `rule_id` begins with `rule_family`. A rule that
    breaks the convention would mis-label a whole band of the chart silently, so
    it breaks the suite here instead."""
    pairs = _rule_pairs()
    # A parametrised list that came out empty and was skipped in silence is one
    # of the failures this repository has already paid for.
    assert len(pairs) >= 5, f"only found {len(pairs)} rule specs — the scan is broken"
    bad = [(f, rid, fam) for f, rid, fam in pairs if rid.split(".")[0] != fam]
    assert not bad, f"rule_id does not start with rule_family: {bad}"


def test_the_family_expression_matches_what_the_detector_writes():
    """The Python equivalent of the SQL, run over real fingerprints from the
    rule modules. If the SQL and this ever disagree, one of them is wrong."""
    def sql_equivalent(fingerprint: str) -> str:
        return fingerprint.split(":")[0].split(".")[0]

    assert sql_equivalent("auth.ssh_bruteforce:203.0.113.5") == "auth"
    assert sql_equivalent("intrusion.shadow_changed") == "intrusion"        # no colon
    assert sql_equivalent("novelty.shift.geo") == "novelty"                 # extra dot
    assert sql_equivalent("anomaly.volume:req:93") == "anomaly"             # two colons
    assert "split_part(split_part(fingerprint, ':', 1), '.', 1)" == \
        reports.INCIDENT_DIMS["rule_family"]


# ---------------------------------------------------------------------------
# Drill-down bounds
# ---------------------------------------------------------------------------
def test_a_long_bucket_is_clamped_before_it_reaches_raw_events():
    """Drilling into a year bucket without a cap reads 365 daily partitions to
    fill one screen. The page shows the tail and says which window it read."""
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = datetime(2027, 1, 1, tzinfo=timezone.utc)
    w = reports.clamp_raw_window(start, end, raw_from=None)
    assert w.capped and not w.trimmed and not w.expired
    assert w.narrowed
    assert w.end == end
    assert (w.end - w.start) <= timedelta(hours=reports.DRILL_MAX_HOURS)


def test_a_short_bucket_is_read_whole():
    start = reports.truncate(NOW, "hour")
    end = reports.advance(start, "hour", 1)
    w = reports.clamp_raw_window(start, end, raw_from=None)
    assert (w.start, w.end) == (start, end)
    assert not w.narrowed and not w.expired


def test_a_bucket_older_than_the_oldest_partition_is_expired_not_empty():
    """Retention drops whole partitions. An empty table for a period whose
    detail was deleted must be labelled as deleted — otherwise the drill-down
    answers "no events" about events that certainly happened."""
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = datetime(2026, 1, 2, tzinfo=timezone.utc)
    w = reports.clamp_raw_window(
        start, end, raw_from=datetime(2026, 7, 10, tzinfo=timezone.utc))
    assert w.expired


def test_partitions_still_held_are_read_from_their_own_start():
    start = datetime(2026, 8, 8, tzinfo=timezone.utc)
    end = datetime(2026, 8, 9, tzinfo=timezone.utc)
    raw_from = datetime(2026, 8, 8, 12, tzinfo=timezone.utc)
    w = reports.clamp_raw_window(start, end, raw_from=raw_from)
    assert not w.expired
    assert w.start == raw_from          # not before it — there is nothing there


def test_retention_narrowing_inside_the_cap_still_raises_a_flag():
    """The bug the verifier found: `truncated` was computed BEFORE retention was
    applied. When the oldest surviving partition falls inside the last
    DRILL_MAX_HOURS of a bucket, the cap alone changes nothing, so the flag
    stayed false — and the window silently shrank while the page header went on
    showing the whole bucket."""
    end = datetime(2026, 8, 9, tzinfo=timezone.utc)
    start = end - timedelta(days=30)                       # a month bucket
    # Inside the last 48h of the bucket, so the cap is not what narrows it.
    raw_from = end - timedelta(hours=6)
    w = reports.clamp_raw_window(start, end, raw_from=raw_from)
    assert not w.expired
    assert w.start == raw_from
    assert w.trimmed, "retention narrowed the window and nothing said so"
    assert w.narrowed


def test_the_two_narrowing_reasons_are_reported_separately():
    """They have different remedies: a cap is fixed by choosing a smaller
    bucket, retention is not fixed at all. Saying "capped" for a deleted month
    sends someone hunting for data that no longer exists."""
    end = datetime(2026, 8, 9, tzinfo=timezone.utc)
    # Long bucket AND retention biting inside the capped tail.
    w = reports.clamp_raw_window(end - timedelta(days=365), end,
                                 raw_from=end - timedelta(hours=6))
    assert w.capped and w.trimmed
    # Long bucket, retention far older: capped only.
    w2 = reports.clamp_raw_window(end - timedelta(days=365), end,
                                  raw_from=end - timedelta(days=200))
    assert w2.capped and not w2.trimmed


# ---------------------------------------------------------------------------
# Coverage probes
# ---------------------------------------------------------------------------
# Deliberately years from any plausible wall clock, so a `rollup_coverage` that
# ignored its `now=` argument could not accidentally agree with these numbers.
# The three tests below used to call it WITHOUT `now=` and build their fixtures
# from `datetime.now()`, which exercised the fallback rather than the parameter:
# a mutation that dropped the argument entirely passed the whole suite, while
# `lag_hours` and `stale` — which decide whether the operator is told the
# aggregation has stopped — silently came from the machine's clock.
FAR = datetime(2031, 3, 2, 8, 13, tzinfo=timezone.utc)


def _cov_at(*, latest, now=FAR, earliest=None):
    db = _StubDB(row_map={"FROM event_rollup_1h": {
        "earliest": earliest if earliest is not None else now - timedelta(days=40),
        "latest": latest}})
    return run(reports.rollup_coverage(db, now=now))


def test_an_empty_rollup_reports_never_ran_rather_than_a_zero_lag():
    db = _StubDB(row_map={"FROM event_rollup_1h": {"earliest": None, "latest": None}})
    cov = run(reports.rollup_coverage(db, now=FAR))
    assert cov["never_ran"] is True
    assert cov["lag_hours"] is None
    assert cov["stale"] is False       # "unknown" is not "stale"; it is worse


def test_the_lag_is_measured_against_the_injected_clock_to_the_tenth_of_an_hour():
    """The number, not the word. `lag_hours` and `stale` are what put "agregatul
    are întârziere de N ore" in front of the operator; a coverage read that used
    the wall clock instead would put it there — or hide it — at random."""
    cov = _cov_at(latest=FAR - timedelta(hours=1))
    assert cov["lag_hours"] == 1.0
    assert cov["stale"] is False
    assert cov["never_ran"] is False

    # 9h12m behind: past the 3h threshold, and reported to the tenth.
    cov = _cov_at(latest=FAR - timedelta(hours=9, minutes=12))
    assert cov["lag_hours"] == 9.2
    assert cov["stale"] is True


def test_the_stale_threshold_is_pinned_on_both_sides():
    just_under = _cov_at(latest=FAR - timedelta(hours=reports.ROLLUP_STALE_HOURS,
                                                minutes=-6))
    just_over = _cov_at(latest=FAR - timedelta(hours=reports.ROLLUP_STALE_HOURS,
                                               minutes=6))
    assert just_under["stale"] is False
    assert just_over["stale"] is True


def test_a_fresh_rollup_is_not_flagged():
    assert _cov_at(latest=FAR - timedelta(minutes=20))["stale"] is False


def test_the_coverage_edge_also_comes_from_the_injected_clock():
    """`event_edges` clamps `complete_to` to now. Reading a different clock there
    would mark the newest bucket complete or incomplete at random."""
    latest = FAR.replace(minute=0, second=0, microsecond=0)
    cov = _cov_at(latest=latest)
    known_from, complete_to, known_to = reports.event_edges(cov, now=FAR)
    assert complete_to == latest
    assert known_to == latest + timedelta(hours=1)
    assert known_from == FAR - timedelta(days=40)


def test_raw_coverage_reads_the_catalog_not_the_partitions():
    """`min(ts)` over `raw_events` is a scan of every surviving partition to
    learn something `pg_inherits` already knows."""
    db = _StubDB(val_map={"pg_inherits": date(2026, 7, 10)})
    got = run(reports.raw_coverage(db))
    assert got == datetime(2026, 7, 10, tzinfo=timezone.utc)
    assert "pg_inherits" in " ".join(db.sql)
    assert "min(ts)" not in " ".join(db.sql)


def test_incident_coverage_comes_from_the_install_date_not_the_first_incident():
    """`min(first_detection_at)` as the coverage edge would paint every quiet
    month before the first incident as "no data"; no edge at all would paint
    every month before install as a clean record. The schema's own first
    migration is when Sentinel started being able to see anything."""
    installed = datetime(2026, 6, 1, tzinfo=timezone.utc)
    db = _StubDB(val_map={"FROM schema_version": installed})
    assert run(reports.installed_at(db)) == installed
    assert "incidents" not in " ".join(db.sql)


def test_earliest_keeps_none_when_nothing_is_known():
    a = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert reports.earliest(None, a, None) == a
    assert reports.earliest(None, None) is None


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
def test_overview_never_sums_per_bucket_distinct_counts():
    """`event_rollup_1h.uniq_src` is distinct-per-bucket. Summing it produces a
    completely plausible "distinct attackers this month" that is simply wrong,
    so this module does not offer the number at all."""
    src = (REPO / "sentinel" / "analytics" / "reports.py").read_text(encoding="utf-8")
    assert "uniq_src" not in src.split('"""', 3)[-1], \
        "uniq_src is being read from the rollup — it cannot be aggregated"


def test_overview_reports_zero_rather_than_none_on_an_empty_database():
    """A fresh install must render numbers, not `None`, and must not 500."""
    db = _StubDB()
    out = run(reports.overview(db, hours=24, rollup_from=None, installed_from=None))
    assert out["events"]["total"] == 0
    assert out["incidents"]["open_total"] == 0
    assert out["patches"]["succeeded"] == 0
    assert out["findings"]["open"] == 0


def test_the_24h_window_covers_at_least_24_hours():
    """`since = now - 24h` against `bucket >= …` drops the partial oldest hour,
    because rollup buckets start at :00 — so "ultimele 24h" counted 23. The
    rounding goes outward: a security window may include a little more than was
    asked for, never less."""
    now = datetime(2026, 8, 9, 6, 37, tzinfo=timezone.utc)
    out = run(reports.overview(_StubDB(), hours=24, rollup_from=None,
                               installed_from=None, now=now))
    assert out["since"] == datetime(2026, 8, 8, 6, tzinfo=timezone.utc)
    assert now - out["since"] >= timedelta(hours=24)
    assert (out["since"].minute, out["since"].second) == (0, 0)


def test_every_offered_window_is_floored_to_a_whole_hour():
    now = datetime(2026, 8, 9, 6, 37, 41, tzinfo=timezone.utc)
    for label, hours in reports.WINDOWS.items():
        out = run(reports.overview(_StubDB(), hours=hours, rollup_from=None,
                                   installed_from=None, now=now))
        assert now - out["since"] >= timedelta(hours=hours), label
        assert out["since"] == reports.truncate(out["since"], "hour"), label


def test_a_window_longer_than_the_retained_data_is_marked_partial():
    """On the live host, "7z" and "30z" printed the same number because only
    5.8 days of rollup exist. Without a marking on the card, next month the same
    "30z" prints five times more for a reason nobody can see."""
    now = datetime(2026, 8, 9, 6, 37, tzinfo=timezone.utc)
    edge = now - timedelta(days=5, hours=19)
    week = run(reports.overview(_StubDB(), hours=24 * 7, rollup_from=edge,
                                installed_from=edge, now=now))["events"]["coverage"]
    month = run(reports.overview(_StubDB(), hours=24 * 30, rollup_from=edge,
                                 installed_from=edge, now=now))["events"]["coverage"]
    assert week.partial and month.partial
    assert week.covered_from == edge and month.covered_from == edge
    assert week.hours_covered < 24 * 7
    # Same data behind both cards: the two numbers being equal is a fact about
    # coverage, and each card now carries the span that explains it.
    assert week.hours_covered == month.hours_covered


def test_a_window_inside_the_retained_data_carries_no_caveat():
    """The caveat has to be absent when it does not apply, or it becomes
    wallpaper and stops being read."""
    now = datetime(2026, 8, 9, 6, 37, tzinfo=timezone.utc)
    cov = run(reports.overview(_StubDB(), hours=24,
                               rollup_from=now - timedelta(days=40),
                               installed_from=now - timedelta(days=40),
                               now=now))["events"]["coverage"]
    assert not cov.partial and not cov.unknown
    assert cov.covered_from == cov.requested_from


def test_a_counter_with_no_coverage_edge_says_unknown_rather_than_full():
    now = datetime(2026, 8, 9, 6, 37, tzinfo=timezone.utc)
    out = run(reports.overview(_StubDB(), hours=24, rollup_from=None,
                               installed_from=None, now=now))
    assert out["events"]["coverage"].unknown
    assert out["events"]["coverage"].hours_covered is None
    assert not out["events"]["coverage"].partial   # unknown is its own state


def test_every_windowed_group_in_the_overview_carries_a_coverage_object():
    """Rule 2 of this module's own docstring, applied to the cards and not only
    to the charts — which is exactly where it was missing."""
    now = datetime(2026, 8, 9, 6, 37, tzinfo=timezone.utc)
    out = run(reports.overview(_StubDB(), hours=24, rollup_from=None,
                               installed_from=None, now=now))
    groups = ("events", "incidents", "patches", "findings")
    assert set(groups) <= set(out), out.keys()
    for group in groups:
        assert isinstance(out[group].get("coverage"), reports.WindowCoverage), group


def test_the_source_card_folds_its_tail_instead_of_stopping():
    """The chart folds its tail into a stated `altele`; this card just stopped
    at the eighth row, which made it the only place on the page where a whole
    category could disappear with nothing to show for it."""
    rows = [{"k": f"src{i}", "n": 100 - i} for i in range(11)]
    db = _StubDB(fetch_map={"ORDER BY 2 DESC LIMIT $2": rows})
    out = run(reports.overview(db, hours=24, rollup_from=None,
                               installed_from=None, now=NOW))
    card = out["events"]["by_source"]
    assert len(card) == reports.SOURCE_ROWS_SHOWN + 1
    assert card[-1]["key"] == "altele"
    assert card[-1]["folded"] == 11 - reports.SOURCE_ROWS_SHOWN
    # Nothing is lost: the fold is a sum, not a truncation.
    assert sum(r["n"] for r in card) == sum(r["n"] for r in rows)
    assert out["events"]["sources_truncated"] is False


def test_a_short_source_list_gains_no_altele_row():
    rows = [{"k": "nginx", "n": 900}, {"k": "sshd", "n": 40}]
    db = _StubDB(fetch_map={"ORDER BY 2 DESC LIMIT $2": rows})
    card = run(reports.overview(db, hours=24, rollup_from=None,
                                installed_from=None, now=NOW))["events"]["by_source"]
    assert [r["key"] for r in card] == ["nginx", "sshd"]


def test_hitting_the_source_read_ceiling_is_reported():
    """Above the ceiling even `altele` is incomplete, and the card says so
    rather than presenting a partial sum as a total."""
    rows = [{"k": f"src{i}", "n": 1} for i in range(reports.SOURCE_ROWS_MAX)]
    db = _StubDB(fetch_map={"ORDER BY 2 DESC LIMIT $2": rows})
    out = run(reports.overview(db, hours=24, rollup_from=None,
                               installed_from=None, now=NOW))
    assert out["events"]["sources_truncated"] is True


@pytest.mark.parametrize("unit", ["hour", "day", "week", "month", "year"])
def test_a_live_series_never_goes_pending_on_an_exact_bucket_boundary(unit):
    """`incidents` and `patch_executions` have no aggregation step and no raw
    store behind them, so a `pending` column there is meaningless — and it used
    to appear, once per bucket boundary.

    `live_edges` returned `known_to = now`, and `_bucket_state` blanks a bucket
    when `start >= known_to`; at exactly midnight UTC, or the top of an hour, or
    Monday 00:00, `now >= now` held and today's column came back `pending`,
    carrying "Click pentru lista brută" about tables that do not exist for it.

    A comment at the call site asserted this could not happen, and nothing
    tested the claim. The moment below is that exact boundary, at every bucket
    size the page offers.
    """
    boundary = reports.truncate(datetime(2026, 8, 10, 0, 0, tzinfo=timezone.utc), unit)
    for now in (boundary, boundary + timedelta(microseconds=1),
                boundary + timedelta(minutes=37)):
        starts = reports.bucket_starts(unit, now=now, count=4)
        known_from, complete_to, known_to = reports.live_edges(
            starts[0] - timedelta(days=1), now=now, unit=unit)
        series = reports.build_series(
            [], unit=unit, starts=starts,
            known_from=known_from, complete_to=complete_to, known_to=known_to,
            fallbacks=reports.NO_FALLBACK)
        assert series.pending_buckets == 0, f"{unit} at {now.isoformat()}"
        assert series.missed_buckets == 0
        # The current bucket is still filling, which is a different statement.
        assert series.state[-1] == reports.PARTIAL, f"{unit} at {now.isoformat()}"
        assert series.state[-2] == reports.KNOWN


def test_the_router_takes_its_coverage_edges_from_analytics():
    """Structural half of the fix. The edge arithmetic is only pinned by a test
    while it lives in `event_edges`/`live_edges`; the moment a handler rebuilds
    it inline, the unit tests above stop covering the code that runs — which is
    how a guard test came to be written against an input shape the router never
    produces."""
    src = (REPO / "sentinel" / "web" / "routers" / "reports.py").read_text(encoding="utf-8")
    assert "reports.event_edges(" in src
    assert "reports.live_edges(" in src
    for handrolled in ('known_to=coverage[', "known_to=now", "known_to=since_install"):
        assert handrolled not in src, f"coverage edge rebuilt in the router: {handrolled}"


def test_overview_open_counts_are_not_limited_to_the_window():
    """An incident opened five weeks ago and still open is a fact about today.
    Filtering it out of "open" behind a 24-hour window is how a queue grows
    unread."""
    db = _StubDB()
    run(reports.overview(db, hours=24, rollup_from=None, installed_from=None))
    open_query = next(s for s in db.sql if "status IN ('open','acknowledged')" in s)
    assert "first_detection_at" not in open_query
