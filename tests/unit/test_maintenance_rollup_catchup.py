"""`rollup_events` — the NORMAL catch-up path (not `repair_rollup_gaps`), fixed
to slice the same way round 3 sliced the repair path.

Before this fix, `rollup_events` called `sentinel_rollup_events_1m(start,
end)` once, over a window of up to `MAX_CATCHUP_HOURS` (48h). On normal
volume that is fast (87 443 rows / 48h measured at 664 ms). But the window is
not always normal volume: a SINGLE incident hour inside it (24.08 14:00,
4 329 065 rows, 67-70s measured) is enough on its own to exceed
`statement_timeout_ms` (30 000 ms). Unlike a slow-but-successful call, a
killed statement writes nothing, so the watermark (`max(bucket)`, `_watermark`
in `maintenance_service.py`) does not move — the next run replays the exact
same window and dies the same way, forever, silently reported as a normal
maintenance pass. `repair_rollup_gaps` cannot help either: its lower bound
IS the stuck watermark.

These tests do not touch `repair_rollup_gaps`, `check_rollup_reconcile`,
`HOURLY_GAPS_SQL`, or migration 0044 — those went through their own three
rounds already. They exercise only the loop inside `rollup_events`.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.services import maintenance_service as ms


def run(coro):
    return asyncio.run(coro)


class _FrozenNow(datetime):
    """A `datetime` subclass whose `.now()` always returns a fixed instant.

    Two clock-dependent bugs already cost a round each this session — time
    has to be injected, not read live. `rollup_events` calls
    `datetime.now(timezone.utc)` directly (no clock parameter to inject
    around), so the test freezes the module's bound name instead of widening
    the function's signature for the sake of a test."""

    _frozen: datetime

    @classmethod
    def now(cls, tz=None):  # noqa: ARG003 - matches datetime.now's signature
        return cls._frozen


def _freeze(monkeypatch, when: datetime) -> None:
    frozen = type("_Frozen", (_FrozenNow,), {"_frozen": when})
    monkeypatch.setattr(ms, "datetime", frozen)


class _DB:
    """Records every `sentinel_rollup_events_1m`/`_1h` call, in order, WITH
    its window — the only way to check a slice's SIZE, which a stub that
    merely returns a canned row count cannot show. `max(bucket)` reads are
    answered per-table from `watermarks`, so the two tables in the loop can be
    driven independently (one already caught up, the other with a gap)."""

    def __init__(
        self,
        watermarks: dict[str, datetime | None],
        row_values: dict[str, int] | int = 1,
        fail_on_agg_call: int | None = None,
    ):
        self._watermarks = watermarks
        self._row_values = row_values
        self._fail_on_agg_call = fail_on_agg_call
        self.calls: list[tuple[str, tuple]] = []
        self._agg_call_count = 0

    async def fetchval(self, sql, *args):
        if "max(bucket)" in sql:
            for table, wm in self._watermarks.items():
                if table in sql:
                    return wm
            raise AssertionError(f"watermark asked for an unconfigured table: {sql}")

        self._agg_call_count += 1
        if self._fail_on_agg_call is not None and self._agg_call_count == self._fail_on_agg_call:
            raise TimeoutError("simulated statement_timeout mid-window")

        self.calls.append((sql, args))
        if isinstance(self._row_values, int):
            return self._row_values
        for name, seq in self._row_values.items():
            if name in sql:
                return seq.pop(0)
        return 1


def _calls_for(db: _DB, fn_name: str) -> list[tuple[datetime, datetime]]:
    return [a for sql, a in db.calls if fn_name in sql]


# ---------------------------------------------------------------------------
# No single statement gets more than one slice of window, per table
# ---------------------------------------------------------------------------
def test_no_single_1m_statement_gets_more_than_the_measured_safe_slice(monkeypatch):
    """The bug itself: before this fix, a single `sentinel_rollup_events_1m`
    call carried the whole catch-up window. The literal here is
    `timedelta(minutes=1)`, NOT `ms.GAP_REPAIR_SLICE` — a session note (round
    3, `test_maintenance_rollup_repair.py`) already burned a round on a guard
    measured against the constant it was supposed to police: mutating the
    constant moved the threshold with it and the test stayed green while the
    code emitted the whole-window statement that times out."""
    now = datetime(2026, 8, 24, 15, 0, 0, tzinfo=timezone.utc)
    _freeze(monkeypatch, now)
    wm = now - timedelta(minutes=5)
    db = _DB(watermarks={"event_rollup_1m": wm, "event_rollup_1h": now})

    run(ms.rollup_events(db))

    slices = _calls_for(db, "sentinel_rollup_events_1m")
    max_slice = timedelta(minutes=1)  # literal, on purpose
    offenders = [(s, e) for s, e in slices if (e - s) > max_slice]
    assert not offenders, (
        f"a sentinel_rollup_events_1m call spans more than {max_slice} — this "
        f"is exactly the statement that costs 67-70s on the incident's worst "
        f"hour, against a 30 000ms connection timeout: {offenders}")
    # a 5-minute gap sliced no coarser than the literal bound needs at least
    # this many calls — arithmetic on the literal, not on GAP_REPAIR_SLICE.
    min_slices = timedelta(minutes=5) // max_slice
    assert len(slices) >= min_slices, (
        f"only {len(slices)} slices for a 5-minute gap — fewer than the "
        f"{min_slices} a {max_slice} bound requires")


def test_no_single_1h_statement_gets_more_than_an_hour(monkeypatch):
    """`sentinel_rollup_events_1h` reads already-aggregated `event_rollup_1m`
    rows, grouped by (asset, source, action) — cheap per hour regardless of
    raw row count (0017_partition_fixes.sql; measured in
    `test_maintenance_rollup_repair.py`'s docstrings). That bound was only
    ever measured for ONE hour at a time; a multi-hour catch-up window has no
    such measurement, so no single call is allowed to span more than the one
    hour that IS measured-safe."""
    now = datetime(2026, 8, 24, 15, 0, 0, tzinfo=timezone.utc)
    _freeze(monkeypatch, now)
    wm = now - timedelta(hours=5)
    db = _DB(watermarks={"event_rollup_1m": now, "event_rollup_1h": wm})

    run(ms.rollup_events(db))

    slices = _calls_for(db, "sentinel_rollup_events_1h")
    max_slice = timedelta(hours=1)  # literal, on purpose
    offenders = [(s, e) for s, e in slices if (e - s) > max_slice]
    assert not offenders, (
        f"a sentinel_rollup_events_1h call spans more than {max_slice}, with "
        f"no measurement backing it being safe: {offenders}")
    # A 5-hour gap must not turn into fewer than 5 hourly calls either — that
    # would mean two-plus hours landed in one statement.
    assert len(slices) == 5, f"expected 5 hourly slices for a 5h gap, got {len(slices)}"


def test_the_common_hourly_pass_does_not_turn_into_sixty_1h_round_trips(monkeypatch):
    """The other side of the same decision: the catch-up window in the common
    case (timer runs hourly, watermark trails by ~1h) is already ~1 hour, so
    slicing `event_rollup_1h` at one-minute granularity — safe, but
    unmeasured as necessary — would multiply every ordinary maintenance pass
    into 60 round trips for no benefit. One hour of gap must cost exactly one
    `sentinel_rollup_events_1h` call."""
    now = datetime(2026, 8, 24, 15, 0, 0, tzinfo=timezone.utc)
    _freeze(monkeypatch, now)
    wm = now - timedelta(hours=1)
    db = _DB(watermarks={"event_rollup_1m": now, "event_rollup_1h": wm})

    run(ms.rollup_events(db))

    slices = _calls_for(db, "sentinel_rollup_events_1h")
    assert len(slices) == 1, (
        f"a 1-hour gap (the ordinary hourly case) issued {len(slices)} "
        f"sentinel_rollup_events_1h calls instead of 1")
    assert slices[0] == (wm, now)


# ---------------------------------------------------------------------------
# Slices tile the window exactly — no gap, no overlap, no overshoot past `end`
# ---------------------------------------------------------------------------
def test_1m_slices_cover_the_window_back_to_back_with_no_overshoot(monkeypatch):
    """A window that does not divide evenly by the slice size (the normal
    case — `now` is not minute-aligned) must still stop exactly at `end`, not
    past it: an off-by-one that drops the `min(cursor + slice, end)` clamp
    would silently reaggregate into the future or skip the last few
    seconds."""
    now = datetime(2026, 9, 3, 10, 7, 23, tzinfo=timezone.utc)
    _freeze(monkeypatch, now)
    wm = now - timedelta(minutes=2, seconds=30)
    db = _DB(watermarks={"event_rollup_1m": wm, "event_rollup_1h": now})

    run(ms.rollup_events(db))

    slices = _calls_for(db, "sentinel_rollup_events_1m")
    assert len(slices) == 3, f"expected 3 slices (1m, 1m, 30s), got {len(slices)}"
    starts = [s for s, _ in slices]
    ends = [e for _, e in slices]
    assert starts[0] == wm
    assert ends[-1] == now, "the last slice must stop exactly at the window's end, not overshoot"
    assert starts[1:] == ends[:-1], "slices must be back to back — no gap, no overlap"
    assert ends[-1] - starts[-1] == timedelta(seconds=30), "the trailing partial slice must be clamped, not padded to a full minute"


# ---------------------------------------------------------------------------
# Progress on partial failure is a fact, not a hope
# ---------------------------------------------------------------------------
def test_a_slice_that_times_out_mid_window_does_not_undo_the_slices_before_it(monkeypatch):
    """The whole point of slicing: before this fix, ONE statement covered the
    whole window, so a timeout wrote nothing and the watermark never moved.
    Sliced, each call is issued and (per `Database.fetchval`,
    `sentinel/db/engine.py`: no explicit transaction wraps it) committed on
    its own — so a failure on slice N leaves slices 1..N-1 durably written,
    and the next run's watermark (`max(bucket)`, derived from data, not a
    cursor) resumes past them instead of replaying the whole window.

    This stub never defines `db.transaction()`. If a future edit wrapped the
    slicing loop in one transaction to look tidier, that would silently
    reintroduce the exact bug this test file exists to catch — a later
    slice's failure would roll back the earlier ones too — and this test
    would fail with `TimeoutError` un-caught by anything (proving the
    earlier slices were, in fact, issued as their own statements) rather
    than with the `AttributeError` a `db.transaction()` call would raise on
    this stub. Either failure shape proves the point; this asserts the one
    that means the fix works."""
    now = datetime(2026, 8, 24, 15, 0, 0, tzinfo=timezone.utc)
    _freeze(monkeypatch, now)
    wm = now - timedelta(minutes=5)
    # fail on the 3rd sentinel_rollup_events_1m call (of 5 expected)
    db = _DB(watermarks={"event_rollup_1m": wm, "event_rollup_1h": now}, fail_on_agg_call=3)

    with pytest.raises(TimeoutError, match="simulated statement_timeout"):
        run(ms.rollup_events(db))

    slices = _calls_for(db, "sentinel_rollup_events_1m")
    assert len(slices) == 2, (
        f"expected exactly the 2 slices issued before the simulated timeout, "
        f"got {len(slices)} — a batching change would make this 0 (all "
        f"rolled back together) or 5 (the failure swallowed)")
    assert slices[0] == (wm, wm + timedelta(minutes=1))
    assert slices[1] == (wm + timedelta(minutes=1), wm + timedelta(minutes=2))


# ---------------------------------------------------------------------------
# The reported row count is the sum across slices, not the last slice's alone
# ---------------------------------------------------------------------------
def test_reported_rows_are_summed_across_every_slice(monkeypatch):
    """Each slice is a separate SQL call with its own return value. A fact
    that kept only the last call's result (or `None`, from a return value
    never assigned back) would silently under-report exactly how much of an
    incident's backlog actually got processed."""
    now = datetime(2026, 8, 24, 15, 0, 0, tzinfo=timezone.utc)
    _freeze(monkeypatch, now)
    wm = now - timedelta(minutes=3)
    db = _DB(
        watermarks={"event_rollup_1m": wm, "event_rollup_1h": now},
        row_values={"sentinel_rollup_events_1m": [10, 20, 30]},
    )

    _, facts = run(ms.rollup_events(db))

    assert facts["event_rollup_1m"]["rows"] == 60, (
        f"expected the sum of all three slices (10+20+30=60), got "
        f"{facts['event_rollup_1m']['rows']}")


# ---------------------------------------------------------------------------
# Both tables in the same pass are sliced independently — no leaked state
# ---------------------------------------------------------------------------
def test_both_tables_are_sliced_independently_in_the_same_pass(monkeypatch):
    """The loop body reuses one local for the per-table slice size; a bug
    that let one iteration's value leak into the next would make
    `event_rollup_1h` slice at one minute too (or `event_rollup_1m` slice at
    one hour, reproducing the original bug) depending on iteration order."""
    now = datetime(2026, 8, 24, 15, 0, 0, tzinfo=timezone.utc)
    _freeze(monkeypatch, now)
    wm_1m = now - timedelta(minutes=2)
    wm_1h = now - timedelta(hours=2)
    db = _DB(watermarks={"event_rollup_1m": wm_1m, "event_rollup_1h": wm_1h})

    run(ms.rollup_events(db))

    m_slices = _calls_for(db, "sentinel_rollup_events_1m")
    h_slices = _calls_for(db, "sentinel_rollup_events_1h")
    assert len(m_slices) == 2 and all(e - s <= timedelta(minutes=1) for s, e in m_slices)
    assert len(h_slices) == 2 and all(e - s <= timedelta(hours=1) for s, e in h_slices)
