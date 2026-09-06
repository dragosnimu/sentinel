"""`detect/novelty.py`'s two rules, and the process-hint enrichment added to
`unseen_before` for F04 (`outbound_dst`).

Every test here exists because of a measured gap: `process` and
`process_status` were already sitting on every `raw_events` row
`collectors/conntrack.py` writes, entirely unused by the one rule that
alerts on a bare destination address — an operator triaging "new
destination 203.0.113.9" had nothing to check beyond the IP itself, for the
exact case (F04) this alert was supposed to make triageable.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sentinel.detect import novelty
from sentinel.predict import behaviour as bh


class _FakeDB:
    """Just enough of `Database` to drive `unseen_before` for ONE dimension
    at a time. `warm_dims` decides which dimensions are even looked at —
    every other one of `bh.DIMENSIONS` reports cold and is skipped, so a
    test does not have to also stub fresh keys / hints for six unrelated
    dimensions to exercise one."""

    def __init__(self, warm_dims, fresh_rows=(), hint_row=None,
                 known_count=3, profile_age_days=5.0):
        self.warm_dims = set(warm_dims)
        self.fresh_rows = list(fresh_rows)
        self.hint_row = hint_row
        self.known_count = known_count
        self.profile_age_days = profile_age_days

    async def fetchval(self, sql, *args):
        if "warm_at IS NOT NULL" in sql:
            return args[0] in self.warm_dims
        if "count(*)" in sql:
            return self.known_count
        if "EXTRACT(EPOCH" in sql:
            # The real query already divides by 86400 in SQL — this fake
            # must hand back DAYS too, not seconds, or _profile_age_days
            # would silently be 86400x off in every test that reads it.
            return self.profile_age_days
        return None

    async def fetch(self, sql, *args):
        dimension = args[0]
        if dimension == "outbound_dst":
            return self.fresh_rows
        return []

    async def fetchrow(self, sql, *args):
        return self.hint_row


def _fresh_row(key="203.0.113.9"):
    return {"key": key, "first_seen": datetime.now(timezone.utc), "observations": 1}


# ---------------------------------------------------------------------------
# _process_hint: only queried for a conntrack-sourced dimension
# ---------------------------------------------------------------------------
def test_process_hint_is_never_queried_for_a_non_conntrack_dimension():
    """`process`/`process_status` are only ever written by
    `collectors/conntrack.py` — querying `raw_events` for e.g. `login_user`
    would just be a wasted round trip against a column that dimension never
    populates. Proven by making the query explode if it ever runs."""
    class _ExplodingDB:
        async def fetchrow(self, *a, **kw):
            raise AssertionError(
                "queried raw_events for a dimension conntrack never wrote to")

    dim = bh.BY_NAME["login_user"]
    result = asyncio.run(novelty._process_hint(_ExplodingDB(), dim, "alice"))
    assert result is None


def test_process_hint_returns_none_when_raw_events_has_nothing_for_the_key():
    dim = bh.BY_NAME["outbound_dst"]
    db = _FakeDB(warm_dims=(), hint_row=None)
    result = asyncio.run(novelty._process_hint(db, dim, "203.0.113.9"))
    assert result is None


def test_process_hint_reads_process_pid_status_and_user_from_raw_events():
    dim = bh.BY_NAME["outbound_dst"]
    hint_row = {"process": "curl", "pid": 4821,
                "process_status": "found", "user": "sentinel"}
    db = _FakeDB(warm_dims=(), hint_row=hint_row)
    result = asyncio.run(novelty._process_hint(db, dim, "203.0.113.9"))
    assert result == {"process": "curl", "pid": 4821,
                       "process_status": "found", "user": "sentinel"}


# ---------------------------------------------------------------------------
# unseen_before: the process hint reaching the actual incident
# ---------------------------------------------------------------------------
def test_unseen_before_surfaces_the_owning_process_for_a_new_outbound_destination():
    """THE fix: an operator reading this incident must have something to
    check beyond the bare IP — the process (and, where known, the user)
    that opened the connection which made the destination novel."""
    hint_row = {"process": "curl", "pid": 4821,
                "process_status": "found", "user": "sentinel"}
    db = _FakeDB(warm_dims={"outbound_dst"}, fresh_rows=[_fresh_row()], hint_row=hint_row)

    specs = asyncio.run(novelty.unseen_before(db, cursor=0))

    assert len(specs) == 1
    spec = specs[0]
    assert spec.evidence["process_hint"]["process"] == "curl"
    assert "curl" in spec.summary
    assert "4821" in spec.summary
    assert "sentinel" in spec.summary


def test_unseen_before_degrades_without_a_process_hint_when_raw_events_has_nothing():
    """Not every novel destination will have a matching raw_events row (the
    hint is best-effort, see `_process_hint`'s own docstring) — the alert
    must still fire, just without the extra field, not silently disappear
    or crash trying to build a hint from nothing."""
    db = _FakeDB(warm_dims={"outbound_dst"}, fresh_rows=[_fresh_row()], hint_row=None)

    specs = asyncio.run(novelty.unseen_before(db, cursor=0))

    assert len(specs) == 1
    assert "process_hint" not in specs[0].evidence
    assert "verifică cine a făcut-o" in specs[0].summary


def test_unseen_before_names_why_attribution_failed_when_the_process_is_unknown():
    """A hint CAN exist with no process name — conntrack's own
    `"not_attributable"`/`"container_egress"`/etc. statuses (see that
    module's docstring). The summary must say WHY it could not identify the
    process, not silently behave as if no hint existed at all."""
    hint_row = {"process": None, "pid": None,
                "process_status": "not_attributable", "user": None}
    db = _FakeDB(warm_dims={"outbound_dst"}, fresh_rows=[_fresh_row()], hint_row=hint_row)

    specs = asyncio.run(novelty.unseen_before(db, cursor=0))

    assert "not_attributable" in specs[0].summary
    assert specs[0].evidence["process_hint"]["process_status"] == "not_attributable"


def test_unseen_before_stays_quiet_for_a_cold_dimension():
    db = _FakeDB(warm_dims=(), fresh_rows=[_fresh_row()])
    specs = asyncio.run(novelty.unseen_before(db, cursor=0))
    assert specs == []
