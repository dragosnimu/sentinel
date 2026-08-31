"""`db/repo/incident_campaigns.py`: the campaign grouping layer.

No live Postgres in this suite — `_FakeDB`/`_FakeConn` answer by SQL
substring and record every bound argument, the same convention
`tests/unit/test_intel_reputation.py` and
`tests/unit/test_incidents_repo_reputation.py` already use for their own
repo-layer stubs. Each test names the operator-visible failure it prevents.
"""

from __future__ import annotations

import asyncio
import contextlib

from sentinel.db.repo import incident_campaigns as camp_repo


def run(coro):
    return asyncio.run(coro)


class _FakeConn:
    """What `db.transaction()` yields for `attach_incident`."""

    def __init__(self, *, campaign_id=1, counts_row=None):
        self.campaign_id = campaign_id
        self.counts_row = counts_row or {
            "incident_count": 3, "actor_count": 2, "top_severity": "medium"}
        self.calls: list[tuple] = []

    async def fetchval(self, sql, *args):
        self.calls.append(("fetchval", sql, args))
        return self.campaign_id

    async def fetchrow(self, sql, *args):
        self.calls.append(("fetchrow", sql, args))
        return self.counts_row

    async def execute(self, sql, *args):
        self.calls.append(("execute", sql, args))
        return "UPDATE 1"


class _FakeDB:
    def __init__(self, *, conn=None, fetch_rows=None):
        self._conn = conn or _FakeConn()
        self.fetch_rows = fetch_rows if fetch_rows is not None else []
        self.fetch_calls: list[tuple] = []

    @contextlib.asynccontextmanager
    async def transaction(self):
        yield self._conn

    async def fetch(self, sql, *args):
        self.fetch_calls.append((sql, args))
        return self.fetch_rows


# --- attach_incident --------------------------------------------------------
def test_attach_incident_upserts_on_the_active_partial_index():
    """`ON CONFLICT` must target EXACTLY the arbiter the partial unique index
    (`incident_campaigns_key_active_idx`, migration 0039) provides. If the `WHERE
    status = 'active'` clause is dropped here, Postgres refuses the INSERT at
    runtime with 'no unique or exclusion constraint matching the ON CONFLICT
    specification' — a real database error a SQL-substring check on the
    shipped statement can catch without a live server."""
    conn = _FakeConn()
    db = _FakeDB(conn=conn)
    run(camp_repo.attach_incident(db, 42, "auth.ssh_bruteforce", "high"))
    insert_sql = conn.calls[0][1]
    assert "ON CONFLICT (campaign_key) WHERE status = 'active'" in insert_sql
    assert conn.calls[0][2] == ("auth.ssh_bruteforce", "high", "Campanie: auth.ssh_bruteforce")


def test_attach_incident_links_the_incident_to_the_returned_campaign():
    """The whole point of the call: the incident row must end up pointing at
    the campaign id the upsert produced, not at some other row."""
    conn = _FakeConn(campaign_id=99)
    db = _FakeDB(conn=conn)
    run(camp_repo.attach_incident(db, 42, "auth.ssh_bruteforce", "high"))
    kind, sql, args = conn.calls[1]
    assert kind == "execute"
    assert "UPDATE incidents SET campaign_id" in sql
    assert args == (42, 99)


def test_attach_incident_recomputes_counters_instead_of_incrementing():
    """`incident_count`/`actor_count` must come from a fresh `count(*)` /
    `count(DISTINCT actor_key)` over `incidents`, never from `+ 1` on the old
    value. An incremented counter silently diverges from reality the first
    time a call is retried — see `CLAUDE.md` on exactly this class of bug and
    the module docstring on why this function recomputes."""
    conn = _FakeConn(campaign_id=7, counts_row={
        "incident_count": 11, "actor_count": 6, "top_severity": "critical"})
    db = _FakeDB(conn=conn)
    run(camp_repo.attach_incident(db, 42, "auth.ssh_bruteforce", "high"))

    recompute_sql = conn.calls[2][1]
    assert "count(*)" in recompute_sql and "count(DISTINCT actor_key)" in recompute_sql

    kind, update_sql, args = conn.calls[3]
    assert kind == "execute"
    assert "+ 1" not in update_sql and "+1" not in update_sql
    assert args == (7, 11, 6, "critical")


def test_attach_incident_returns_the_campaign_id():
    conn = _FakeConn(campaign_id=123)
    db = _FakeDB(conn=conn)
    result = run(camp_repo.attach_incident(db, 42, "auth.ssh_bruteforce", "high"))
    assert result == 123


def test_attach_incident_runs_inside_one_transaction():
    """All four statements must go through the SAME connection out of
    `db.transaction()`, not `db.execute`/`db.fetchrow` directly — otherwise a
    concurrent call on the same family could observe the campaign linked to
    one incident but counted for another."""
    conn = _FakeConn()
    db = _FakeDB(conn=conn)
    run(camp_repo.attach_incident(db, 42, "auth.ssh_bruteforce", "high"))
    assert len(conn.calls) == 4


# --- quiet_stale -------------------------------------------------------------
def test_quiet_stale_only_touches_active_campaigns_past_the_threshold():
    """A campaign that is `quiet` or `closed` already, or one still within the
    quiet window, must not be touched — the WHERE clause is what stands
    between this and silently re-quieting or resurrecting the wrong rows."""
    db = _FakeDB(fetch_rows=[{"id": 1}, {"id": 2}])
    n = run(camp_repo.quiet_stale(db, 24))
    assert n == 2
    sql, args = db.fetch_calls[0]
    assert "status = 'active'" in sql
    assert "SET status = 'quiet', quieted_at = now()" in sql
    assert args == (24,)


def test_quiet_stale_default_is_the_named_constant_not_a_bare_number():
    """`CAMPAIGN_QUIET_HOURS` must be an absolute constant a caller can pass
    explicitly — `maintenance_service.quiet_campaigns` does — so a threshold
    written as `SOMETHING_ELSE + 8` elsewhere can never silently drift this
    one along with it."""
    assert camp_repo.CAMPAIGN_QUIET_HOURS == 24
    import inspect
    default = inspect.signature(camp_repo.quiet_stale).parameters["quiet_hours"].default
    assert default == camp_repo.CAMPAIGN_QUIET_HOURS


def test_quiet_stale_reports_zero_when_nothing_is_stale():
    db = _FakeDB(fetch_rows=[])
    assert run(camp_repo.quiet_stale(db, 24)) == 0


# --- active_campaigns --------------------------------------------------------
def test_active_campaigns_filters_to_active_only():
    """The dashboard and the Telegram summary must never see a `quiet` or
    `closed` campaign in this list — that is what distinguishes 'in progress'
    from 'closed the register on'."""
    db = _FakeDB(fetch_rows=[])
    run(camp_repo.active_campaigns(db))
    sql, _ = db.fetch_calls[0]
    assert "WHERE status = 'active'" in sql


def test_active_campaigns_returns_plain_dicts_of_the_fetched_rows():
    row = {"id": 1, "campaign_key": "auth.ssh_bruteforce", "severity": "high",
           "title": "Campanie: auth.ssh_bruteforce", "first_seen_at": None,
           "last_activity_at": None, "incident_count": 37, "actor_count": 37}
    db = _FakeDB(fetch_rows=[row])
    result = run(camp_repo.active_campaigns(db))
    assert result == [dict(row)]


# --- aggregate.campaigns: the dashboard's entry point ------------------------
def test_aggregate_campaigns_delegates_to_the_repo_not_a_second_query():
    """`page.py`, `maintenance_service.quiet_campaigns` and
    `insights._campaign_insight` must all read the SAME query. A second copy
    written directly in `aggregate.py` could drift from it silently — the
    exact failure mode `sources`/`_gap_insights` already guard against
    elsewhere in this codebase."""
    from sentinel.analytics import aggregate

    row = {"id": 1, "campaign_key": "auth.ssh_bruteforce", "severity": "high",
           "title": "t", "first_seen_at": None, "last_activity_at": None,
           "incident_count": 1, "actor_count": 1}
    db = _FakeDB(fetch_rows=[row])
    result = run(aggregate.campaigns(db))
    assert result == [dict(row)]
    sql, _ = db.fetch_calls[0]
    assert "FROM incident_campaigns" in sql and "WHERE status = 'active'" in sql
