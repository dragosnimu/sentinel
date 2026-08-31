"""`db/repo/incident_campaigns.py`: the campaign grouping layer.

Two tiers of test, deliberately:

* `_FakeConn`/`_FakeDB` answer by SQL substring and record every bound
  argument — enough to prove WIRING (which statement ran, in what order, on
  which connection) without a live database, the convention
  `tests/unit/test_intel_reputation.py` and
  `tests/unit/test_incidents_repo_reputation.py` already use.
* `_run_sqlite` executes the SHIPPED query text against a real, in-memory
  SQLite, translating only the PostgreSQL-only constructs it uses
  (`array_agg`, `array_position`/`ARRAY[...]`, `interval`) — same idiom as
  `tests/unit/test_aggregate.py`. This tier exists because round 1 of this
  feature shipped two defects that substring checks could not have caught:
  `active_campaigns`'s `ORDER BY` and `quiet_stale`'s `interval '1 hour'`
  can both be deleted or mangled while every substring-based test in this
  file stays green. A test that asserts on a real, computed result cannot
  do that — it has to run the ordering, or run the interval math, to pass.

Each test names the operator-visible failure it prevents.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import sqlite3

from sentinel.db.repo import incident_campaigns as camp_repo


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Tier 1: wiring, via a fake connection that only records calls
# ---------------------------------------------------------------------------
class _FakeConn:
    """What `db.transaction()` yields for `attach_incident`.

    `fetchval` is called exactly twice per run when the destination and the
    incident's previous campaign are the SAME (the upsert's `RETURNING id`,
    then the `SELECT campaign_id FROM incidents` lookup) — distinguished by
    call ORDER, since both are plausible with the same signature. Pass
    `old_campaign_id` to simulate an incident that already belonged to a
    DIFFERENT campaign.
    """

    def __init__(self, *, campaign_id=1, old_campaign_id=None):
        self.campaign_id = campaign_id
        self.old_campaign_id = campaign_id if old_campaign_id is None else old_campaign_id
        self.calls: list[tuple] = []
        self._fetchval_n = 0

    async def fetchval(self, sql, *args):
        self.calls.append(("fetchval", sql, args))
        self._fetchval_n += 1
        return self.campaign_id if self._fetchval_n == 1 else self.old_campaign_id

    async def fetchrow(self, sql, *args):
        self.calls.append(("fetchrow", sql, args))
        return None

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
    kind, sql, args = conn.calls[2]
    assert kind == "execute"
    assert "UPDATE incidents SET campaign_id" in sql
    assert args == (42, 99)


def test_attach_incident_recomputes_the_destination_not_an_increment():
    """The destination campaign's recompute statement must derive its numbers
    from `count(*)`/`count(DISTINCT actor_key)` over `incidents`, never from
    `+ 1` on the stored value — an incremented counter silently diverges the
    first time a call is retried or an incident moves. See `CLAUDE.md` on
    this exact class of bug, and the real-counting test below for the case
    an increment-based implementation could not even express: a campaign
    whose membership went DOWN."""
    conn = _FakeConn(campaign_id=7)
    db = _FakeDB(conn=conn)
    run(camp_repo.attach_incident(db, 42, "auth.ssh_bruteforce", "high"))

    kind, recompute_sql, args = conn.calls[3]
    assert kind == "execute"
    assert "count(*)" in recompute_sql and "count(DISTINCT actor_key)" in recompute_sql
    assert "+ 1" not in recompute_sql and "+1" not in recompute_sql
    assert args == (7,)


def test_attach_incident_returns_the_campaign_id():
    conn = _FakeConn(campaign_id=123)
    db = _FakeDB(conn=conn)
    result = run(camp_repo.attach_incident(db, 42, "auth.ssh_bruteforce", "high"))
    assert result == 123


def test_attach_incident_runs_inside_one_transaction():
    """Every statement must go through the SAME connection out of
    `db.transaction()`, not `db.execute`/`db.fetchrow` directly — otherwise a
    concurrent call on the same family could observe the campaign linked to
    one incident but counted for another."""
    conn = _FakeConn()
    db = _FakeDB(conn=conn)
    run(camp_repo.attach_incident(db, 42, "auth.ssh_bruteforce", "high"))
    assert len(conn.calls) == 4
    assert all(c is not None for c in conn.calls)  # all four went through `conn`


def test_attach_incident_also_recomputes_the_incidents_previous_campaign():
    """Wiring check: when the incident already belonged to a DIFFERENT
    campaign, a second recompute must run against that OLD campaign id, not
    just the destination. This only proves the call happens — the real-count
    proof that the numbers it produces are correct is
    `test_attach_incident_recomputes_the_source_campaign_when_an_incident_moves`
    below."""
    conn = _FakeConn(campaign_id=12, old_campaign_id=11)
    db = _FakeDB(conn=conn)
    run(camp_repo.attach_incident(db, 42, "net.x", "high"))
    assert len(conn.calls) == 5
    kind, dest_sql, dest_args = conn.calls[3]
    assert kind == "execute" and dest_args == (12,)
    kind, src_sql, src_args = conn.calls[4]
    assert kind == "execute" and src_args == (11,)
    # The destination gets fresh activity; the source does not (see
    # `_recompute`'s docstring — losing a member is bookkeeping, not activity).
    assert "last_activity_at = now()" in dest_sql
    assert "last_activity_at = now()" not in src_sql


def test_attach_incident_does_not_recompute_twice_when_campaign_is_unchanged():
    """The common case — an incident already in its family's only active
    campaign — must not pay for or risk a second, no-op recompute."""
    conn = _FakeConn(campaign_id=7)  # old_campaign_id defaults to the same value
    db = _FakeDB(conn=conn)
    run(camp_repo.attach_incident(db, 42, "auth.ssh_bruteforce", "high"))
    assert len(conn.calls) == 4


# ---------------------------------------------------------------------------
# Tier 2: real execution against SQLite — ordering, interval math, real counts
# ---------------------------------------------------------------------------
#: Same severity order as `_SEVERITY_ORDER_SQL` in the module under test,
#: rewritten as a `CASE` expression because SQLite has no `array_position`.
_SEV_CASE = ("CASE severity WHEN 'info' THEN 1 WHEN 'low' THEN 2 WHEN 'medium' THEN 3 "
             "WHEN 'high' THEN 4 WHEN 'critical' THEN 5 END")

#: Constructs the shipped queries use that SQLite does not understand at all.
#: If any of these survive `_tradu`, a translation was missed and the test
#: MUST fail loudly here rather than pass on a query it silently never ran
#: (or fail later with an opaque `sqlite3.OperationalError` that looks like a
#: real behavioural mismatch).
_RAMASE_PG = ("array_agg(", "ARRAY[", "::int", "interval '")


def _tradu(sql: str) -> str:
    """Rewrite the PostgreSQL-only constructs `incident_campaigns.py` uses
    into SQLite equivalents that mean the same thing — a change of form, not
    of meaning, same convention as `test_aggregate.py`'s `_tradu`."""
    # SQLite requires an explicit `AS` for a table alias in `UPDATE ... FROM`;
    # Postgres allows the bare form `_recompute` uses.
    sql = sql.replace("UPDATE incident_campaigns c", "UPDATE incident_campaigns AS c")

    # `now() - ($1::int * interval '1 hour')`, `quiet_stale`'s threshold —
    # matched and replaced WHOLE (not just `interval '1 hour'` in isolation)
    # so the hour/minute unit stays live in the translated text: a mutation
    # that swaps `'1 hour'` for `'1 minute'` in the SOURCE file changes what
    # this regex captures and what it emits, so the real semantics still
    # differ before and after the mutation — unlike a translation that hard-
    # codes "hours" regardless of what the source said.
    sql = re.sub(
        r"now\(\)\s*-\s*\(\$1::int \* interval '1 (\w+)'\)",
        lambda m: "datetime('now', '-' || CAST($1 AS TEXT) || ' " + m.group(1) + "s')",
        sql)

    # `(array_agg(severity ORDER BY array_position(ARRAY[...], severity) DESC))[1]`
    # from `_recompute` — SQLite has no `array_agg`. A correlated scalar
    # subquery over the SAME `campaign_id = $1` picks the same "severity of
    # the highest-ranked member" value.
    sql = re.sub(
        r"\(array_agg\(severity ORDER BY array_position\(\s*"
        r"ARRAY\['info','low','medium','high','critical'\],\s*severity\) DESC\)\)\[1\]",
        f"(SELECT severity FROM incidents WHERE campaign_id = $1 ORDER BY {_SEV_CASE} DESC LIMIT 1)",
        sql, flags=re.S)

    # Bare `array_position(ARRAY[...], severity)`, from `active_campaigns`'s
    # `ORDER BY` — a straight rank expression.
    sql = re.sub(
        r"array_position\(\s*ARRAY\['info','low','medium','high','critical'\],\s*severity\)",
        _SEV_CASE, sql)

    sql = sql.replace("now()", "datetime('now')")

    ramase = [c for c in _RAMASE_PG if c in sql]
    assert not ramase, f"construct PostgreSQL netradus: {ramase}\n{sql}"
    return sql


def _compile(sql: str, args: tuple):
    """`$1, $2, ...` -> `?`, in order of appearance, expanding repeats — the
    real queries here reuse `$1` more than once in the same statement, which
    positional `?` cannot do on its own."""
    nums = [int(n) for n in re.findall(r"\$(\d+)", sql)]
    sql = re.sub(r"\$\d+", "?", sql)
    return sql, [args[n - 1] for n in nums]


class _SQLiteConn:
    """A real `sqlite3.Connection` behind the same async surface
    `incident_campaigns.py` calls on both `db` and `db.transaction()`'s
    connection — no separate fake needed for each, since SQLite does not
    need a second connection to observe transactional state here."""

    def __init__(self, con):
        self.con = con

    async def execute(self, sql, *args):
        s, a = _compile(_tradu(sql), args)
        self.con.execute(s, a)
        return "OK"

    async def fetchval(self, sql, *args):
        s, a = _compile(_tradu(sql), args)
        row = self.con.execute(s, a).fetchone()
        return row[0] if row else None

    async def fetchrow(self, sql, *args):
        s, a = _compile(_tradu(sql), args)
        row = self.con.execute(s, a).fetchone()
        return dict(row) if row else None

    async def fetch(self, sql, *args):
        s, a = _compile(_tradu(sql), args)
        return [dict(r) for r in self.con.execute(s, a).fetchall()]

    @contextlib.asynccontextmanager
    async def transaction(self):
        yield self


def _sqlite_db() -> _SQLiteConn:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("""
        CREATE TABLE incident_campaigns (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_key      TEXT NOT NULL,
            status            TEXT NOT NULL DEFAULT 'active',
            severity          TEXT NOT NULL,
            title             TEXT NOT NULL,
            first_seen_at     TEXT NOT NULL DEFAULT (datetime('now')),
            last_activity_at  TEXT NOT NULL DEFAULT (datetime('now')),
            incident_count    INTEGER NOT NULL DEFAULT 0,
            actor_count       INTEGER NOT NULL DEFAULT 0,
            quieted_at        TEXT,
            closed_at         TEXT
        )
    """)
    con.execute("""
        CREATE UNIQUE INDEX incident_campaigns_key_active_idx
            ON incident_campaigns (campaign_key) WHERE status = 'active'
    """)
    con.execute("""
        CREATE TABLE incidents (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id  INTEGER,
            actor_key    TEXT,
            severity     TEXT NOT NULL
        )
    """)
    return _SQLiteConn(con)


def test_attach_incident_recomputes_the_source_campaign_when_an_incident_moves():
    """The scenario found in round 1 review, reproduced exactly: incident #1
    is still attached to campaign 11 (`quiet`, holding stale counters from
    before it went quiet); `attach_incident` is now called for it again
    (the case where a quiet campaign's last remaining open incident gets
    fresh activity, so it is re-attached to a freshly-opened ACTIVE campaign
    for the same family — see the module docstring on why quiet campaigns
    never reactivate).

    Proven by REAL counting, not by asserting a call happened: after the
    move, campaign 11's stored `incident_count` must equal
    `SELECT count(*) FROM incidents WHERE campaign_id = 11` — zero, since its
    only member just left. Before this fix, campaign 11 kept its stale
    `incident_count = 1` forever, contradicting `quiet_stale`'s own promise
    that quieted campaigns "stay on record" (a wrong record, kept)."""
    db = _sqlite_db()
    con = db.con
    con.execute(
        "INSERT INTO incident_campaigns (id, campaign_key, status, severity, title, "
        "incident_count, actor_count) VALUES (11, 'net.x', 'quiet', 'medium', 't', 1, 1)")
    con.execute(
        "INSERT INTO incidents (id, campaign_id, actor_key, severity) "
        "VALUES (1, 11, 'a1', 'medium')")
    con.commit()

    new_id = run(camp_repo.attach_incident(db, 1, "net.x", "high"))
    assert new_id != 11  # moved to a NEW campaign, not the quiet one

    real_old_count = con.execute(
        "SELECT count(*) FROM incidents WHERE campaign_id = 11").fetchone()[0]
    stored_old_count = con.execute(
        "SELECT incident_count FROM incident_campaigns WHERE id = 11").fetchone()[0]
    assert stored_old_count == real_old_count == 0

    old_status = con.execute(
        "SELECT status FROM incident_campaigns WHERE id = 11").fetchone()[0]
    assert old_status == "quiet"  # stays on record, not resurrected, not deleted

    real_new_count = con.execute(
        f"SELECT count(*) FROM incidents WHERE campaign_id = {new_id}").fetchone()[0]
    stored_new_count = con.execute(
        f"SELECT incident_count FROM incident_campaigns WHERE id = {new_id}").fetchone()[0]
    assert stored_new_count == real_new_count == 1


def test_active_campaigns_orders_by_severity_not_by_row_order():
    """`active_campaigns` must order by SEVERITY first — a `critical` front
    with one incident has to lead a `medium` front with hundreds, when a
    human reads the list directly. Rows are inserted here in the OPPOSITE
    order (biggest/lowest-severity first) so a missing or reordered
    `ORDER BY` cannot pass by coincidence, the way it would if insertion
    order already matched the expected order."""
    db = _sqlite_db()
    con = db.con
    con.execute(
        "INSERT INTO incident_campaigns (id, campaign_key, status, severity, title, "
        "incident_count, actor_count) VALUES (1, 'fam.brute', 'active', 'medium', 't', 500, 500)")
    con.execute(
        "INSERT INTO incident_campaigns (id, campaign_key, status, severity, title, "
        "incident_count, actor_count) VALUES (2, 'fam.tiny', 'active', 'critical', 't', 1, 1)")
    con.execute(
        "INSERT INTO incident_campaigns (id, campaign_key, status, severity, title) "
        "VALUES (3, 'fam.quiet', 'quiet', 'high', 't')")
    con.commit()

    rows = run(camp_repo.active_campaigns(db))
    assert [r["campaign_key"] for r in rows] == ["fam.tiny", "fam.brute"]  # critical first
    assert "fam.quiet" not in [r["campaign_key"] for r in rows]  # not active


def test_quiet_stale_uses_hours_not_some_other_unit():
    """`quiet_hours=24` must mean 24 HOURS, real elapsed time — not 24
    minutes, 24 days, or any other unit a typo could substitute. A campaign
    2 hours old must stay `active` (well under any 24-hour threshold); one
    30 hours old must go `quiet`. If the unit were minutes, the 2-hour-old
    row (120 minutes) would ALSO cross a 24-minute threshold and be quieted
    incorrectly — which is exactly what distinguishes this test from one
    that would pass under either unit."""
    db = _sqlite_db()
    con = db.con
    con.execute(
        "INSERT INTO incident_campaigns (id, campaign_key, status, severity, title, "
        "last_activity_at) VALUES (1, 'fam.fresh', 'active', 'medium', 't', "
        "datetime('now', '-2 hours'))")
    con.execute(
        "INSERT INTO incident_campaigns (id, campaign_key, status, severity, title, "
        "last_activity_at) VALUES (2, 'fam.stale', 'active', 'medium', 't', "
        "datetime('now', '-30 hours'))")
    con.commit()

    n = run(camp_repo.quiet_stale(db, 24))
    assert n == 1

    statuses = dict(con.execute(
        "SELECT campaign_key, status FROM incident_campaigns").fetchall())
    assert statuses["fam.fresh"] == "active"
    assert statuses["fam.stale"] == "quiet"


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
    db = _sqlite_db()
    assert run(camp_repo.quiet_stale(db, 24)) == 0


def test_active_campaigns_returns_plain_dicts():
    db = _sqlite_db()
    db.con.execute(
        "INSERT INTO incident_campaigns (id, campaign_key, status, severity, title, "
        "incident_count, actor_count) VALUES (1, 'auth.ssh_bruteforce', 'active', "
        "'high', 'Campanie: auth.ssh_bruteforce', 37, 37)")
    db.con.commit()
    result = run(camp_repo.active_campaigns(db))
    assert len(result) == 1
    assert isinstance(result[0], dict)
    assert result[0]["campaign_key"] == "auth.ssh_bruteforce"
    assert result[0]["incident_count"] == 37


# ---------------------------------------------------------------------------
# aggregate.campaigns: the dashboard's entry point
# ---------------------------------------------------------------------------
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
