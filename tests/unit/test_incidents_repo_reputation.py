"""`db/repo/incidents.py`: the actor-side plumbing feeding `respond/decider.py`.

No live Postgres in this suite (see `tests/conftest.py`) — `_FakeDB` captures
the exact SQL and bound arguments `upsert_actor`/`actor_flags` send, which is
what a wrong argument ORDER or a wrong NULL-vs-empty choice would get wrong
silently against a real database.
"""

from __future__ import annotations

import asyncio

from sentinel.db.repo import incidents as inc_repo


def run(coro):
    return asyncio.run(coro)


class _FakeDB:
    def __init__(self, *, fetchrow_result=None):
        self.fetchrow_result = fetchrow_result
        self.execute_calls: list[tuple] = []

    async def execute(self, sql, *args):
        self.execute_calls.append((sql, args))
        return "INSERT 0 1"

    async def fetchrow(self, sql, *args):
        return self.fetchrow_result


def test_actor_flags_missing_actor_reads_as_no_reputation_no_flags():
    """An actor never seen by the enrichment pass must read as `[]`/`False`,
    never as `unknown` — the decider treats absence exactly like "no feed
    match", which is the correct default; a wrong sentinel here (e.g. raising,
    or returning None) would crash guard 2's `any(cat in ... for cat in
    flags.get('reputation', ()))` call in `respond/decider.py`."""
    db = _FakeDB(fetchrow_result=None)
    flags = run(inc_repo.actor_flags(db, "198.51.100.7"))
    assert flags == {"is_allowlisted": False, "is_known_scanner": False, "reputation": []}


def test_actor_flags_converts_the_reputation_array():
    """A real row's `reputation` (a Postgres `text[]`, read back by asyncpg as
    a Python list) must come through as a plain list the decider can iterate
    with `any(... for cat in flags['reputation'])`."""
    db = _FakeDB(fetchrow_result={
        "is_allowlisted": False, "is_known_scanner": False,
        "reputation": ["botnet", "drop"]})
    flags = run(inc_repo.actor_flags(db, "198.51.100.7"))
    assert flags["reputation"] == ["botnet", "drop"]


def test_actor_flags_null_reputation_array_is_an_empty_list():
    """Defensive against a NULL array reaching Python (should not happen —
    the column is NOT NULL DEFAULT '{}' since migration 0001 — but `row[...]
    or []` is what stands between a NULL slipping through and a crash in the
    decider's `any(...)` over `None`)."""
    db = _FakeDB(fetchrow_result={
        "is_allowlisted": False, "is_known_scanner": False, "reputation": None})
    flags = run(inc_repo.actor_flags(db, "198.51.100.7"))
    assert flags["reputation"] == []


def test_upsert_actor_reputation_none_is_distinct_from_empty_list():
    """`None` (caller did not look up) and `[]` (looked up, found nothing
    hostile) must bind as DIFFERENT SQL parameters — the whole point of the
    distinction documented in `upsert_actor`'s docstring. If both collapsed to
    the same bound value, a lookup failure and a clean lookup would be
    indistinguishable to the database, and `CASE WHEN $7::text[] IS NULL ...`
    could never tell them apart."""
    db = _FakeDB()
    run(inc_repo.upsert_actor(db, "198.51.100.7", src_ip="198.51.100.7",
                              reputation=None, is_known_scanner=None))
    _, args_none = db.execute_calls[0]

    db2 = _FakeDB()
    run(inc_repo.upsert_actor(db2, "198.51.100.7", src_ip="198.51.100.7",
                              reputation=[], is_known_scanner=False))
    _, args_empty = db2.execute_calls[0]

    # Position 6 (0-indexed) is `reputation`, position 7 is `is_known_scanner`
    # — see the `$7`/`$8` binds in `upsert_actor`.
    assert args_none[6] is None
    assert args_empty[6] == []
    assert args_none[7] is None
    assert args_empty[7] is False


def test_upsert_actor_binds_eight_positional_arguments():
    """Pins the argument count against the SQL's `$1`..`$8` placeholders — a
    parameter added to one side without the other is exactly the kind of
    drift that only shows up against a real database, at 3 a.m."""
    db = _FakeDB()
    run(inc_repo.upsert_actor(db, "198.51.100.7", src_ip="198.51.100.7",
                              reputation=["botnet"], is_known_scanner=False))
    sql, args = db.execute_calls[0]
    assert len(args) == 8
    assert sql.count("$7") >= 1 and sql.count("$8") >= 1
