"""Stratul de bază pentru Funcționalitatea 08: selecția candidaților, latch-ul
de oprire, dovada de arhivă și jurnalul de rulare.

Fiecare test probează o decizie din interogare, nu doar că a fost apelată —
o interogare care pare corectă dar alege primul eșec în loc de cel mai vechi
ar raporta un alt plan drept cel care a declanșat oprirea.
"""
from __future__ import annotations

import asyncio
import json

from sentinel.db.repo import patches as repo


def run(c):
    return asyncio.run(c)


class _FetchDB:
    def __init__(self, *, fetch_rows=None, fetchrow_row=None, fetchval_value=None):
        self.fetch_rows = fetch_rows if fetch_rows is not None else []
        self.fetchrow_row = fetchrow_row
        self.fetchval_value = fetchval_value
        self.fetch_sql: str | None = None
        self.fetch_args: tuple = ()
        self.fetchrow_sql: str | None = None
        self.fetchval_sql: str | None = None
        self.fetchval_args: tuple = ()

    async def fetch(self, sql, *a):
        self.fetch_sql = sql; self.fetch_args = a
        return self.fetch_rows

    async def fetchrow(self, sql, *a):
        self.fetchrow_sql = sql
        return self.fetchrow_row

    async def fetchval(self, sql, *a):
        self.fetchval_sql = sql; self.fetchval_args = a
        return self.fetchval_value

    async def execute(self, sql, *a):
        return "UPDATE 1"


# --- candidates --------------------------------------------------------------
def test_candidates_exclude_plans_the_window_already_decided_on():
    db = _FetchDB(fetch_rows=[])
    run(repo.window_candidate_plans(db, limit=7))
    assert "status = 'validated'" in db.fetch_sql
    assert "NOT proposed_by_window" in db.fetch_sql
    assert db.fetch_args[-1] == 7


def test_candidates_are_ordered_oldest_first():
    """Un plan care așteaptă de o săptămână nu are voie să fie sărit mereu de
    unul generat aseară."""
    db = _FetchDB()
    run(repo.window_candidate_plans(db))
    assert "ORDER BY created_at" in db.fetch_sql
    assert "DESC" not in db.fetch_sql.split("ORDER BY created_at")[1].split("LIMIT")[0]


# --- outstanding ---------------------------------------------------------
def test_outstanding_only_matches_still_pending_window_plans():
    db = _FetchDB(fetchrow_row=None)
    result = run(repo.outstanding_window_plan(db))
    assert result is None
    assert "proposed_by_window" in db.fetchrow_sql
    assert "status = 'validated'" in db.fetchrow_sql


# --- releasing -------------------------------------------------------------
def test_marking_released_flips_exactly_that_plan():
    class _ExecDB:
        def __init__(self):
            self.calls = []
        async def execute(self, sql, *a):
            self.calls.append((sql, a))
            return "UPDATE 1"

    db = _ExecDB()
    run(repo.mark_proposed_by_window(db, 55))
    sql, args = db.calls[0]
    assert "proposed_by_window = true" in sql
    assert "WHERE id = $1" in sql
    assert args == (55,)


# --- the halt latch ----------------------------------------------------------
def test_halt_looks_only_at_window_released_apply_failures():
    db = _FetchDB(fetchrow_row=None)
    result = run(repo.window_halt(db))
    assert result is None
    sql = db.fetchrow_sql
    assert "p.proposed_by_window" in sql
    assert "e.mode = 'apply'" in sql
    assert "'failed'" in sql and "'rolled_back'" in sql and "'rollback_failed'" in sql


def test_halt_reports_the_earliest_failure_not_the_latest():
    """«Oprire la primul eșec» — dacă interogarea ar lua ultimul eșec în loc
    de primul, mesajul către operator ar acuza planul greșit."""
    db = _FetchDB(fetchrow_row={"execution_id": 1, "plan_id": 9, "status": "failed",
                                "finished_at": None})
    run(repo.window_halt(db))
    assert "ORDER BY e.finished_at ASC" in db.fetchrow_sql


# --- archive evidence ---------------------------------------------------------
def test_no_archive_evidence_returns_none():
    db = _FetchDB(fetchrow_row=None)
    assert run(repo.latest_archive_drill_summary(db)) is None


def test_archive_evidence_is_aggregated_over_the_whole_latest_drill():
    """Nu pe un singur artefact: un exercițiu cu o arhivă bună și una coruptă
    nu are voie să raporteze doar partea bună."""
    db = _FetchDB(fetchrow_row={"performed_at": None, "age_days": 3.0,
                                "any_bad": True, "all_good": False})
    out = run(repo.latest_archive_drill_summary(db))
    assert out == {"performed_at": None, "age_days": 3.0, "any_bad": True, "all_good": False}
    assert "is_archive" in db.fetchrow_sql
    assert "bool_or" in db.fetchrow_sql and "bool_and" in db.fetchrow_sql


# --- the run log ---------------------------------------------------------
def test_every_run_is_recorded_even_with_nothing_to_report():
    class _ValDB:
        def __init__(self):
            self.calls = []
        async def fetchval(self, sql, *a):
            self.calls.append((sql, a))
            return 1

    db = _ValDB()
    run_id = run(repo.record_window_run(
        db, candidates=0, proposed_plan_id=None, halted=False,
        detail="nimic de propus", skipped=[]))
    assert run_id == 1
    sql, args = db.calls[0]
    assert "INSERT INTO patch_window_runs" in sql
    assert args[0] == 0 and args[1] is None and args[2] is False


def test_last_run_decodes_the_skipped_list():
    db = _FetchDB(fetchrow_row={
        "id": 1, "ran_at": None, "candidates": 2, "proposed_plan_id": None,
        "halted": False, "detail": "x",
        "skipped": json.dumps([{"plan_id": 4, "state": "unproven", "reason": "y"}])})
    out = run(repo.last_window_run(db))
    assert out["skipped"] == [{"plan_id": 4, "state": "unproven", "reason": "y"}]


def test_no_run_yet_is_none():
    db = _FetchDB(fetchrow_row=None)
    assert run(repo.last_window_run(db)) is None
