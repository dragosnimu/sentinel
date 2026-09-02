"""Stratul de bază pentru Funcționalitatea 08: selecția candidaților, latch-ul
de oprire, dovada de arhivă și jurnalul de rulare.

Runda 2 a arătat că o aserțiune pe SUBȘIRUL clauzei WHERE trece chiar dacă
interogarea a fost mutată într-o tautologie: adăugând ` OR TRUE` la coadă,
precedența SQL transformă `A AND B OR TRUE` în `(A AND B) OR TRUE`, adică
„orice rând" — fiecare subșir căutat rămâne prezent, dar decizia reală
dispare. De aceea testele critice de mai jos EXECUTĂ clauza (peste SQLite, cu
substituțiile PostgreSQL-specifice documentate la fiecare test) peste rânduri
concrete: o asemenea mutație produce un rezultat greșit observabil, nu doar
un text care conține subșirurile căutate.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3

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


# --- shared execution helper --------------------------------------------------
def _where_and_order(sql: str) -> str:
    """Tot ce e după `WHERE`, inclusiv `ORDER BY`/`LIMIT` dacă există — nu doar
    fragmentul dinainte de primul cuvânt cheie, ca reordonarea clauzelor să nu
    scape testului."""
    return sql.split("WHERE", 1)[1].strip()


def _bool_or_and():
    class _BoolOr:
        def __init__(self):
            self.value = 0
        def step(self, v):
            if v:
                self.value = 1
        def finalize(self):
            return self.value

    class _BoolAnd:
        def __init__(self):
            self.value = 1
        def step(self, v):
            if not v:
                self.value = 0
        def finalize(self):
            return self.value
    return _BoolOr, _BoolAnd


# ===========================================================================
# window_candidate_plans — cine intră pe lista pe care fereastra o citește
# ===========================================================================
def test_candidates_exclude_plans_the_window_already_decided_on():
    db = _FetchDB(fetch_rows=[])
    run(repo.window_candidate_plans(db, limit=7))
    assert "status = 'validated'" in db.fetch_sql
    assert "NOT proposed_by_window" in db.fetch_sql
    assert db.fetch_args == (repo.WINDOW_CANDIDATE_MAX_AGE_DAYS, 7)


def test_candidates_are_ordered_oldest_first():
    """Un plan care așteaptă de o săptămână nu are voie să fie sărit mereu de
    unul generat aseară."""
    db = _FetchDB()
    run(repo.window_candidate_plans(db))
    assert "ORDER BY created_at" in db.fetch_sql
    assert "DESC" not in db.fetch_sql.split("ORDER BY created_at")[1].split("LIMIT")[0]


def test_candidates_are_bounded_in_age_when_executed():
    """Runda 2: fără plafon, un plan validat acum patru luni ar rămâne pentru
    totdeauna primul candidat. EXECUTAT peste SQLite: un plan mai vechi decât
    `WINDOW_CANDIDATE_MAX_AGE_DAYS` nu are voie să apară în rezultat, oricât
    de „bine" ar arăta clauza citită ca text."""
    where = _where_and_order(
        run(_capture_sql(repo.window_candidate_plans)))
    # `now() - make_interval(days => $1)` -> literal legat, ca sub asyncpg;
    # `$1`/`$2` -> `?` pozițional pentru sqlite3.
    where_sqlite = (where
        .replace("now() - make_interval(days => $1)", "?")
        .replace("$2", "?"))

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE patch_plans (id INTEGER, status TEXT, "
                 "proposed_by_window INTEGER, created_at TEXT)")
    old_cutoff = "2026-08-01T00:00:00+00:00"
    conn.executemany("INSERT INTO patch_plans VALUES (?,?,?,?)", [
        (1, "validated", 0, "2026-08-02T00:00:00+00:00"),   # fresh enough -> in
        (2, "validated", 0, "2026-01-01T00:00:00+00:00"),   # too old -> out
        (3, "validated", 1, "2026-08-02T00:00:00+00:00"),   # already released -> out
        (4, "rejected", 0, "2026-08-02T00:00:00+00:00"),    # wrong status -> out
    ])
    sql = f"SELECT id FROM patch_plans WHERE {where_sqlite}".replace(
        "ORDER BY created_at", "ORDER BY created_at").replace("LIMIT ?", "LIMIT ?")
    matched = {r[0] for r in conn.execute(sql, (old_cutoff, 10))}
    assert matched == {1}, matched


async def _capture_sql(fn):
    """Cheamă `fn` cu un `_FetchDB` și întoarce textul SQL folosit — un
    generator mic, ca `test_candidates_are_bounded_in_age_when_executed` să
    nu-și scrie singur ciotul."""
    db = _FetchDB(fetch_rows=[])
    await fn(db)
    return db.fetch_sql


# ===========================================================================
# expire_stale_window_candidates — imbatranirea trebuie sa fie productiva
# ===========================================================================
def test_expiring_targets_only_ai_unreleased_validated_plans():
    db = _FetchDB(fetch_rows=[])
    run(repo.expire_stale_window_candidates(db, max_age_days=30))
    sql = db.fetch_sql
    assert "SET status = 'expired'" in sql
    assert "status = 'validated'" in sql
    assert "generated_by = 'ai'" in sql
    assert "NOT proposed_by_window" in sql
    assert db.fetch_args == (30,)


def test_expiring_executed_only_moves_plans_past_the_bound():
    """Runda 3: gasit la revizuire ca planurile care depasesc plafonul
    disparea tacut din candidatura, fara nicio expirare productiva. EXECUTAT
    peste SQLite: doar planul CHIAR mai vechi decat plafonul trece la
    'expired' -- un plan proaspat, unul deja eliberat, unul deja rezolvat sau
    unul non-AI raman neatinse."""
    sql = run(_capture_sql(
        lambda db: repo.expire_stale_window_candidates(db, max_age_days=30)))
    where = _where_and_order(sql).replace("now() - make_interval(days => $1)", "?")

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE patch_plans (id INTEGER, status TEXT, "
                 "generated_by TEXT, proposed_by_window INTEGER, created_at TEXT)")
    old_cutoff = "2026-08-01T00:00:00+00:00"
    conn.executemany("INSERT INTO patch_plans VALUES (?,?,?,?,?)", [
        (1, "validated", "ai", 0, "2026-01-01T00:00:00+00:00"),   # stale -> expires
        (2, "validated", "ai", 0, "2026-08-15T00:00:00+00:00"),   # fresh -> stays
        (3, "validated", "ai", 1, "2026-01-01T00:00:00+00:00"),   # released -> stays
        (4, "approved", "ai", 0, "2026-01-01T00:00:00+00:00"),    # not validated -> stays
        (5, "validated", "manual", 0, "2026-01-01T00:00:00+00:00"),  # not AI -> stays
    ])
    sql2 = f"UPDATE patch_plans SET status = 'expired' WHERE {where}"
    conn.execute(sql2, (old_cutoff,))
    statuses = dict(conn.execute("SELECT id, status FROM patch_plans"))
    assert statuses == {1: "expired", 2: "validated", 3: "validated",
                        4: "approved", 5: "validated"}


# ===========================================================================
# outstanding_window_plan
# ===========================================================================
def test_outstanding_only_matches_still_pending_window_plans():
    db = _FetchDB(fetchrow_row=None)
    result = run(repo.outstanding_window_plan(db))
    assert result is None
    assert "proposed_by_window" in db.fetchrow_sql
    assert "status = 'validated'" in db.fetchrow_sql


def test_outstanding_executed_ignores_resolved_and_non_window_plans():
    """Interogarea e ANSI SQL pură — executată verbatim, fără nicio
    substituție."""
    sql = run(_capture_row_sql(repo.outstanding_window_plan))
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE patch_plans (id INTEGER, created_at TEXT, "
                 "proposed_by_window INTEGER, status TEXT)")
    conn.executemany("INSERT INTO patch_plans VALUES (?,?,?,?)", [
        (1, "2026-08-01", 0, "validated"),   # not released -> not outstanding
        (2, "2026-08-02", 1, "approved"),    # released but resolved -> not outstanding
        (3, "2026-08-03", 1, "validated"),   # released, still pending -> THE one
        (4, "2026-08-04", 1, "validated"),   # released, pending, but not the oldest
    ])
    got = conn.execute(sql).fetchone()
    assert got == (3, "2026-08-03")


async def _capture_row_sql(fn):
    db = _FetchDB(fetchrow_row=None)
    await fn(db)
    return db.fetchrow_sql


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


# ===========================================================================
# the informational notice (Funcționalitatea 08, runda 2)
# ===========================================================================
def test_gated_notice_candidates_are_only_ai_and_not_yet_released():
    db = _FetchDB(fetch_rows=[])
    run(repo.unnotified_window_gated_plans(db, limit=5))
    sql = db.fetch_sql
    assert "window_notice_sent_at IS NULL" in sql
    assert "generated_by = 'ai'" in sql
    assert "NOT proposed_by_window" in sql
    assert db.fetch_args[-1] == 5


def test_gated_notice_selection_executed_excludes_released_and_non_ai():
    sql = run(_capture_sql(repo.unnotified_window_gated_plans))
    where = _where_and_order(sql).replace("$1", "?")
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE patch_plans (id INTEGER, window_notice_sent_at TEXT, "
                 "status TEXT, generated_by TEXT, proposed_by_window INTEGER, "
                 "created_at TEXT)")
    conn.executemany("INSERT INTO patch_plans VALUES (?,?,?,?,?,?)", [
        (1, None, "validated", "ai", 0, "2026-08-01"),   # candidate
        (2, "2026-08-05", "validated", "ai", 0, "2026-08-01"),  # already notified -> out
        (3, None, "validated", "ai", 1, "2026-08-01"),   # already released -> out
        (4, None, "validated", "manual", 0, "2026-08-01"),  # not AI -> out
    ])
    sql2 = f"SELECT id FROM patch_plans WHERE {where}"
    matched = {r[0] for r in conn.execute(sql2, (5,))}
    assert matched == {1}, matched


def test_marking_notice_sent_stamps_only_that_plan():
    class _ExecDB:
        def __init__(self):
            self.calls = []
        async def execute(self, sql, *a):
            self.calls.append((sql, a))
            return "UPDATE 1"

    db = _ExecDB()
    run(repo.mark_window_notice_sent(db, 9))
    sql, args = db.calls[0]
    assert "window_notice_sent_at = now()" in sql
    assert args == (9,)


# ===========================================================================
# the halt latch, and the override that does not rewrite history
# ===========================================================================
def test_halt_looks_only_at_window_released_apply_failures():
    db = _FetchDB(fetchrow_row=None)
    result = run(repo.window_halt(db))
    assert result is None
    sql = db.fetchrow_sql
    assert "p.proposed_by_window" in sql
    assert "e.mode = 'apply'" in sql
    assert "'failed'" in sql and "'rolled_back'" in sql and "'rollback_failed'" in sql
    assert "patch_window_overrides" in sql


def test_halt_executed_reports_the_earliest_unoverridden_failure():
    """EXECUTAT peste SQLite, verbatim (interogarea e ANSI SQL pură — niciun
    `now()`, niciun `make_interval`). Falsifică precis defectul găsit la
    revizuire: dacă `ORDER BY` ar fi `DESC` sau `NOT EXISTS` ar lipsi, testul
    ăsta pică pe un rezultat greșit, nu pe un subșir lipsă."""
    sql = run(_capture_row_sql(repo.window_halt))

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE patch_plans (id INTEGER PRIMARY KEY, proposed_by_window INTEGER)")
    conn.execute("CREATE TABLE patch_executions (id INTEGER PRIMARY KEY, plan_id INTEGER, "
                 "mode TEXT, status TEXT, finished_at TEXT)")
    conn.execute("CREATE TABLE patch_window_overrides (execution_id INTEGER)")
    conn.executemany("INSERT INTO patch_plans VALUES (?,?)", [
        (1, 1), (2, 1), (3, 0),
    ])
    conn.executemany("INSERT INTO patch_executions VALUES (?,?,?,?,?)", [
        (10, 3, "apply", "failed", "2026-08-01"),     # non-window plan -> ignored
        (11, 1, "dry_run", "failed", "2026-08-02"),   # not an apply -> ignored
        (12, 1, "apply", "succeeded", "2026-08-03"),  # not a failure -> ignored
        (13, 1, "apply", "failed", "2026-08-04"),     # THE earliest real failure
        (14, 2, "apply", "rolled_back", "2026-08-05"),  # later -> must not win
    ])
    row = conn.execute(sql).fetchone()
    assert row[0] == 13, row  # execution_id: the earliest failure, not #14

    # Now override #13. The latch must move to the NEXT unoverridden failure —
    # #14 — not disappear entirely and not still report #13.
    conn.execute("INSERT INTO patch_window_overrides VALUES (13)")
    row2 = conn.execute(sql).fetchone()
    assert row2[0] == 14, row2

    # Override everything: the latch must lift.
    conn.execute("INSERT INTO patch_window_overrides VALUES (14)")
    row3 = conn.execute(sql).fetchone()
    assert row3 is None


def test_recording_an_override_writes_a_new_row_not_an_update():
    """Vezi migrația 0043: desfacerea zăvorului trebuie să lase urmă, nu să
    rescrie `patch_executions`."""
    class _ExecDB:
        def __init__(self):
            self.calls = []
        async def fetchval(self, sql, *a):
            self.calls.append((sql, a))
            return 1

    db = _ExecDB()
    override_id = run(repo.record_window_override(
        db, execution_id=13, by="telegram:1", reason="analizat, downgrade manual reușit"))
    assert override_id == 1
    sql, args = db.calls[0]
    assert "INSERT INTO patch_window_overrides" in sql
    assert "UPDATE" not in sql
    assert "patch_executions" not in sql  # nu atinge tabela de istoric
    assert args == ("telegram:1", 13, "analizat, downgrade manual reușit")


# ===========================================================================
# archive evidence
# ===========================================================================
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


def test_archive_evidence_executed_picks_the_latest_drill_and_aggregates_it():
    """EXECUTAT peste SQLite (CTE + `bool_or`/`bool_and` înregistrate ca
    agregate proprii — nume identic cu cel din interogarea reală). Singura
    substituție e expresia de vârstă (`EXTRACT(EPOCH FROM ...)`, sintaxă
    specifică PostgreSQL, imposibil de parsat de SQLite) — decizia testată
    (care exercițiu e „cel mai recent" și cum se agregă verdictele lui) NU e
    substituită."""
    sql = run(_capture_row_sql(repo.latest_archive_drill_summary))
    sql_sqlite = sql.replace(
        "EXTRACT(EPOCH FROM (now() - l.performed_at)) / 86400 AS age_days",
        "0 AS age_days")

    conn = sqlite3.connect(":memory:")
    bool_or, bool_and = _bool_or_and()
    conn.create_aggregate("bool_or", 1, bool_or)
    conn.create_aggregate("bool_and", 1, bool_and)
    conn.execute("CREATE TABLE restore_drills (id INTEGER PRIMARY KEY, performed_at TEXT)")
    conn.execute("CREATE TABLE restore_drill_items (drill_id INTEGER, is_archive INTEGER, "
                 "verdict TEXT)")
    conn.executemany("INSERT INTO restore_drills VALUES (?,?)", [
        (1, "2026-07-01"),   # older drill, all good -> must NOT win
        (2, "2026-08-01"),   # latest drill with an archive -> this one counts
    ])
    conn.executemany("INSERT INTO restore_drill_items VALUES (?,?,?)", [
        (1, 1, "restorable_verified"),
        (2, 1, "restorable_verified"),
        (2, 1, "corrupt"),            # a second archive in the SAME latest drill
        (2, 0, "informational_only"),  # non-archive item in the same drill -> ignored
    ])
    row = conn.execute(sql_sqlite).fetchone()
    # (performed_at, age_days, any_bad, all_good)
    assert row[0] == "2026-08-01", row
    assert row[2] == 1, "the corrupt archive in the latest drill was not seen"
    assert row[3] == 0, "all_good must be false when one archive in the latest drill is bad"


# ===========================================================================
# the run log
# ===========================================================================
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
        "halted": False, "detail": "x", "age_min": 42.0,
        "skipped": json.dumps([{"plan_id": 4, "state": "unproven", "reason": "y"}])})
    out = run(repo.last_window_run(db))
    assert out["skipped"] == [{"plan_id": 4, "state": "unproven", "reason": "y"}]
    assert out["age_min"] == 42.0


def test_last_run_age_is_computed_by_the_database_not_by_python():
    """Runda 2: `check_patch_window` calcula vârsta cu `datetime.now()` peste
    un `ran_at` absolut — un test cu ceas înghețat trecea azi și pica singur
    peste `PATCH_WINDOW_STALE_DAYS` zile, fără nicio schimbare de cod. Vârsta
    trebuie să vină DEJA calculată din interogare, ca `drill_age_min`."""
    db = _FetchDB(fetchrow_row=None)
    run(repo.last_window_run(db))
    assert "age_min" in db.fetchrow_sql
    assert "EXTRACT(EPOCH FROM (now() - ran_at))" in db.fetchrow_sql


def test_no_run_yet_is_none():
    db = _FetchDB(fetchrow_row=None)
    assert run(repo.last_window_run(db)) is None
