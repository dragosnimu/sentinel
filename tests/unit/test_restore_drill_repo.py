"""Stratul de bază pentru Funcționalitatea 07: selecția punctului de testat,
scrierea drill-ului și a artefactelor lui, citirea pentru verificarea de
sănătate.

Fiecare test aici probează o decizie a interogării SQL, nu doar că a fost
apelată — o interogare care „arată bine" dar alege punctul greșit, sau scrie
artefactele într-o tranzacție separată de rândul-cap, produce exact genul de
pană pe care restul repository-ului îl vânează.
"""

from __future__ import annotations

import asyncio
import contextlib
import json

from sentinel.db.repo import patches as repo


def run(c):
    return asyncio.run(c)


class _FetchDB:
    """Pentru funcțiile care doar citesc: `fetch` / `fetchrow` / `fetchval`."""

    def __init__(self, *, fetch_rows=None, fetchrow_row=None, fetchval_value=None):
        self.fetch_rows = fetch_rows if fetch_rows is not None else []
        self.fetchrow_row = fetchrow_row
        self.fetchval_value = fetchval_value
        self.fetch_sql: str | None = None
        self.fetchrow_sql: str | None = None
        self.fetchval_sql: str | None = None

    async def fetch(self, sql, *a):
        self.fetch_sql = sql
        return self.fetch_rows

    async def fetchrow(self, sql, *a):
        self.fetchrow_sql = sql
        return self.fetchrow_row

    async def fetchval(self, sql, *a):
        self.fetchval_sql = sql
        return self.fetchval_value


class _FakeConn:
    """Ce dă `db.transaction()` — o SINGURĂ conexiune pentru tot ce scrie
    `record_drill`, ca rândul-cap și artefactele lui să cadă sau să rămână
    împreună."""

    def __init__(self, *, drill_id=42):
        self.drill_id = drill_id
        self.calls: list[tuple] = []

    async def fetchval(self, sql, *a):
        self.calls.append(("fetchval", sql, a))
        return self.drill_id

    async def execute(self, sql, *a):
        self.calls.append(("execute", sql, a))
        return "INSERT 0 1"


class _TxDB:
    def __init__(self, conn=None):
        self._conn = conn or _FakeConn()

    @contextlib.asynccontextmanager
    async def transaction(self):
        yield self._conn


# ---------------------------------------------------------------------------
# Selecția punctului
# ---------------------------------------------------------------------------
def test_pick_prefers_the_point_never_drilled_over_the_stale_one() -> None:
    """`NULLS FIRST` e chiar regula: un punct niciodată testat trece înaintea
    unuia testat demult, altfel un punct nou creat ar sări peste unul vechi de
    un an care n-a fost verificat niciodată."""
    db = _FetchDB(fetchrow_row=None)
    run(repo.pick_restore_point_for_drill(db))
    sql = " ".join(db.fetchrow_sql.split())
    assert "deleted_at IS NULL" in sql
    assert "ld.last_drill_at ASC NULLS FIRST" in sql
    assert "LIMIT 1" in sql


def test_pick_returns_none_when_nothing_is_live() -> None:
    assert run(repo.pick_restore_point_for_drill(_FetchDB(fetchrow_row=None))) is None


def test_pick_parses_the_manifest_from_json_text() -> None:
    """asyncpg întoarce `jsonb` ca text — un apelant care nu-l parsează ar primi
    un șir în loc de un dicționar și `manifest.get("sources")` ar cădea."""
    row = {"id": 7, "path": "/var/backups/sentinel/x", "asset_id": None,
          "created_at": None, "last_drill_at": None,
          "manifest": json.dumps({"sources": ["/etc/nginx"]})}
    point = run(repo.pick_restore_point_for_drill(_FetchDB(fetchrow_row=row)))
    assert point["manifest"] == {"sources": ["/etc/nginx"]}


def test_any_live_restore_point_reads_the_existence_flag() -> None:
    db = _FetchDB(fetchval_value=True)
    assert run(repo.any_live_restore_point(db)) is True
    assert "EXISTS" in db.fetchval_sql
    assert "deleted_at IS NULL" in db.fetchval_sql


# ---------------------------------------------------------------------------
# Scrierea drill-ului
# ---------------------------------------------------------------------------
def test_record_drill_writes_the_head_row_and_every_item_in_one_transaction() -> None:
    """Rândul-cap și artefactele lui trebuie să cadă sau să rămână împreună —
    altfel un drill întrerupt la mijloc ar lăsa un rând `restore_drills` fără
    niciun artefact, sau artefacte fără rândul care le dă sens."""
    conn = _FakeConn(drill_id=99)
    db = _TxDB(conn)
    items = [
        {"artifact": "a.tar.zst", "is_archive": True, "sha256_ok": True,
         "verdict": "restorable_verified", "detail": ""},
        {"artifact": "b.txt", "is_archive": False, "sha256_ok": True,
         "verdict": "informational_only", "detail": ""},
    ]
    drill_id = run(repo.record_drill(
        db, restore_point_id=5, automated=True, performed_by="sentinel-restore-drill",
        succeeded=False, duration_ms=1234, notes="cel puțin un artefact nu a trecut",
        result={"restorable_verified": 1, "informational_only": 1}, items=items))

    assert drill_id == 99
    kinds = [c[0] for c in conn.calls]
    assert kinds == ["fetchval", "execute", "execute"], (
        "rândul-cap și cele două artefacte nu s-au scris pe ACEEAȘI conexiune "
        f"de tranzacție: {kinds}")

    head_sql = " ".join(conn.calls[0][1].split())
    assert "INSERT INTO restore_drills" in head_sql
    assert "automated" in head_sql

    item_sqls = [" ".join(c[1].split()) for c in conn.calls[1:]]
    for sql in item_sqls:
        assert "INSERT INTO restore_drill_items" in sql
        assert "drill_id" in sql


def test_record_drill_ties_every_item_to_the_head_row_id() -> None:
    """ID-ul întors de `RETURNING id` trebuie folosit ca `drill_id` pe fiecare
    artefact — nu un ID furnizat separat, care ar putea diverge."""
    conn = _FakeConn(drill_id=7)
    db = _TxDB(conn)
    run(repo.record_drill(
        db, restore_point_id=1, automated=True, performed_by="x", succeeded=True,
        duration_ms=1, notes="", result={},
        items=[{"artifact": "a", "is_archive": True, "sha256_ok": True,
               "verdict": "restorable_verified", "detail": ""}]))
    item_args = conn.calls[1][2]
    assert item_args[0] == 7, (
        f"artefactul poartă drill_id={item_args[0]}, nu id-ul rândului-cap (7)")


def test_record_drill_marks_manual_entries_as_not_automated() -> None:
    """`docs/PATCHING.md` §6 scrie un rând manual, de mână, fără `automated` —
    valoarea implicită a coloanei (verificată în migrația 0042) e `false`.
    Aici se probează doar că API-ul de scris NU forțează `true` peste tot."""
    conn = _FakeConn()
    db = _TxDB(conn)
    run(repo.record_drill(
        db, restore_point_id=1, automated=False, performed_by="operator",
        succeeded=True, duration_ms=None, notes="test trimestrial", result=None,
        items=[]))
    args = conn.calls[0][2]
    # (restore_point_id, automated, performed_by, succeeded, duration_ms, notes, result)
    assert args[1] is False


# ---------------------------------------------------------------------------
# Citirea pentru verificarea de sănătate
# ---------------------------------------------------------------------------
def test_live_points_query_computes_drill_age_in_the_database() -> None:
    """Vârsta ultimului drill se calculează cu ceasul BAZEI, nu cu al gazdei
    care rulează verificarea — la fel ca la `check_last_scan`."""
    db = _FetchDB(fetch_rows=[])
    run(repo.live_restore_points_with_last_drill(db))
    sql = " ".join(db.fetch_sql.split())
    assert "EXTRACT(EPOCH FROM (now() - ld.performed_at))/60" in sql
    assert "d.automated" in sql
    assert "deleted_at IS NULL" in sql


def test_live_points_query_parses_the_result_column_from_json_text() -> None:
    row = {"id": 3, "asset_id": None, "created_at": None, "asset_name": "blog",
          "drill_id": 9, "performed_at": None, "succeeded": True, "notes": "ok",
          "result": json.dumps({"restorable_verified": 2}), "drill_age_min": 100.0}
    out = run(repo.live_restore_points_with_last_drill(_FetchDB(fetch_rows=[row])))
    assert out[0]["result"] == {"restorable_verified": 2}


def test_live_points_query_leaves_a_never_drilled_point_with_null_drill_id() -> None:
    """`LEFT JOIN LATERAL`, nu `JOIN`: un punct fără niciun drill trebuie să
    rămână în listă, cu `drill_id = None` — altfel dispare din raport în loc
    să apară ca «netestat»."""
    row = {"id": 4, "asset_id": None, "created_at": None, "asset_name": None,
          "drill_id": None, "performed_at": None, "succeeded": None,
          "notes": None, "result": None, "drill_age_min": None}
    out = run(repo.live_restore_points_with_last_drill(_FetchDB(fetch_rows=[row])))
    assert out[0]["drill_id"] is None
