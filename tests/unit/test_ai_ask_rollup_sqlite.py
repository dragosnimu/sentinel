"""`_q_evenimente_fereastra`'s long-window branch, executed for real.

Round 2 shipped a query that reads right (mentions `event_rollup_1h`, the
right table names) but computes wrong: the partial bucket at the rollup's
frontier was counted once from the rollup snapshot AND once again from
`raw_events`, and the hour overlapping the window's START edge could be
dropped entirely. A verifier proved this with a mutation — `WHERE ts >
frontiera.pana` replaced by `WHERE ts > now()` — that every test in
`test_ai_ask.py` missed, because those tests only check that a table NAME
appears in the SQL string and that `ips is None`. Neither checks what the
query actually COMPUTES.

So this file runs the SHIPPED query text against a real, in-memory SQLite —
same tier-2 idiom as `test_incident_campaigns_repo.py` and `test_aggregate.py`:
only the PostgreSQL-only constructs are rewritten, each a change of form and
not of meaning, and `_tradu` refuses to hand back a query it did not fully
translate. The fixture is built so that a wrong boundary produces a
DIFFERENT number, not a coincidentally-equal one — reconciliation, not a
smoke test.
"""
from __future__ import annotations

import asyncio
import re
import sqlite3
from datetime import datetime, timedelta

from sentinel.ai import ask as ask_mod


def run(coro):
    return asyncio.run(coro)


#: Ce nu are voie să rămână netradus. Fără verificarea asta, o rescriere a
#: interogării din `ask.py` ar putea face un regex de mai jos să nu mai
#: potrivească nimic, iar testul ar pica pe o eroare de sintaxă confuză — sau,
#: mai rău, SQLite ar accepta construcția cu alt înțeles și testul ar compara
#: liniștite două lucruri greșite.
_RAMASE_PG = ("make_interval", "date_trunc", "greatest(", "::", "now()", "FILTER")


def _tradu(sql: str, acum: str) -> str:
    """Rescrie interogarea REALĂ (nu o copie a ei) într-o formă pe care SQLite
    o înțelege. `acum` înlocuiește `now()` cu un moment FIXAT de test — altfel
    testul ar depinde de ceasul mașinii care rulează suita, exact ce cusătura
    asta greșește când `now()` real se mișcă între citirea frontierei și
    citirea cozii."""
    sql = sql.replace("now()", "'" + acum + "'")
    # `'<acum>' - make_interval(hours => $1::int)` -> aritmetică de dată SQLite,
    # cu parametrul legat încă viu ca `$1` (compilat mai jos în `_compile`).
    sql = re.sub(
        r"'" + re.escape(acum) + r"'\s*-\s*make_interval\(hours => \$1::int\)",
        "datetime('" + acum + "', '-' || CAST($1 AS TEXT) || ' hours')",
        sql)
    # `date_trunc('hour', X)` și `strftime('%Y-%m-%d %H:00:00', X)` au aceeași
    # aritate — un simplu prefix, nu o extragere cu paranteze imbricate.
    sql = sql.replace("date_trunc('hour', ", "strftime('%Y-%m-%d %H:00:00', ")
    # `greatest(a, b)` -> `max(a, b)`: forma scalară cu 2+ argumente a lui
    # `max` din SQLite e exact `greatest`, nu agregatul pe o coloană.
    sql = sql.replace("greatest(", "max(")
    # `sum(n) FILTER (WHERE cond)` / `count(*) FILTER (WHERE cond)` -> CASE WHEN.
    sql = re.sub(
        r"sum\(n\) FILTER \(WHERE action IN \('auth_fail','alert'\)\)",
        "sum(CASE WHEN action IN ('auth_fail','alert') THEN n ELSE 0 END)", sql)
    sql = re.sub(
        r"count\(\*\) FILTER \(WHERE action IN \('auth_fail','alert'\)\)",
        "sum(CASE WHEN action IN ('auth_fail','alert') THEN 1 ELSE 0 END)", sql)
    sql = re.sub(r"::\w+", "", sql)

    ramase = [c for c in _RAMASE_PG if c in sql]
    assert not ramase, "construct PostgreSQL netradus: " + repr(ramase) + "\n" + sql
    return sql


def _compile(sql: str, args: tuple):
    """`$1, $2, ...` -> `?`, în ordinea apariției, extinzând repetițiile."""
    nums = [int(n) for n in re.findall(r"\$(\d+)", sql)]
    sql = re.sub(r"\$\d+", "?", sql)
    return sql, [args[n - 1] for n in nums]


class _RollupSQLite:
    """Cât din `Database` îi trebuie funcției: doar `fetchrow`, care chiar
    rulează interogarea PRIMITĂ (nu una reconstruită de test) pe SQLite."""

    def __init__(self, acum, rollup=(), raw=()):
        self.acum = acum
        self.con = sqlite3.connect(":memory:")
        self.con.row_factory = sqlite3.Row
        self.con.execute("CREATE TABLE event_rollup_1h (bucket TEXT, n INTEGER, action TEXT)")
        self.con.execute("CREATE TABLE raw_events (ts TEXT, action TEXT)")
        self.con.executemany(
            "INSERT INTO event_rollup_1h (bucket, n, action) VALUES (?, ?, ?)", list(rollup))
        self.con.executemany("INSERT INTO raw_events (ts, action) VALUES (?, ?)", list(raw))

    async def fetchrow(self, sql, *args):
        s, a = _compile(_tradu(sql, self.acum), args)
        row = self.con.execute(s, a).fetchone()
        return dict(row) if row else None


# ---------------------------------------------------------------------------
# Test 1: bucket-ul parțial de la frontieră se numără o SINGURĂ dată
# ---------------------------------------------------------------------------
def test_partial_frontier_bucket_counts_once_not_twice_not_zero():
    """Bucket-ul de la frontieră (999 în rollup, o valoare aleasă mare și
    ușor de recunoscut) NU are voie să apară în total — conținutul lui real,
    mai proaspăt, vine din cele 4 rânduri `raw_events`. Runda 2 aduna 999 ȘI
    numărul din `raw_events`, deci totalul era 1003 în loc de 4."""
    acum = "2026-08-31 14:05:43"
    frontiera = "2026-08-31 14:00:00"

    db = _RollupSQLite(
        acum,
        rollup=[(frontiera, 999, "http")],   # bucket-ul parțial — trebuie EXCLUS
        raw=[
            ("2026-08-31 14:00:05", "http"),
            ("2026-08-31 14:01:47", "http"),
            ("2026-08-31 14:03:12", "auth_fail"),
            ("2026-08-31 14:05:30", "http"),
        ],
    )

    result = run(ask_mod._q_evenimente_fereastra(db, {"ore": 25}))

    assert result["total"] == 4, (
        "asteptat 4 (doar randurile raw_events din ora partiala), primit "
        + str(result["total"]) + " - bucket-ul de 999 din rollup a scapat in total")
    assert result["ostile"] == 1


# ---------------------------------------------------------------------------
# Test 2: reconciliere completă — marginea de start, frontiera, și coada
# ---------------------------------------------------------------------------
def test_full_window_reconciles_start_margin_and_frontier_without_double_count():
    """Scenariul verificatorului, reconstituit cu cifre proprii: o oră EXACT
    la începutul ferestrei ancorate (care s-ar pierde fără rotunjirea la ora
    întreagă), o oră chiar înainte de fereastră (care NU are voie să intre),
    bucket-ul parțial de la frontieră (999 — NU are voie să intre din rollup),
    un rând `raw_events` deja acoperit de un bucket complet (NU are voie să
    se numere a doua oară), și un rând `raw_events` dinaintea ferestrei
    (NU are voie să intre deloc)."""
    acum = "2026-08-31 14:05:43"
    ore = 26
    # date_trunc('hour', acum - 26h) = 2026-08-30 12:00:00
    fereastra_start = "2026-08-30 12:00:00"
    inainte_de_fereastra = "2026-08-30 11:00:00"     # bucket EXCLUS
    frontiera = "2026-08-31 14:00:00"                 # bucket parțial, EXCLUS din vechi

    rollup = [
        # Bucket-ul chiar înainte de fereastră — nu are voie să intre.
        (inainte_de_fereastra, 999, "http"),
        # Primul bucket AL ferestrei, exact la ancoră — trebuie inclus.
        (fereastra_start, 30, "http"),
        (fereastra_start, 20, "auth_fail"),
        # Bucket-ul parțial de la frontieră — trebuie EXCLUS (se numără prin raw_events).
        (frontiera, 300, "http"),
        (frontiera, 122, "auth_fail"),
    ]
    # 25 de bucket-uri complete între (fereastra_start, frontiera) — o oră pe rând.
    cursor = datetime.fromisoformat(fereastra_start) + timedelta(hours=1)
    frontiera_dt = datetime.fromisoformat(frontiera)
    while cursor < frontiera_dt:
        b = cursor.strftime("%Y-%m-%d %H:%M:%S")
        rollup.append((b, 10, "http"))
        rollup.append((b, 5, "auth_fail"))
        cursor += timedelta(hours=1)

    raw = [
        # Coada reală, de la frontieră până acum — trebuie numărată o dată.
        ("2026-08-31 14:00:05", "http"),
        ("2026-08-31 14:00:47", "http"),
        ("2026-08-31 14:01:12", "http"),
        ("2026-08-31 14:01:59", "http"),
        ("2026-08-31 14:02:30", "http"),
        ("2026-08-31 14:03:10", "http"),
        ("2026-08-31 14:04:00", "http"),
        ("2026-08-31 14:04:20", "auth_fail"),
        ("2026-08-31 14:04:55", "auth_fail"),
        ("2026-08-31 14:05:30", "auth_fail"),
        # Deja acoperit de bucket-ul complet de la 13:00 — NU are voie să se
        # numere a doua oară prin `raw_events`.
        ("2026-08-31 13:30:00", "auth_fail"),
        # Înainte de fereastră cu totul — NU are voie să intre.
        ("2026-08-30 10:00:00", "http"),
    ]

    db = _RollupSQLite(acum, rollup=rollup, raw=raw)
    result = run(ask_mod._q_evenimente_fereastra(db, {"ore": ore}))

    # vechi: 50 (bucket de ancoră) + 25 * 15 (bucket-urile complete) = 425
    # recent: 10 rânduri raw_events din coada reală
    asteptat_total = (50 + 25 * 15) + 10
    asteptat_ostile = (20 + 25 * 5) + 3

    assert result["total"] == asteptat_total, (
        "asteptat " + str(asteptat_total) + ", primit " + str(result["total"])
        + " - verifica dubla numarare la frontiera sau pierderea orei de la marginea de start")
    assert result["ostile"] == asteptat_ostile
    assert result["ips"] is None
    assert result["aproximat"] is True
