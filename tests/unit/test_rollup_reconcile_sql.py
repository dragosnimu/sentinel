"""`sentinel.db.repo.rollups.hourly_gaps`, executed for real.

`event_rollup_1h` pierde tăcut orice rând brut sosit după ce filigranul
`maintenance_service.rollup_events` a lăsat ora lui în urmă (vezi antetul
acelui modul). Măsurat pe 24 august 2026: 3,96 milioane de rânduri lipsă
pentru o singură zi, fără nicio eroare — interogarea care citește agregatul
rămâne validă, doar întoarce mai puțin.

Testele astea rulează SQL-ul livrat (`rollups.HOURLY_GAPS_SQL`, prin
`hourly_gaps`, nu o copie reconstruită) pe un SQLite tradus — același tipar de
nivel 2 ca `test_ai_ask_rollup_sqlite.py`. O aserțiune statică pe forma
interogării ar fi trecut și pentru varianta care confundă „gaură reală" cu
„brut expirat de retenție" — capcana din raportul funcționalității asta o
repară: rollup-ul ține istoric mai mult decât brutul, dinadins, deci o oră cu
agregat și fără brut NU e o gaură.
"""
from __future__ import annotations

import asyncio
import re
import sqlite3
from datetime import datetime, timezone

from sentinel.db.repo import rollups as rollup_repo


def run(coro):
    return asyncio.run(coro)


def _dt(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


#: Ce nu are voie să rămână netradus. Vezi motivul în `test_ai_ask_rollup_sqlite.py`.
_RAMASE_PG = ("date_trunc", "::")


def _tradu(sql: str) -> str:
    sql = sql.replace(
        "date_trunc('hour', ts)", "strftime('%Y-%m-%d %H:00:00', ts)")
    sql = re.sub(r"::\w+", "", sql)
    ramase = [c for c in _RAMASE_PG if c in sql]
    assert not ramase, "construct PostgreSQL netradus: " + repr(ramase) + "\n" + sql
    return sql


def _compile(sql: str, args: tuple):
    """`$1, $2, ...` -> `?`, legând `datetime` ca text SQLite comparabil."""
    nums = [int(n) for n in re.findall(r"\$(\d+)", sql)]
    sql = re.sub(r"\$\d+", "?", sql)
    bound = []
    for n in nums:
        v = args[n - 1]
        bound.append(v.strftime("%Y-%m-%d %H:%M:%S") if isinstance(v, datetime) else v)
    return sql, bound


class _GapSQLite:
    """Doar `fetch`, care rulează interogarea PRIMITĂ (nu una reconstruită de
    test) pe SQLite. `bucket` se întoarce ca `datetime`, nu text — asyncpg
    întoarce `timestamptz`, iar `hourly_gaps` presupune asta (`_as_utc`)."""

    def __init__(self, *, rollup=(), raw=()):
        self.con = sqlite3.connect(":memory:")
        self.con.row_factory = sqlite3.Row
        self.con.execute("CREATE TABLE event_rollup_1h (bucket TEXT, n INTEGER)")
        self.con.execute("CREATE TABLE raw_events (ts TEXT)")
        self.con.executemany(
            "INSERT INTO event_rollup_1h (bucket, n) VALUES (?, ?)", list(rollup))
        self.con.executemany(
            "INSERT INTO raw_events (ts) VALUES (?)", [(t,) for t in raw])

    async def fetch(self, sql, *args):
        s, a = _compile(_tradu(sql), args)
        rows = self.con.execute(s, a).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["bucket"] = _dt(d["bucket"])
            out.append(d)
        return out


# ---------------------------------------------------------------------------
# 1. O oră cu rânduri sosite târziu e detectată
# ---------------------------------------------------------------------------
def test_late_arriving_hour_is_detected_as_a_gap():
    """Filigranul a lăsat ora 04:00 în urmă cu 6 rânduri agregate; alte 4 au
    sosit după aceea (aceeași geometrie ca migrația 0025: 6 în rollup, mult mai
    multe în brut). Trebuie găsită, cu numărul exact de rânduri lipsă."""
    db = _GapSQLite(
        rollup=[("2026-08-24 04:00:00", 6)],
        raw=[f"2026-08-24 04:0{i}:00" for i in range(9)],  # 9 rânduri reale > 6
    )
    report = run(rollup_repo.hourly_gaps(
        db, lower=_dt("2026-08-24 00:00:00"), upper=_dt("2026-08-24 06:00:00"), limit=20))

    assert report.total_hours == 1
    assert report.total_missing == 3          # 9 brut - 6 rollup
    assert len(report.hours) == 1
    gap = report.hours[0]
    assert gap.bucket == _dt("2026-08-24 04:00:00")
    assert gap.raw_n == 9
    assert gap.rollup_n == 6
    assert gap.missing == 3


# ---------------------------------------------------------------------------
# 2. Ora în curs nu e raportată
# ---------------------------------------------------------------------------
def test_hour_at_or_after_upper_is_never_reported_even_when_it_mismatches():
    """Ora curentă are DEJA un decalaj mare (bucket-ul parțial, rescris la
    fiecare trecere — vezi 0025_rollup_watermark.sql), dar apelantul a ales
    `upper` s-o excludă. Interogarea nu are voie să o raporteze, oricât de
    mare ar fi diferența — altfel agregarea normală, în desfășurare, ar fi
    citită ca o gaură pierdută definitiv."""
    ora_curenta = "2026-08-24 07:00:00"
    db = _GapSQLite(
        rollup=[(ora_curenta, 5)],       # doar 5 minute agregate până acum
        raw=[f"2026-08-24 07:{i:02d}:00" for i in range(40)],  # 40 sosite deja
    )
    report = run(rollup_repo.hourly_gaps(
        db, lower=_dt("2026-08-24 00:00:00"), upper=_dt(ora_curenta), limit=20))

    assert report.total_hours == 0, (
        "ora curentă a fost raportată ca gaură — granița `upper` (exclusivă) "
        "nu mai desparte agregarea în desfășurare de o gaură reală")
    assert report.hours == []


# ---------------------------------------------------------------------------
# 3. O oră al cărei brut a expirat nu e raportată
# ---------------------------------------------------------------------------
def test_hour_whose_raw_data_has_expired_is_not_reported():
    """Capcana măsurată în raport: `08-03 rollup 41070 brut 0`. Rollup-ul ține
    istoric mai mult decât brutul (`rollup_1h_days` >> `raw_events_days`),
    dinadins — o oră cu agregat și FĂRĂ niciun rând brut nu e o gaură, e
    retenția care și-a făcut treaba. O verificare care ar semnala asta ar
    alerta identic la fiecare rulare, pentru totdeauna."""
    db = _GapSQLite(
        rollup=[("2026-08-03 09:00:00", 41070)],
        raw=[],  # partiția zilei a fost eliminată de retenție
    )
    report = run(rollup_repo.hourly_gaps(
        db, lower=_dt("2026-08-03 00:00:00"), upper=_dt("2026-08-03 12:00:00"), limit=20))

    assert report.total_hours == 0, (
        "o oră cu rollup > brut (brut expirat) a fost citită ca o gaură")
    assert report.total_missing == 0


# ---------------------------------------------------------------------------
# 3b. O oră care lipsește TOTAL din rollup (nicio linie, nu doar puțină) e
#     tot o gaură — `LEFT JOIN`, nu `JOIN`, e ce face diferența
# ---------------------------------------------------------------------------
def test_hour_missing_entirely_from_rollup_is_detected():
    """`event_rollup_1h` n-are NICIO linie pentru ora asta — filigranul a
    sărit-o complet, nu doar parțial. Diferă de testul 1 (unde rollup-ul are
    o linie, doar cu o valoare mică): aici cheia din `raw_h` n-are pereche
    deloc în `roll_h`, iar `LEFT JOIN` + `COALESCE(..., 0)` sunt ce garantează
    că bucket-ul tot apare drept o gaură — un `JOIN` obișnuit l-ar arunca."""
    db = _GapSQLite(
        rollup=[],  # nimic pentru ora asta, în nicio partiție
        raw=[f"2026-08-24 05:0{i}:00" for i in range(4)],
    )
    report = run(rollup_repo.hourly_gaps(
        db, lower=_dt("2026-08-24 00:00:00"), upper=_dt("2026-08-24 06:00:00"), limit=20))

    assert report.total_hours == 1
    assert report.hours[0].rollup_n == 0
    assert report.hours[0].raw_n == 4
    assert report.hours[0].missing == 4


# ---------------------------------------------------------------------------
# 4. O oră perfect sincronă nu e raportată
# ---------------------------------------------------------------------------
def test_exact_match_is_not_flagged():
    db = _GapSQLite(
        rollup=[("2026-08-24 03:00:00", 4)],
        raw=[f"2026-08-24 03:0{i}:00" for i in range(4)],
    )
    report = run(rollup_repo.hourly_gaps(
        db, lower=_dt("2026-08-24 00:00:00"), upper=_dt("2026-08-24 06:00:00"), limit=20))
    assert report.total_hours == 0
    assert report.hours == []


# ---------------------------------------------------------------------------
# 5. Totalurile supraviețuiesc plafonului — window function înainte de LIMIT
# ---------------------------------------------------------------------------
def test_totals_survive_the_sample_limit():
    """`count(*) OVER()`/`sum(...) OVER()` trebuie calculate pe TOT setul de
    goluri, înainte ca `LIMIT` să taie lista întoarsă — altfel un apelant
    care cere doar un eșantion (autoverificarea) ar raporta „3 goluri" când
    de fapt sunt 10, fiindcă a citit lungimea listei în loc de totalul
    interogării."""
    rollup = [(f"2026-08-24 {h:02d}:00:00", 1) for h in range(10)]
    raw = [f"2026-08-24 {h:02d}:00:00" for h in range(10) for _ in range(5)]  # 5 > 1 la fiecare oră
    db = _GapSQLite(rollup=rollup, raw=raw)

    report = run(rollup_repo.hourly_gaps(
        db, lower=_dt("2026-08-24 00:00:00"), upper=_dt("2026-08-25 00:00:00"), limit=3))

    assert report.total_hours == 10
    assert report.total_missing == 10 * (5 - 1)
    assert len(report.hours) == 3          # eșantionul, plafonat
    assert report.truncated is True
    # cele mai vechi trei, în ordine
    assert [g.bucket.hour for g in report.hours] == [0, 1, 2]


# ---------------------------------------------------------------------------
# 6. Fereastră goală — nimic interogat, nimic raportat
# ---------------------------------------------------------------------------
def test_empty_window_short_circuits_without_querying():
    """`lower >= upper` întoarce direct un raport gol, fără să atingă baza —
    contractul pe care se sprijină `check_rollup_reconcile`/
    `repair_rollup_gaps` când încă nu există nicio oră stabilită."""
    db = _GapSQLite(rollup=[], raw=[])
    report = run(rollup_repo.hourly_gaps(
        db, lower=_dt("2026-08-24 06:00:00"), upper=_dt("2026-08-24 06:00:00"), limit=20))
    assert report.total_hours == 0
    assert report.hours == []
