"""`aggregate.sources` — the "Surse de date" card, and the query behind it.

The interesting failures here are all in SQL, so the tests run the SHIPPED
query — the one `sources` actually hands to the driver — against an in-memory
SQLite. A stub that returned canned rows would agree with any query at all,
including one that lost half the sources; that is the shape of dead test this
repository has already paid for twice.

Only the constructs SQLite does not have are rewritten, each one a change of
form and not of meaning, and `_tradu` refuses to hand over a query that still
contains a PostgreSQL construct it did not translate.
"""
from __future__ import annotations

import asyncio
import re
import sqlite3
from datetime import datetime, timedelta, timezone

from sentinel.analytics import aggregate


def run(coro):
    return asyncio.run(coro)


def _t(**delta) -> str:
    """Un moment din trecut, în formatul în care SQLite compară text cu text."""
    return (datetime.now(timezone.utc) - timedelta(**delta)).strftime("%Y-%m-%d %H:%M:%S")


def _minut(ts: str) -> str:
    """Bucketul de rollup în care ar cădea momentul dat."""
    return ts[:16] + ":00"


#: `LEFT JOIN LATERAL` nu există în SQLite. Subinterogarea numără, deci
#: întoarce ÎNTOTDEAUNA exact un rând — 0 când nu găsește nimic. Un `LEFT JOIN`
#: cu numărătoarea deja grupată dă `NULL` în locul acelui 0, iar `sources` îl
#: trece prin `COALESCE(..., 0)`: aceleași cifre, altă formă.
_LATERAL_24H = re.compile(
    r"LEFT JOIN LATERAL \(\s*"
    r"SELECT count\(\*\) AS n FROM raw_events e\s*"
    r"WHERE e\.source = a\.source AND e\.action = a\.action\s*"
    r"AND e\.ts > now\(\) - interval '24 hours'\) c ON true",
    re.S)
_LATERAL_24H_SQLITE = (
    "LEFT JOIN (SELECT source, action, count(*) AS n FROM raw_events "
    "WHERE ts > now() - interval '24 hours' GROUP BY 1, 2) c "
    "ON c.source = a.source AND c.action = a.action")

#: Restul e formă pură: `datetime('now', ...)` e chiar aritmetica de interval,
#: iar `::bigint` e o conversie pe care SQLite o face oricum.
_TRADUCERI = (
    (re.compile(r"now\(\)\s*-\s*interval\s*'(\d+) (\w+)'"), r"datetime('now','-\1 \2')"),
    (re.compile(r"::bigint"), ""),
)

#: Ce nu are voie să rămână după traducere. Fără verificarea asta, o rescriere a
#: interogării din `aggregate.py` ar putea face regexul de mai sus să nu mai
#: potrivească nimic, iar testele ar pica pe o eroare de sintaxă confuză — sau,
#: mai rău, SQLite ar accepta construcția cu ALT înțeles și testele ar compara
#: liniștite două lucruri greșite.
_RAMASITE_PG = ("LATERAL", "ON true", "interval '", "now()", "::", "->>")


def _tradu(sql: str) -> str:
    sql = _LATERAL_24H.sub(_LATERAL_24H_SQLITE, sql)
    for tipar, inlocuire in _TRADUCERI:
        sql = tipar.sub(inlocuire, sql)
    ramase = [m for m in _RAMASITE_PG if m in sql]
    assert not ramase, f"construcții PostgreSQL netraduse: {ramase}"
    return sql


class _SQLite:
    """Cât din `Database` îi trebuie lui `sources`: un `fetch` care chiar rulează."""

    def __init__(self, rollup=(), raw=()):
        self.rollup = list(rollup)
        self.raw = list(raw)
        self.sql: str | None = None

    async def fetch(self, sql, *args):
        self.sql = sql
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        con.execute("CREATE TABLE event_rollup_1m (bucket TEXT, asset_id INTEGER, "
                    "source TEXT, action TEXT, n INTEGER)")
        con.execute("CREATE TABLE raw_events (id INTEGER PRIMARY KEY, ts TEXT, "
                    "source TEXT, action TEXT)")
        con.executemany("INSERT INTO event_rollup_1m (bucket, asset_id, source, action, n) "
                        "VALUES (?, 0, ?, ?, ?)", self.rollup)
        con.executemany("INSERT INTO raw_events (ts, source, action) VALUES (?, ?, ?)",
                        self.raw)
        try:
            return [dict(r) for r in con.execute(_tradu(sql)).fetchall()]
        finally:
            con.close()


def _pe_sursa(randuri):
    return {r["source"]: r for r in randuri}


# --- inventarul nu are voie să se subțieze ---------------------------------
def test_a_silent_source_stays_in_the_table_with_a_zero():
    """O sursă tăcută trebuie să rămână în tabel, cu zero.

    Pana pe care o previne: cardul „Surse de date" e singurul loc din panou în
    care un colector mort se vede — și se vede fiindcă scrie zero, nu fiindcă
    lipsește. Dacă un rând dispare, operatorul citește „sshd nu există aici",
    nu „sshd a amuțit", și treizeci de zile de autentificări nevăzute arată
    identic cu o lună liniștită. E exact pana de trei zile din care s-a născut
    `_gap_insights`, mutată în tabelul de alături.

    E ușor de pierdut fix la schimbarea asta: ultima activitate nu mai vine
    dintr-un `LEFT JOIN` peste inventar, ci dintr-o reuniune — iar o reuniune
    din care lipsește ramura de rollup conține doar sursele care AU scris.
    """
    db = _SQLite(
        rollup=[(_minut(_t(days=8)), "sudo", "auth_ok", 3),
                (_minut(_t(minutes=2)), "nginx", "alert", 40)],
        raw=[(_t(minutes=2), "nginx", "alert"), (_t(hours=5), "nginx", "alert")],
    )
    out = _pe_sursa(run(aggregate.sources(db)))
    assert "sudo" in out, "sursa tăcută a dispărut din tabel"
    assert out["sudo"]["ev_24h"] == 0
    assert out["sudo"]["ultim"] == _minut(_t(days=8))
    assert out["nginx"]["ev_24h"] == 2


def test_a_pair_seen_in_both_halves_does_not_double_its_events():
    """Numărul de evenimente pe 24 h nu are voie să se dubleze.

    Pana pe care o previne: ultima activitate se citește din două locuri —
    rollup-ul și coada neagregată — iar o pereche activă apare în amândouă.
    Dacă reuniunea iese cu două rânduri pe pereche, numărătoarea legată de ele
    se face de două ori, iar panoul raportează dublul traficului real. Un
    contor de securitate care exagerează antrenează exact reflexul greșit:
    operatorul învață că cifrele de acolo nu înseamnă nimic.
    """
    db = _SQLite(
        rollup=[(_minut(_t(minutes=30)), "nginx", "alert", 5)],
        raw=[(_t(minutes=m), "nginx", "alert") for m in (5, 10, 20, 40, 90)],
    )
    out = _pe_sursa(run(aggregate.sources(db)))
    assert out["nginx"]["ev_24h"] == 5, "evenimentele au fost numărate de două ori"


def test_the_fresh_tail_reaches_back_to_the_rollup_frontier():
    """Coada citită din `raw_events` trebuie să ajungă până la rollup.

    Pana pe care o previne: `sentinel-maintenance.timer` e `OnCalendar=hourly`
    cu `RandomizedDelaySec=300`, deci între două rulări pot trece peste 66 de
    minute fără ca nimic să fie stricat. Cu o coadă fixă de o oră, evenimentele
    din minutele dintre frontiera rollup-ului și ora aia nu se văd nicăieri: o
    sursă care tocmai s-a întors la viață rămâne afișată ca tăcută de zile, iar
    `_gap_insights` — care pune aceeași întrebare — ar da alarma „sursa a
    amuțit" despre un colector care scrie chiar acum.
    """
    db = _SQLite(
        # Frontiera rollup-ului e acum 80 de minute: rularea a întârziat.
        rollup=[(_minut(_t(minutes=80)), "nginx", "alert", 9),
                (_minut(_t(days=3)), "sshd", "auth_fail", 2)],
        # sshd a scris acum 70 de minute — după frontieră, dar nu în ultima oră.
        raw=[(_t(minutes=70), "sshd", "auth_fail"), (_t(minutes=81), "nginx", "alert")],
    )
    out = _pe_sursa(run(aggregate.sources(db)))
    assert out["sshd"]["ultim"] == _t(minutes=70), \
        "ultima activitate a căzut în gaura dintre rollup și coadă"


def test_an_empty_rollup_does_not_empty_the_table():
    """Un rollup gol nu are voie să golească tabelul.

    Pana pe care o previne: coada din `raw_events` pornește de la frontiera
    rollup-ului, iar pe o bază nouă — sau după o curățare a agregatelor —
    frontiera aia e NULL. În SQL, orice comparație cu NULL e falsă, deci fără
    `COALESCE` reuniunea n-ar întoarce niciun rând brut, iar cardul „Surse de
    date" ar fi complet gol pe o gazdă care primește evenimente. Gol nu se
    citește ca „nu știu"; se citește ca „nu vine nimic".
    """
    db = _SQLite(rollup=[], raw=[(_t(hours=2), "nginx", "alert"),
                                 (_t(minutes=3), "nginx", "alert")])
    out = _pe_sursa(run(aggregate.sources(db)))
    assert "nginx" in out, "cu rollup-ul gol, tabelul a rămas fără surse"
    assert out["nginx"]["ultim"] == _t(minutes=3)
    assert out["nginx"]["ev_24h"] == 2


def test_last_activity_survives_the_pruning_of_the_raw_rows():
    """Ultima activitate nu mai depinde de rândurile brute, care expiră.

    Pana pe care o previne: `raw_events` se taie la `raw_events_days` (30, și
    până la 7 când `disk_guard` strânge din retenție), pe când rollup-ul ține
    90 de zile. Citită din rândurile brute, ultima activitate a unei surse
    tăcute de mai mult decât retenția ieșea NULL — „niciun eveniment
    vreodată" — despre un colector despre care rollup-ul știe exact când a
    vorbit ultima dată. Testul ăsta e și dovada că interogarea nu mai citește
    30 de zile de `raw_events`: dacă ar citi, aici n-ar găsi nimic.
    """
    db = _SQLite(
        rollup=[(_minut(_t(days=20)), "suricata", "alert", 11)],
        raw=[],                       # partițiile vechi au fost eliminate
    )
    out = _pe_sursa(run(aggregate.sources(db)))
    assert "suricata" in out
    assert out["suricata"]["ultim"] == _minut(_t(days=20)), \
        "ultima activitate s-a pierdut odată cu rândurile brute"
    assert out["suricata"]["ev_24h"] == 0


def test_a_rollup_older_than_thirty_days_does_not_revive_a_dead_source():
    """O sursă scoasă din uz de luni de zile nu are voie să reapară.

    Pana pe care o previne: rollup-ul ține 90 de zile, de trei ori retenția
    evenimentelor brute. Fără fereastra de 30 de zile, cardul s-ar umple cu
    colectoare dezafectate — Wazuh a fost scos — fiecare cu zero evenimente,
    adică fiecare arătând exact ca un colector mort. Trei rânduri false de
    „tăcut" ascund unul adevărat.
    """
    db = _SQLite(
        rollup=[(_minut(_t(days=45)), "wazuh", "alert", 4),
                (_minut(_t(minutes=10)), "nginx", "alert", 7)],
        raw=[(_t(minutes=10), "nginx", "alert")],
    )
    out = _pe_sursa(run(aggregate.sources(db)))
    assert "wazuh" not in out, "o sursă dinaintea ferestrei de 30 de zile a reapărut"
    assert "nginx" in out


def test_the_minute_of_precision_is_lost_only_backwards():
    """Precizia pierdută e de un minut, și numai spre trecut.

    Pana pe care o previne: `bucket` e trunchiat la minut, deci un eveniment de
    la 09:20:59 deja agregat se citește 09:20:00. Asta e acceptabil fiindcă
    pragurile care judecă tăcerea sunt în ORE — dar numai atâta vreme cât
    eroarea rămâne într-o singură direcție. O valoare rotunjită în sus, oricât
    de puțin, ar face o sursă să pară mai proaspătă decât e, iar asta e chiar
    forma de minciună pe care panoul există ca s-o prevină. Coada neagregată
    păstrează secundele exacte pentru ce e după frontieră.
    """
    tarziu = _t(minutes=30)[:17] + "59"          # ...:59, deja agregat
    db = _SQLite(
        # Frontiera e mai nouă decât evenimentul, deci răspunsul vine din rollup.
        rollup=[(_minut(tarziu), "sshd", "auth_ok", 1),
                (_minut(_t(minutes=20)), "nginx", "alert", 1)],
        raw=[(tarziu, "sshd", "auth_ok"), (_t(minutes=20), "nginx", "alert")],
    )
    agregat = _pe_sursa(run(aggregate.sources(db)))["sshd"]["ultim"]
    assert agregat <= tarziu, "ultima activitate a ieșit mai nouă decât evenimentul"
    assert agregat == _minut(tarziu), "nu e bucketul de rollup"

    # Același eveniment, dar după frontieră: secundele se păstrează întregi.
    proaspat = _SQLite(
        rollup=[(_minut(_t(minutes=90)), "sshd", "auth_ok", 1)],
        raw=[(tarziu, "sshd", "auth_ok")],
    )
    assert _pe_sursa(run(aggregate.sources(proaspat)))["sshd"]["ultim"] == tarziu
