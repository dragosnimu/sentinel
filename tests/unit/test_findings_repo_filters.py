"""Filtrele de constatări se aplică în SQL, înaintea lui `LIMIT`.

Botul cerea 200 de rânduri din 1055 și abia apoi păstra dintre ele pe cele
critice sau pe cele din KEV. Pe gazda de producție, unde primul rând `dnf` e al
373-lea în ordinea priorității, mulțimea „criticele deschise" și mulțimea
„criticele dintre primele 200 după prioritate" nu au niciun rând comun — deci
răspunsul „niciuna" era despre a doua, iar operatorul îl citea despre prima.

Aici nu se verifică o intenție („am pasat un argument"), ci textul interogării:
unde stă clauza față de `LIMIT` și cu ce parametru. O clauză corectă trimisă cu
numărul de parametru greșit e SQL valid care caută severități printre numele de
scanere, și nicio excepție nu o semnalează.
"""
from __future__ import annotations

import asyncio

from sentinel.db.repo import findings as fx


class _SQLDB:
    """Nu execută nimic: reține interogările și parametrii lor.

    Baza reală nu e disponibilă în suită, iar întrebarea de aici nu e „ce
    rânduri întoarce Postgres", ci „ce i se cere". Un ciot care ar întoarce
    rânduri filtrate de el însuși ar răspunde la a doua întrebare cu prima.
    """

    def __init__(self, *, rows=None, row=None):
        self.rows = rows or []
        self.row = row
        self.calls: list[tuple[str, tuple]] = []

    async def fetch(self, sql: str, *args):
        self.calls.append((sql, args))
        return self.rows

    async def fetchval(self, sql: str, *args):
        self.calls.append((sql, args))
        return 0

    async def fetchrow(self, sql: str, *args):
        self.calls.append((sql, args))
        return self.row

    def only(self) -> tuple[str, tuple]:
        assert len(self.calls) == 1, f"am așteptat o interogare, sunt {len(self.calls)}"
        return self.calls[0]


def run(c):
    return asyncio.run(c)


def test_severity_filter_sits_in_the_where_clause(monkeypatch):
    """Filtrul pe severitate merge în `WHERE`, nu după `LIMIT`.

    Dacă ajunge după tăiere, `/vulnerabilitati critice` răspunde „niciuna"
    despre vulnerabilități critice deschise, fiindcă ele stau sub pragul de
    prioritate al feliei afișate.
    """
    db = _SQLDB()
    run(fx.list_open(db, limit=20, severities=["critical"]))
    sql, args = db.only()

    assert "severity = ANY($1::text[])" in sql, sql
    assert sql.index("severity = ANY") < sql.index("LIMIT"), (
        "clauza de severitate a ajuns după LIMIT")
    assert args == (["critical"], 20, 0)


def test_the_filters_keep_the_order_of_their_parameters():
    """Clauzele și parametrii merg în aceeași ordine.

    `$1` e primul parametru trimis. Dacă lista de scanere și cea de severități
    se inversează între clauză și apel, interogarea rămâne validă și caută
    „critical" printre numele de scanere — zero rânduri, fără nicio eroare.
    """
    db = _SQLDB()
    run(fx.list_open(db, limit=5, offset=40, scanners=["dnf"],
                     severities=["critical", "high"], kev_only=True))
    sql, args = db.only()

    assert "coalesce(f.scanner, '') = ANY($1::text[])" in sql
    assert "f.severity = ANY($2::text[])" in sql
    assert "AND f.kev" in sql
    assert "LIMIT $3 OFFSET $4" in sql
    assert args == (["dnf"], ["critical", "high"], 5, 40)


def test_an_empty_severity_list_means_no_rows_not_all_rows():
    """`[]` e „nicio severitate cerută", nu „fără filtru".

    Aceeași distincție ca la scanere. Confundate, o categorie goală ar arăta
    toate cele 1055 de constatări sub eticheta ei.
    """
    db = _SQLDB()
    run(fx.list_open(db, limit=20, severities=[]))
    sql, args = db.only()
    assert "severity = ANY($1::text[])" in sql
    assert args == ([], 20, 0)


def test_no_filter_asks_the_same_question_as_before():
    """Fără argumente, interogarea nu capătă nicio clauză în plus.

    Pagina de vulnerabilități cheamă exact așa. O clauză strecurată pe drumul
    implicit ar restrânge tăcut ce vede panoul.
    """
    db = _SQLDB()
    run(fx.list_open(db, limit=200, offset=200))
    sql, args = db.only()
    where = sql.split("WHERE f.status = 'open'")[1].split("ORDER BY")[0]
    assert not where.strip(), f"drumul implicit a căpătat o clauză: {where!r}"
    assert args == (200, 200)


def test_open_counts_counts_the_same_rows_the_list_shows():
    """Pastilele descriu mulțimea din care s-a tăiat lista, inclusiv 🔥 KEV.

    Defectul prins pe pagină și rămas în bot: numărătoarea era globală, lista
    era filtrată, iar „🔥 2 KEV" stătea deasupra unei liste în care nu era
    niciunul. Numărătoarea de KEV trebuie deci să poarte aceleași filtre ca
    lista — altfel cele două cifre de pe același ecran descriu două mulțimi.
    """
    db = _SQLDB()
    run(fx.open_counts(db, scanners=["trivy_fs"], severities=["critical"]))

    assert len(db.calls) == 2, "numărătoarea pe severități și cea de KEV"
    for sql, args in db.calls:
        assert "coalesce(scanner, '') = ANY($1::text[])" in sql, sql
        assert "severity = ANY($2::text[])" in sql, sql
        assert args == (["trivy_fs"], ["critical"])
    assert "AND kev" in db.calls[1][0]


def test_open_counts_without_filters_is_the_query_the_page_sends():
    """Drumul implicit rămâne neatins, caracter cu caracter.

    Panoul numără global când nu e niciun filtru; o clauză în plus aici ar
    schimba cifrele din antetul paginii fără ca nimic să o ceară.
    """
    db = _SQLDB()
    run(fx.open_counts(db))
    assert db.calls[0][0] == (
        "SELECT severity, count(*) AS n FROM findings WHERE status = 'open'"
        " GROUP BY severity")
    assert db.calls[0][1] == ()
    assert db.calls[1][0] == (
        "SELECT count(*) FROM findings WHERE status = 'open' AND kev")


def test_get_finding_selects_what_the_detail_prints():
    """Coloanele pe care le citește `/vuln <id>` sunt chiar cerute.

    `get_finding` selectează pe nume: o coloană lipsă nu dă eroare, doar
    dispare din mesaj. `epss` e cifra care spune cât de probabil e să fie
    exploatată, iar `location` e ce decide dacă lucrul stă pe sistemul de
    operare, într-o imagine sau într-o aplicație — adică exact întrebarea
    pentru care a fost reparată pagina.
    """
    db = _SQLDB(row=None)
    run(fx.get_finding(db, 3001))
    sql, args = db.only()
    for column in ("f.id", "f.cve", "f.severity", "f.cvss", "f.epss", "f.kev",
                   "f.priority", "f.package", "f.installed_version",
                   "f.fixed_version", "f.location", "f.ecosystem", "f.scanner",
                   "f.status"):
        assert column in sql, f"{column} nu mai e selectată"
    assert args == (3001,)


def test_get_finding_looks_up_by_key_not_by_position():
    """Id-ul ajunge în `WHERE f.id = $1`, fără `LIMIT` peste el.

    Varianta veche căuta id-ul printre primele 1000 de rânduri deschise; pe
    gazda de producție, cu 1055 deschise, ultimele 55 nu se puteau deschide
    deloc.
    """
    db = _SQLDB(row=None)
    run(fx.get_finding(db, 99999))
    sql, _ = db.only()
    assert "WHERE f.id = $1" in sql
    assert "LIMIT" not in sql
    assert "status = 'open'" not in sql, (
        "un finding rezolvat trebuie să poată fi citit, altfel „nu există” și "
        "„s-a reparat” rămân același răspuns")
