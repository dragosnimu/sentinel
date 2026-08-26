"""Tipul cheii unui flux mutabil, verificat pe trei fețe care trebuie să coincidă.

Eșecul pe care îl previne, în termeni de ce se strică pentru operator: un flux
declarat corect, cu serviciul `active` și fără nicio repornire, care nu livrează
niciodată un rând — iar pagina lui din panou rămâne goală luni de zile.

Exact asta s-a întâmplat cu `selfcheck_state` până pe 21 august 2026. Cheia lui
e `key`, o coloană `text`, dar șablonul SQL avea `::bigint` scris de mână în
patru locuri, iar cursorul era convertit cu un `int()` necondiționat. Postgres
răspundea la fiecare rundă cu `operator does not exist: text > bigint`. Nimic nu
se oprea: doar o linie de jurnal, și 43 de verificări de sănătate care nu
ajungeau în panou.

De ce testele existente nu l-au prins: baza falsă din `test_shipper.py` nu
execută SQL. Un `text > bigint` e o eroare a lui Postgres, nu a Python-ului, deci
un dublu îl trece fără să clipească. Testele de aici verifică de aceea ce POATE
fi verificat fără o bază: că cele trei declarații ale aceluiași tip — coloana din
migrație, cast-ul din SQL și tipul valorii legate — spun toate același lucru.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sentinel.report import shipper
from sentinel.report.shipper import MUTABLE, STREAMS, Stream

MIGRATIONS = Path(__file__).resolve().parents[2] / "sentinel" / "db" / "migrations"

MUTABLE_STREAMS = [s for s in STREAMS if s.cursor_kind == MUTABLE]

#: Ce tip SQL de coloană se potrivește cu ce fel de filigran. `bigserial` e
#: `bigint` cu o secvență, deci intră la același fel.
COLUMN_TO_KIND = {
    "bigint": "int", "bigserial": "int", "integer": "int", "serial": "int",
    "text": "text", "varchar": "text", "citext": "text",
}


def _declared_column_type(table: str, column: str) -> str | None:
    """Tipul coloanei așa cum îl scrie migrația care creează tabelul.

    Migrațiile sunt sursa de adevăr pentru schema de producție, iar un test care
    ar întreba o bază de test ar verifica altceva decât ce se instalează.
    """
    pattern = re.compile(
        r"CREATE TABLE (?:IF NOT EXISTS )?" + re.escape(table) + r"\s*\((.*?)\n\);",
        re.DOTALL | re.IGNORECASE)
    for path in sorted(MIGRATIONS.glob("*.sql")):
        found = pattern.search(path.read_text(encoding="utf-8"))
        if not found:
            continue
        for line in found.group(1).splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("--"):
                continue
            parts = stripped.split()
            if parts[0].strip('"') == column:
                return parts[1].split("(")[0].lower()
    return None


def test_there_is_at_least_one_mutable_stream_of_each_kind() -> None:
    """Garda listei parametrizate.

    Un `parametrize` peste o listă ieșită goală trece în tăcere și raportează
    zero eșecuri — s-a mai întâmplat în depozitul ăsta și a costat o pană. Dacă
    fluxul cu filigran text dispare din declarații, testele de mai jos ar deveni
    decorative, iar linia asta e cea care spune asta cu voce tare.
    """
    kinds = {s.watermark_kind for s in MUTABLE_STREAMS}
    assert "text" in kinds, (
        "niciun flux mutabil cu filigran text: testele de mai jos nu mai "
        "acoperă calea pe care a picat `selfcheck_state`")
    assert "int" in kinds, "niciun flux mutabil cu filigran întreg"


@pytest.mark.parametrize("stream", MUTABLE_STREAMS, ids=lambda s: s.name)
def test_the_declared_column_and_the_watermark_kind_agree(stream: Stream) -> None:
    """Coloana din migrație și felul filigranului spun același lucru.

    Asta e verificarea care prinde fluxul URMĂTOR, nu doar pe cel reparat: cine
    adaugă un flux cu cheie text și uită `watermark_kind="text"` află aici, la
    import, nu peste luni dintr-o pagină goală.
    """
    declared = _declared_column_type(stream.table, stream.key_column)
    assert declared is not None, (
        f"nu am găsit coloana {stream.key_column!r} a tabelului {stream.table!r} "
        f"în migrații — testul nu poate verifica nimic, deci pică")
    expected = COLUMN_TO_KIND.get(declared)
    assert expected is not None, (
        f"tipul {declared!r} nu e cunoscut de tabelul de potrivire; adaugă-l "
        f"împreună cu felul de filigran care i se potrivește")
    assert expected == stream.watermark_kind, (
        f"{stream.name}: coloana {stream.key_column} e {declared}, deci "
        f"filigranul ar trebui să fie {expected!r}, nu {stream.watermark_kind!r}. "
        f"Nepotrivirea nu oprește nimic — fluxul pornește și tace.")


@pytest.mark.parametrize("stream", MUTABLE_STREAMS, ids=lambda s: s.name)
def test_the_sql_cast_matches_the_column_it_is_compared_against(
        stream: Stream) -> None:
    """Cast-ul din SQL urmează tipul coloanei, nu un `bigint` fixat în șablon.

    Forma exactă a bug-ului: `WHERE (updated_at, key) > ($1::timestamptz,
    $2::bigint)` pe o coloană `key` de tip text.
    """
    declared = _declared_column_type(stream.table, stream.key_column)
    assert declared is not None
    if declared == "text":
        assert stream.key_sql_type == "text", (
            f"{stream.name}: cheia e text, dar comparația s-ar lega ca "
            f"{stream.key_sql_type} — Postgres răspunde `operator does not exist`")
    else:
        assert stream.key_sql_type == "bigint"


@pytest.mark.parametrize("stream", MUTABLE_STREAMS, ids=lambda s: s.name)
def test_the_bound_cursor_keeps_the_type_the_column_has(stream: Stream) -> None:
    """Valoarea legată în SQL are tipul Python potrivit coloanei.

    Un `int()` necondiționat aici e a doua jumătate a aceleiași pene: chiar cu
    cast-ul corect în șablon, o cheie text convertită la întreg ar cădea cu
    `invalid input syntax for type bigint`.
    """
    value = shipper._cursor_key(stream, "web")  if stream.watermark_kind == "text" \
        else shipper._cursor_key(stream, "41")
    if stream.watermark_kind == "text":
        assert isinstance(value, str) and value == "web"
    else:
        assert isinstance(value, int) and value == 41


@pytest.mark.parametrize("stream", MUTABLE_STREAMS, ids=lambda s: s.name)
def test_the_first_seed_cannot_hide_rows(stream: Stream) -> None:
    """Pragul de la prima semănare nu taie nicio cheie reală.

    Pe un flux text, `'0'` ar exclude tăcut orice cheie care sortează sub
    caracterul `0`, iar simptomul ar fi „lipsesc rânduri din panou" — o clasă de
    bug mult mai greu de găsit decât o eroare la fiecare rundă.
    """
    if stream.watermark_kind == "text":
        assert stream.key_floor == "", (
            f"{stream.name}: pragul text e {stream.key_floor!r}, nu șirul gol")
    else:
        assert stream.key_floor == "0"


def test_an_unknown_watermark_kind_is_refused_at_declaration() -> None:
    """Un fel de filigran necunoscut cade la import, pe mașina celui care îl
    scrie — nu în producție, ca un flux care tace.
    """
    with pytest.raises(ValueError, match="watermark_kind"):
        Stream(name="inventat", table="selfcheck_state",
               columns=("key", "updated_at"), time_column="updated_at",
               cursor_kind=MUTABLE, key_column="key", watermark_kind="uuid")


# ---------------------------------------------------------------------------
# A treia fața: ecoul. Filigranul a trecut de SQL și a plecat — dar cursorul
# avansează doar dacă receptorul îl ecouă, iar verificarea aia cerea un întreg.
# ---------------------------------------------------------------------------

def _body(accepted: dict) -> str:
    import json
    return json.dumps({"ok": True, "accepted": accepted})


def test_a_text_watermark_echoed_back_exactly_is_confirmed() -> None:
    """Fluxul text, acceptat și ecouat identic, trebuie CONFIRMAT.

    Eșecul pe care îl previne, măsurat în producție pe 21 august 2026: cele 43 de
    rânduri plecau, agregatorul le accepta și ecoua exact șirul trimis, iar
    expeditorul refuza să avanseze fiindcă verificarea cerea `int`. Rândurile se
    retrimiteau la fiecare rundă, la nesfârșit — un flux care nu termină niciodată
    de livrat arată, din contoare, exact ca unul care nu livrează deloc.
    """
    sent = {"selfcheck_state": "unit:sentinel-web.service"}
    confirmed, why = shipper.accepted_watermarks(_body(dict(sent)), sent)
    assert confirmed == sent, f"filigranul text nu a fost confirmat: {why}"
    assert why == ""


def test_a_number_echoed_for_a_text_watermark_is_refused() -> None:
    """Alt tip decât cel trimis înseamnă că nu vorbim despre același lot."""
    confirmed, why = shipper.accepted_watermarks(
        _body({"selfcheck_state": 42}), {"selfcheck_state": "unit:web"})
    assert confirmed == {}
    assert "int" in why and "str" in why


def test_a_string_echoed_for_an_int_watermark_is_refused() -> None:
    """Și invers — altfel un receptor care întoarce `"346"` ar părea că a preluat."""
    confirmed, why = shipper.accepted_watermarks(
        _body({"audit_log": "346"}), {"audit_log": 346})
    assert confirmed == {}
    assert "str" in why


def test_true_is_still_refused_for_an_int_watermark() -> None:
    """Proprietatea de dinainte, care nu are voie să se piardă la reparație.

    În Python `True == 1`, deci `{"audit_log": true}` ar confirma filigranul 1
    fără ca nimeni să scrie asta. Comparația pe tip exact o respinge — dar asta
    trebuie PROBAT, nu dedus: `isinstance(True, int)` e adevărat.
    """
    confirmed, why = shipper.accepted_watermarks(
        _body({"audit_log": True}), {"audit_log": 1})
    assert confirmed == {}
    assert "bool" in why


def test_a_float_echo_is_refused_for_an_int_watermark() -> None:
    """`346.0` de la un receptor neglijent nu e `346`."""
    confirmed, why = shipper.accepted_watermarks(
        _body({"audit_log": 346.0}), {"audit_log": 346})
    assert confirmed == {}
    assert "float" in why


# ---------------------------------------------------------------------------
# A patra față: SQL-ul CHIAR EMIS de scriitorii de cursor.
#
# Testele de mai sus verifică declarațiile. Astea verifică ce ajunge la driver,
# fiindcă acolo a fost a doua jumătate a penei: patru locuri reparate, alte cinci
# rămase cu `::bigint` scris de mână. Expeditorul a pornit, a încercat să lege
# șirul `'0'` la un parametru `bigint`, a căzut ÎNAINTE de prima rundă și a intrat
# în buclă până când systemd a renunțat — deci s-au oprit toate cele opt fluxuri,
# nu doar cel reparat. Un flux stricat devenise un expeditor mort.
# ---------------------------------------------------------------------------

class _RecordingDB:
    """Reține SQL-ul, nu îl execută. Ce se verifică aici e forma lui."""

    def __init__(self) -> None:
        self.sql: list[str] = []

    async def fetchrow(self, sql, *args):
        self.sql.append(sql)
        return {"cursor_at": None, "cursor_key": None}

    async def execute(self, sql, *args):
        self.sql.append(sql)
        return "INSERT 0 1"


def _emitted(fn, stream: Stream) -> str:
    import asyncio
    from datetime import datetime, timezone
    db = _RecordingDB()
    asyncio.run(fn(db, stream, (datetime(2026, 8, 21, tzinfo=timezone.utc),
                                "unit:web" if stream.watermark_kind == "text" else 7),
                   3))
    return "\n".join(db.sql)


@pytest.mark.parametrize("stream", MUTABLE_STREAMS, ids=lambda s: s.name)
@pytest.mark.parametrize("writer", ["_advance_mutable", "_remember_window"],
                         ids=["avans", "fereastră"])
def test_no_cursor_writer_casts_a_text_key_as_bigint(
        stream: Stream, writer: str) -> None:
    """Parametrul $3 e jumătatea-cheie. Cast-ul lui urmează tipul fluxului.

    Verificat pe SQL-ul emis, nu pe o constantă: aici a fost greșeala. O căutare
    după un singur tipar a raportat „niciun `::bigint` rămas" în timp ce cinci
    mai existau în alte forme.
    """
    sql = _emitted(getattr(shipper, writer), stream)
    if stream.watermark_kind == "text":
        assert "$3::bigint" not in sql, (
            f"{writer} leagă cheia text a lui {stream.name} ca bigint — "
            f"expeditorul cade la pornire și se oprește TOT")
        assert "$3::text" in sql, f"{writer}: cheia text nu e legată ca text"
    else:
        assert "$3::bigint" in sql, (
            f"{writer}: cheia întreagă a lui {stream.name} nu mai e comparată "
            f"numeric — '10' ar fi mai mic decât '9' și cursorul ar merge înapoi")


def test_the_key_sql_pieces_change_together() -> None:
    """Cele trei bucăți vin dintr-un singur loc, ca să nu poată diverge."""
    text_stream = next(s for s in MUTABLE_STREAMS if s.watermark_kind == "text")
    int_stream = next(s for s in MUTABLE_STREAMS if s.watermark_kind == "int")

    stored, incoming, returned = shipper._key_sql(text_stream)
    assert "::bigint" not in stored + incoming + returned

    stored, incoming, returned = shipper._key_sql(int_stream)
    assert all("::bigint" in piece for piece in (stored, incoming, returned)), (
        "cheia întreagă trebuie comparată și întoarsă ca număr; coloana e text, "
        "iar pe text '10' < '9'")
