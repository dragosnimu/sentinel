"""Migrația care dă filigran entităților mutabile — 0023_ship_watermarks.sql.

## Ce NU poate proba fișierul ăsta, citit înainte de a te sprijini pe el

Nu există PostgreSQL în suita asta. Deci ce se verifică aici e că migrația SPUNE
ce trebuie, nu că baza face ce spune ea. „Un rând actualizat capătă `updated_at`
nou" e afirmația centrală a schimbării, iar de aici se poate arăta doar că există
un trigger `BEFORE UPDATE FOR EACH ROW` pe fiecare tabelă expediată și că funcția
lui chiar atribuie coloana — nu că nucleul l-a acceptat și nici că a rulat vreodată.

Distincția e chiar tiparul din `CLAUDE.md`: un fișier pe disc nu e dovadă că a
fost încărcat. Efectul se poate confirma numai pe gazdă, și numai așa:

    UPDATE incidents SET summary = summary WHERE id = <x>;
    SELECT id, updated_at FROM incidents WHERE id = <x>;   -- trebuie să fie now()
    SELECT tgname FROM pg_trigger WHERE tgrelid = 'audit_log'::regclass;

Testele de mai jos închid clasa de defecte care se poate decide mecanic: o
tabelă uitată din listă, un trigger scris `AFTER` (prea târziu — `NEW` nu se mai
poate schimba), o funcție care returnează `NEW` fără să atingă coloana, un
trigger pus din greșeală pe `audit_log`, și un index care nu e în ordinea în care
expeditorul cere rândurile.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sentinel.report import shipper

MIGRATIONS = Path(__file__).resolve().parents[2] / "sentinel" / "db" / "migrations"
SQL = (MIGRATIONS / "0023_ship_watermarks.sql").read_text(encoding="utf-8")

# Tabelele mutabile expediate, cu coloana pe care cursorul le departajează.
# Perechea contează: indexul, `ORDER BY`-ul expeditorului și comparația din
# `WHERE` trebuie să fie aceeași, în aceeași ordine.
MUTABLE_TABLES = {
    "incidents": "id",
    "blocklist": "id",
    "findings": "id",
    "patch_plans": "id",
    "assets": "id",
    "actors": "actor_key",
    "selfcheck_state": "key",
}


@pytest.mark.parametrize("table", sorted(MUTABLE_TABLES))
def test_every_shipped_mutable_table_gets_the_column(table: str):
    """Eșecul pe care îl previne: o entitate al cărei panou nu se mai schimbă.

    O tabelă uitată din listă nu produce nicio eroare nicăieri. Fluxul ei pur și
    simplu nu se poate declara mutabil, iar dacă se declară totuși, prima rundă
    cade pe o coloană inexistentă și fluxul tace din prima zi.
    """
    assert re.search(
        rf"^ALTER TABLE {table} ADD COLUMN updated_at timestamptz NOT NULL "
        rf"DEFAULT now\(\);$", SQL, re.MULTILINE), \
        f"{table} nu primește updated_at în 0023"


@pytest.mark.parametrize("table", sorted(MUTABLE_TABLES))
def test_every_shipped_mutable_table_gets_a_before_update_row_trigger(table: str):
    """Eșecul pe care îl previne: coloana există și nu se mișcă niciodată.

    `updated_at` cu `DEFAULT now()` și fără trigger e cea mai rea dintre toate
    variantele: rândul are o valoare plauzibilă, cursorul avansează peste ea o
    dată, și de atunci nicio schimbare a entității nu mai pleacă de pe gazdă. Pe
    agregator, un incident închis rămâne deschis pentru totdeauna, iar nimic —
    nici jurnal, nici `ship:lag` — nu raportează ceva: fluxul chiar e „la zi".

    `BEFORE`, nu `AFTER`: după UPDATE, `NEW` nu se mai poate schimba, deci un
    trigger `AFTER` care atribuie coloana e cod care rulează și nu face nimic.
    `FOR EACH ROW`, nu `FOR EACH STATEMENT`: un `UPDATE ... WHERE status = 'open'`
    peste 40 de rânduri e o singură instrucțiune.
    """
    pattern = (rf"DROP TRIGGER IF EXISTS {table}_set_updated_at ON {table};\s*"
               rf"CREATE TRIGGER {table}_set_updated_at\s+"
               rf"BEFORE UPDATE ON {table}\s+"
               rf"FOR EACH ROW EXECUTE FUNCTION set_updated_at\(\);")
    assert re.search(pattern, SQL), \
        f"{table} nu primește un trigger BEFORE UPDATE FOR EACH ROW în 0023"


def test_the_trigger_function_actually_assigns_the_column():
    """Eșecul pe care îl previne: șapte triggere care nu fac nimic.

    O funcție de trigger care doar `RETURN NEW;` e sintactic validă, se instalează
    fără o vorbă, rulează la fiecare UPDATE și lasă `updated_at` neschimbat.
    Simptomul e identic cu al triggerului lipsă cu totul — adică niciunul.

    `now()`, nu `clock_timestamp()`: două rânduri atinse de aceeași tranzacție
    trebuie să primească același moment, altfel pot cădea de o parte și de alta a
    unui filigran și jumătate dintr-o schimbare atomică ajunge pe agregator.
    """
    body = re.search(r"CREATE OR REPLACE FUNCTION set_updated_at\(\).*?\$\$ LANGUAGE",
                     SQL, re.DOTALL)
    assert body, "funcția set_updated_at nu e definită în 0023"
    assert re.search(r"NEW\.updated_at\s*:=\s*now\(\)\s*;", body.group(0)), \
        "funcția de trigger nu atribuie updated_at — se instalează și nu face nimic"
    assert "clock_timestamp" not in body.group(0)


def test_audit_log_gets_neither_the_column_nor_a_trigger():
    """Eșecul pe care îl previne: o migrație care nu se poate aplica, sau o
    afirmație falsă lăsată în schemă.

    `0002_response.sql` pune pe `audit_log` un trigger `BEFORE UPDATE OR DELETE`
    care RIDICĂ EXCEPȚIE — tabela e append-only, impus de bază, nu doar evitat în
    cod. Un al doilea trigger `BEFORE UPDATE` acolo n-ar putea să ruleze
    niciodată, fiindcă orice UPDATE moare înainte. Fluxul lui merge pe `id` și nu
    are nevoie de nimic din fișierul ăsta.
    """
    assert not re.search(r"^ALTER TABLE audit_log\b", SQL, re.MULTILINE)
    assert not re.search(r"CREATE TRIGGER audit_log\w*", SQL)
    assert "audit_log" in SQL, (
        "0023 nu mai explică de ce audit_log e lăsată în afară; următorul om o "
        "va adăuga crezând că a fost o scăpare")


def test_the_append_only_trigger_on_audit_log_is_still_the_one_from_0002():
    """Perechea celui de sus, și cea care îl face să însemne ceva.

    Testul de mai sus verifică o ABSENȚĂ, iar o absență trece verde și dacă
    triggerul de append-only a fost șters între timp de altcineva. Atunci
    `audit_log` ar deveni o tabelă obișnuită, rescriabilă, iar motivul pentru care
    0023 o ocolește ar fi dispărut fără ca nimic să pice.
    """
    original = (MIGRATIONS / "0002_response.sql").read_text(encoding="utf-8")
    assert "CREATE TRIGGER audit_log_no_update" in original
    assert "BEFORE UPDATE OR DELETE ON audit_log" in original
    assert "RAISE EXCEPTION 'audit_log is append-only" in original


@pytest.mark.parametrize("table,key", sorted(MUTABLE_TABLES.items()))
def test_the_index_is_in_the_order_the_shipper_reads_rows(table: str, key: str):
    """Eșecul pe care îl previne: fiecare rundă a fiecărui flux e o parcurgere
    completă a tabelei plus o sortare.

    `collect_stream` cere `ORDER BY updated_at, <cheie>` cu `LIMIT`. Fără un index
    exact pe perechea aia, în ordinea aia, PostgreSQL citește tot și sortează —
    pe `findings`, la fiecare 60 de secunde. Un index doar pe `updated_at` nu
    ajunge: departajarea e a doua coloană a sortării.
    """
    assert re.search(
        rf"^CREATE INDEX {table}_updated_idx ON {table} \(updated_at, {key}\);$",
        SQL, re.MULTILINE), f"{table} nu are index pe (updated_at, {key})"


def test_the_cursor_table_gets_the_time_half_of_the_watermark():
    """Eșecul pe care îl previne: un filigran pe pereche păstrat ca un singur text.

    Fără coloana asta, `(updated_at, id)` ar fi trebuit înghesuit într-un
    `cursor` text, iar comparația „a avansat cursorul?" — care se face în SQL, în
    aceeași instrucțiune cu scrierea — ar fi cerut un al doilea parser al aceleiași
    gramatici, în alt limbaj decât cel din Python. Două gramatici scrise de două
    ori, fără nimic care să le lege, e chiar defectul livrat de 0015 și 0020.

    Fără `NOT NULL` dinadins: colectoarele și fluxurile pe `id` n-au jumătate de
    timp, iar `NULL` face comparația de rânduri necunoscută — adică un cursor
    căruia îi lipsește momentul NU avansează, în loc să pornească de la zero.
    """
    assert re.search(
        r"^ALTER TABLE collector_cursors ADD COLUMN cursor_at timestamptz;$",
        SQL, re.MULTILINE)
    assert "NOT NULL" not in SQL.split("collector_cursors ADD COLUMN")[1].split(";")[0]


def test_the_migration_is_not_numbered_over_one_that_is_already_applied():
    """Eșecul pe care îl previne: schema care nu mai avansează deloc.

    `discover()` din `sentinel/db/migrate.py` ridică `StorageError` la două
    fișiere cu același număr, iar `run_migrations` iese cu 1 — deci nu se mai
    aplică NICIO migrație, nici cele de după. Planul cerea „0022_ship_watermarks";
    0022 era deja luat de identitatea de instanță, care e livrată.
    """
    numbers = sorted(int(p.name[:4]) for p in MIGRATIONS.glob("*.sql"))
    assert len(numbers) == len(set(numbers))
    assert (MIGRATIONS / "0023_ship_watermarks.sql").is_file()
    assert not (MIGRATIONS / "0022_ship_watermarks.sql").exists()


def test_the_whole_file_is_one_transaction_worth_of_work():
    """Migrațiile se aplică una-o-tranzacție (`sentinel/db/migrate.py`), iar pe
    PostgreSQL DDL-ul E tranzacțional — deci un eșec la a cincea tabelă nu lasă
    patru cu trigger și trei fără.

    Ce ar strica garanția aia: un `COMMIT`, un `BEGIN` sau un `CREATE INDEX
    CONCURRENTLY` scris în fișier. Ultimul nu se poate rula într-o tranzacție
    deloc, iar PostgreSQL îl refuză cu o eroare care numește tranzacția, nu
    indexul — o oră pierdută la următorul deploy.
    """
    # Se scot întâi comentariile și corpurile citate cu `$$`: `COMMIT_SAFETY_LAG_S`
    # e numit într-un comentariu, iar `BEGIN` e cuvântul de bloc al lui plpgsql,
    # nu control de tranzacție. Un test care se potrivește peste ele ar fi roșu
    # pentru un fișier perfect corect — și, mai rău, ar fi ajustat până se face
    # verde.
    without_bodies = re.sub(r"\$\$.*?\$\$", " ", SQL, flags=re.DOTALL)
    statements = "\n".join(line for line in without_bodies.splitlines()
                           if not line.lstrip().startswith("--")).upper()
    for forbidden in (r"\bCOMMIT\b", r"\bBEGIN\b", r"\bCONCURRENTLY\b", r"\bVACUUM\b"):
        assert not re.search(forbidden, statements), \
            f"{forbidden} rupe garanția „un fișier, o tranzacție”"


def test_the_shipper_and_the_migration_agree_on_what_a_mutable_stream_needs():
    """Cele două jumătăți ale schimbării sunt scrise în două limbaje.

    Migrația creează coloana și triggerul; expeditorul cere coloana pe nume. Dacă
    una se redenumește fără cealaltă, fluxul nu produce o eroare de configurație:
    cade la prima rundă pe o coloană inexistentă, iar de pe gazdă asta arată ca o
    bază indisponibilă — `ship_once` prinde orice excepție de citire ca rundă
    ratată și reîncearcă la nesfârșit.
    """
    probe = shipper.Stream(name="p", table="incidents",
                           columns=("id", "updated_at"), time_column="updated_at",
                           cursor_kind=shipper.MUTABLE)
    assert probe.time_column == "updated_at"
    assert f"ADD COLUMN {probe.time_column} timestamptz" in SQL
    assert probe.key_column == "id"
