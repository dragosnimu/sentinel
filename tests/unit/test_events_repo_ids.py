"""Preallocarea id-urilor din `raw_events_id_seq`, ca `event_id` să ajungă corect.

Ce previn testele astea, fiecare cu forma pe care ar avea-o pe ecran:

  * **Un `event_id` care leagă o comandă de rândul brut al alteia.** Dacă
    `insert_batch` ar atribui id-urile în altă ordine decât cea în care le-a
    cerut, sau ar pune ACELAȘI id pe mai multe evenimente, o investigație ar
    fi trimisă la rândul brut al altcuiva — mai rău decât o coloană goală.
  * **Ingestia oprită de o secvență indisponibilă.** Dacă `raw_events_id_seq`
    nu poate fi citită (bază picată, timeout), scrierea evenimentelor tot
    trebuie să reușească — cu id implicit din `bigserial`, ca înainte.
  * **Un `event_id` inventat când legătura nu s-a putut face.** Absența
    trebuie să rămână absență (`ev.id is None`), nu un 0 sau alt substitut
    care ar arăta ca o legătură reală mai târziu, în `session_commands`.
  * **`src_ip`/`dst_ip`/`raw` scrise cu tipul PostgreSQL greșit, fiindcă `id`
    s-a adăugat înaintea lor și a deplasat pozițiile.** O versiune veche a
    acestui fișier lega tipul de o poziție hardcodată (`"$5::inet"`), nu de
    numele coloanei — corectă doar cât timp nimeni nu adaugă o coloană
    înaintea lui `src_ip`, exact ce face `id` acum.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sentinel.db.repo import events as events_repo
from sentinel.model.event import Event


def run(coro):
    return asyncio.run(coro)


class _FakeRecord(dict):
    """Un `dict` e suficient: codul citește doar `r["id"]`."""


class _FakeDB:
    """Dublu minimal: ține evidența comenzilor SQL primite, nu reimplementează Postgres.

    `fetch` simulează `SELECT nextval(...) FROM generate_series(...)`, fără să
    depindă de text — dacă `insert_batch` ar întreba altceva, `n` ar veni greșit
    și testele de mai jos ar prinde discrepanța prin numărul de id-uri alocate.
    """

    def __init__(self, *, fail: bool = False, id_start: int = 1000) -> None:
        self.fail = fail
        self._next_id = id_start
        self.executemany_calls: list[tuple[str, list[tuple]]] = []

    async def fetch(self, sql: str, n: int):
        if self.fail:
            raise OSError("conexiunea a picat chiar când cerea id-urile")
        ids = list(range(self._next_id, self._next_id + n))
        self._next_id += n
        return [_FakeRecord(id=i) for i in ids]

    async def executemany(self, sql: str, rows: list[tuple]) -> None:
        self.executemany_calls.append((sql, rows))


def _ev(argv: str) -> Event:
    return Event(ts=datetime(2026, 8, 31, 10, 0, tzinfo=timezone.utc),
                 source="auditd", action="command", raw={"argv": argv})


def test_each_event_gets_a_distinct_id_matching_the_row_it_was_written_with() -> None:
    """Verifică prin EXECUȚIE, nu prin numele coloanei: id-ul pus pe `ev.id`
    trebuie să fie EXACT cel scris pe rândul acelui eveniment în `raw_events`,
    nu al vecinului din același lot.
    """
    db = _FakeDB(id_start=5000)
    events = [_ev("a"), _ev("b"), _ev("c")]

    run(events_repo.insert_batch(db, events))

    ids_on_events = [e.id for e in events]
    assert len(set(ids_on_events)) == 3, "două evenimente au primit același id"
    assert all(i is not None for i in ids_on_events)

    [(sql, rows)] = db.executemany_calls
    assert sql is events_repo._INSERT_WITH_ID
    id_pos = events_repo._COLS_WITH_ID.index("id")
    written_ids = [row[id_pos] for row in rows]

    # Fiecare rând scris trebuie să poarte id-ul de pe OBIECTUL lui, în ordinea
    # în care evenimentele au fost date — nu id-uri amestecate între rânduri.
    assert written_ids == ids_on_events


def test_preallocation_failure_falls_back_without_losing_the_batch() -> None:
    """Ingestia nu are voie să cadă din cauza unei coloane de urmărire."""
    db = _FakeDB(fail=True)
    events = [_ev("a"), _ev("b")]

    n = run(events_repo.insert_batch(db, events))

    assert n == 2, "lotul nu s-a mai scris fiindcă preallocarea a picat"
    assert all(e.id is None for e in events), (
        "un id a fost pus pe eveniment deși preallocarea a eșuat -- ar arăta "
        "ca o legătură reală mai târziu, în session_commands.event_id")
    [(sql, rows)] = db.executemany_calls
    assert sql is events_repo._INSERT, (
        "s-a folosit instrucțiunea cu `id` deși nu există niciun id de pus")
    assert len(rows) == 2


def test_a_row_count_mismatch_is_treated_as_failure_not_partial_success() -> None:
    """O presupunere nevalidată aici ar însemna id-uri la nimereală.

    Dublul întoarce mai puține rânduri decât s-au cerut -- un caz pe care
    `generate_series` nu-l produce în practică, dar exact genul de
    presupunere nevalidată pe care regula 1 din temă o interzice.
    """
    class _ShortFakeDB(_FakeDB):
        async def fetch(self, sql: str, n: int):
            rows = await super().fetch(sql, n)
            return rows[:-1]  # un id mai puțin decât s-a cerut

    db = _ShortFakeDB(id_start=1)
    events = [_ev("a"), _ev("b")]

    run(events_repo.insert_batch(db, events))

    assert all(e.id is None for e in events)
    [(sql, _rows)] = db.executemany_calls
    assert sql is events_repo._INSERT


def _placeholder_for(insert_sql: str, position_1_based: int) -> str:
    values_clause = insert_sql.split("VALUES (", 1)[1].rstrip(") \n")
    parts = [p.strip() for p in values_clause.split(",")]
    return parts[position_1_based - 1]


def test_typed_columns_keep_their_cast_after_id_shifts_every_position() -> None:
    """Tipul PostgreSQL trebuie legat de NUMELE coloanei, nu de poziția ei.

    `id` se adaugă înaintea tuturor celorlalte coloane. O versiune care ar
    lega tipul de o poziție fixă (cum lega vechiul cod `src_ip` de `"$5"`) ar
    pune `::inet` pe placeholder-ul lui `id` și ar lăsa `src_ip` fără cast --
    iar asyncpg ar trimite un `text` acolo unde Postgres așteaptă `inet`,
    picând lotul întreg de îndată ce apare primul `src_ip` nenul.
    """
    cols = events_repo._COLS_WITH_ID
    sql = events_repo._INSERT_WITH_ID
    tipate = {"src_ip": "inet", "dst_ip": "inet", "raw": "jsonb"}

    # Nu doar CĂ poartă castul corect, ci că-l poartă la NUMĂRUL DE POZIȚIE
    # corect: verificăm șirul întreg, nu doar sufixul, fiindcă un placeholder
    # hardcodat („$5::inet” indiferent de poziția reală) ar trece un test care
    # se uită doar dacă textul „::inet” apare undeva pe rândul respectiv.
    for i, c in enumerate(cols, start=1):
        asteptat = f"${i}::{tipate[c]}" if c in tipate else f"${i}"
        assert _placeholder_for(sql, i) == asteptat, (
            f"coloana {c!r} de la poziția {i} a primit placeholder-ul "
            f"{_placeholder_for(sql, i)!r}, nu {asteptat!r} -- asyncpg ar lega "
            f"valoarea altei coloane sub tipul ăsta")
