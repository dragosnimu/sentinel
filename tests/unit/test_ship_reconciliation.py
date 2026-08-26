"""Ștergerea de la sursă trebuie să ajungă și la agregator.

Eșecul pe care îl previne: panoul arată o problemă rezolvată ca fiind încă
deschisă. Ingestia agregatorului e numai upsert, deci un rând șters pe server nu
dispare niciodată dincolo — rămâne acolo, cu ultima lui stare, pentru totdeauna.

Măsurat pe 21 august 2026, imediat după ce fluxul `selfcheck_state` a început să
curgă: serverul avea 43 de verificări, agregatorul 44. A 44-a era
`ship:lag:selfcheck_state:unreadable`, verificarea care semnalase chiar defectul
reparat cu o oră înainte. Serverul o ștersese; panoul o arăta în continuare ca
`unknown`.

Reparația oglindește ștergerea de la sursă: lotul poartă mulțimea COMPLETĂ de
chei, iar receptorul șterge ce nu e în ea. Proprietatea care contează cel mai
mult e negativă și e probată aici: **lista nu se taie niciodată**. O listă tăiată
ar spune „astea sunt toate cheile care există", iar receptorul ar șterge restul —
adică o trunchiere tăcută ar deveni pierdere de date.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from sentinel.report import shipper
from sentinel.report.shipper import MAX_PRUNE_KEYS, STREAMS


def run(coro):
    return asyncio.run(coro)


class _DB:
    """Servește o listă de chei, sau cade — după cum cere testul."""

    def __init__(self, keys=None, boom: str | None = None) -> None:
        self.keys = list(keys or [])
        self.boom = boom
        self.limits: list[int] = []

    async def fetch(self, sql, *args):
        if self.boom:
            raise RuntimeError(self.boom)
        assert " AS k FROM " in sql, sql
        self.limits.append(args[0])
        return [{"k": k} for k in sorted(self.keys)][: args[0]]


PRUNING = [s for s in STREAMS if s.prunes_at_source]
QUIET = [s for s in STREAMS if not s.prunes_at_source]


def test_exactly_the_streams_whose_source_deletes_are_marked() -> None:
    """Garda listelor de mai jos, și o afirmație despre depozit.

    Singurul `DELETE` peste un tabel expediat e cel din `selfcheck/runner.py`.
    Dacă apare al doilea, steagul trebuie pus și acolo — iar linia asta e cea
    care obligă pe cineva să se uite.
    """
    assert [s.name for s in PRUNING] == ["selfcheck_state"], (
        "lista fluxurilor care se reconciliază s-a schimbat; verifică dacă sursa "
        "chiar șterge din tabelul nou, cu `grep -rn 'DELETE FROM'`")
    assert QUIET, "toate fluxurile se reconciliază: garda nu mai probează nimic"


def test_the_complete_key_set_travels_with_the_batch() -> None:
    """Cazul obișnuit: cheile pleacă, toate, sortate."""
    db = _DB(keys=["db:reachable", "alert:telegram", "mode:autoblock"])
    got = run(shipper._prune_keys(db, PRUNING))
    assert got == {"selfcheck_state":
                   ["alert:telegram", "db:reachable", "mode:autoblock"]}


def test_a_stream_whose_source_never_deletes_sends_no_list() -> None:
    """Fără steag, nicio listă — deci receptorul nu poate șterge nimic acolo.

    Contează: o listă trimisă din greșeală pentru `incidents` ar face ca fiecare
    incident absent dintr-un lot să fie șters de pe agregator.
    """
    db = _DB(keys=["orice"])
    assert run(shipper._prune_keys(db, QUIET)) == {}


def test_a_list_that_would_be_too_long_is_omitted_not_truncated() -> None:
    """Proprietatea care contează cel mai mult, și e negativă.

    Omisă, receptorul nu șterge nimic și un rând fantomă mai trăiește o rundă.
    Tăiată, ar fi șters rânduri reale. Prima greșeală se repară singură.
    """
    db = _DB(keys=[f"k{i:05d}" for i in range(MAX_PRUNE_KEYS + 1)])
    assert run(shipper._prune_keys(db, PRUNING)) == {}, (
        "o listă peste plafon a plecat oricum — receptorul ar șterge tot ce nu e "
        "în ea, adică rândurile tăiate")


def test_the_query_asks_for_one_more_than_the_cap() -> None:
    """Ca să POATĂ ști că e prea lungă.

    Cerute exact `MAX_PRUNE_KEYS`, o mulțime de fix atâtea și una mai mare ar
    arăta identic, iar a doua ar fi trimisă ca și cum ar fi completă.
    """
    db = _DB(keys=["a", "b"])
    run(shipper._prune_keys(db, PRUNING))
    assert db.limits == [MAX_PRUNE_KEYS + 1]


def test_a_list_of_exactly_the_cap_still_travels() -> None:
    """Plafonul nu taie cazul legitim de la limită."""
    db = _DB(keys=[f"k{i:05d}" for i in range(MAX_PRUNE_KEYS)])
    got = run(shipper._prune_keys(db, PRUNING))
    assert len(got["selfcheck_state"]) == MAX_PRUNE_KEYS


def test_a_broken_query_does_not_fail_the_batch() -> None:
    """Rândurile sunt treaba; reconcilierea e igienă.

    Un lot pierdut fiindcă n-am putut număra cheile ar fi mai scump decât un rând
    fantomă care mai stă o rundă.
    """
    db = _DB(boom="baza a căzut")
    assert run(shipper._prune_keys(db, PRUNING)) == {}


@pytest.mark.parametrize("stream", PRUNING, ids=lambda s: s.name)
def test_the_key_column_asked_for_is_the_stream_s_own(stream) -> None:
    """Interogarea cere coloana declarată de flux, nu `id` presupus."""
    seen: list[str] = []

    class _Spy(_DB):
        async def fetch(self, sql, *args):
            seen.append(sql)
            return []

    run(shipper._prune_keys(_Spy(), [stream]))
    assert seen and f"SELECT {stream.key_column} AS k FROM {stream.table} " in seen[0], seen
