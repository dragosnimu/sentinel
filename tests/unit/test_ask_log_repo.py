"""`db/repo/ask_log.py` — plafonul de rată pentru `/intreaba`.

Fără o numărătoare CORECTĂ pe fereastra ultimei ore, plafonul din
`ask_rate_limit_per_hour` fie nu oprește nimic (o interogare care numără altă
fereastră sau alt chat), fie blochează un chat care n-a mai întrebat nimic de
ore întregi — ambele sunt o comandă care spune operatorului ceva fals despre
propria lui folosire.
"""
from __future__ import annotations

import asyncio

from sentinel.db.repo import ask_log


def run(coro):
    return asyncio.run(coro)


class _FakeDB:
    def __init__(self, count: int = 0) -> None:
        self.count = count
        self.executed: list[tuple[str, tuple]] = []
        self.fetchval_calls: list[tuple[str, tuple]] = []

    async def execute(self, sql, *args):
        self.executed.append((sql, args))
        return "INSERT 0 1"

    async def fetchval(self, sql, *args):
        self.fetchval_calls.append((sql, args))
        return self.count


def test_record_scrie_un_rand_cu_chat_id_corect():
    db = _FakeDB()
    run(ask_log.record(db, 4242))

    assert len(db.executed) == 1
    sql, args = db.executed[0]
    assert "ask_log" in sql and "INSERT" in sql
    assert args == (4242,)


def test_count_last_hour_intreaba_cu_chat_id_si_fereastra_unei_ore():
    db = _FakeDB(count=3)
    n = run(ask_log.count_last_hour(db, 4242))

    assert n == 3
    sql, args = db.fetchval_calls[0]
    assert "ask_log" in sql
    assert "interval '1 hour'" in sql
    assert args == (4242,)


def test_count_last_hour_trateaza_null_ca_zero():
    """`fetchval` pe un chat fără nicio întrebare încă întoarce NULL din SQL —
    dacă asta ar deveni o excepție sau `None`, apelantul l-ar compara greșit cu
    plafonul (`None >= limit` pică cu TypeError sub Python 3)."""
    class _NullDB(_FakeDB):
        async def fetchval(self, sql, *args):
            return None

    n = run(ask_log.count_last_hour(_NullDB(), 1))
    assert n == 0
