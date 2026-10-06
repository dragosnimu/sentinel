"""`scripts/backfill-recommended-action.py` — decizia, fără bază de date.

Partea cu baza (read-only de-adevăratelea, compare-and-set, `updated_at`,
re-rulare) e în `tests/integration/test_ai_verdict_pg.py`, pe un Postgres real.
Aici e ce se poate spune fără unul:

  * **Valorile pe care producția chiar le are.** Cele 14 ortografii măsurate pe
    6 octombrie 2026 sunt tabela de adevăr: fiecare se plasează pe cuvântul
    potrivit sau rămâne neatinsă. Un script care ar «repara» altceva decât a
    văzut operatorul în raportul uscat n-ar mai fi cel pe care el l-a aprobat.
  * **A doua regulă.** Dacă scriptul și plasa din `triage` ajung să decidă
    diferit, un rând vechi și unul nou înseamnă lucruri diferite; testul de
    acord ține cele două legate.
  * **Uscat înseamnă că serverul refuză scrierea**, nu că scriptul se abține.

Backslash-ul se construiește din `chr(92)`: unealta prin care se scrie fișierul
înjumătățește barele și convertește secvențele de escape.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from sentinel.ai import triage

REPO = Path(__file__).resolve().parents[2]
CALE = REPO / "scripts" / "backfill-recommended-action.py"
BS = chr(92)
ESC_A = BS + "u0103"


def _modul():
    spec = importlib.util.spec_from_file_location("backfill_recommended_action", CALE)
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul


backfill = _modul()

# Tabelul măsurat pe producție (6 oct 2026), valoare stocată → (cuvânt, fel) sau None.
PRODUCTIE = [
    ("blocheaz" + ESC_A, "blochează", "escape"),
    ("investigheaz" + ESC_A, "investighează", "escape"),
    ("monitorizeaz" + ESC_A, "monitorizează", "escape"),
    ("investigheaz", "investighează", "prefix"),
    ("blocheaz", "blochează", "prefix"),
    ("ignor", "ignoră", "prefix"),
    ("monitorizeaz", "monitorizează", "prefix"),
    ("investigheaza", "investighează", "folded"),
    ("blocheaza", "blochează", "folded"),
    ("monitorizeaza", "monitorizează", "folded"),
    ("ignora", "ignoră", "folded"),
    ("unknown", None, None),
    ("investighează", None, None),
    ("blochează", None, None),
]


@pytest.mark.parametrize("stored,new,kind", PRODUCTIE)
def test_every_value_production_holds_is_placed_or_left_alone(stored, new, kind):
    """Tabela de adevăr pe cele 14 valori reale: fiecare ortografie stricată
    pe cuvântul ei, fiecare valoare deja bună sau `unknown` neatinsă.

    `unknown` NU se atinge: valoarea brută s-a pierdut, deci n-are din ce să se
    deducă ceva; un script care ar pune acolo un cuvânt ar inventa un verdict.
    """
    d = backfill.decide(stored)
    if new is None:
        assert d is None, f"{stored!r} a fost atinsă: {d}"
    else:
        assert d is not None, f"{stored!r} nu s-a plasat — rămâne stricat în istoric"
        assert (d.new, d.kind) == (new, kind)


@pytest.mark.parametrize("stored", ["i", "bl", "mon", "sparge tot", "", "blo",
                                     "block-ul", "investigheaza-l", "x" * 40])
def test_what_cannot_be_placed_without_guessing_is_left_alone(stored):
    """Fragmente sub 4 litere, text străin, valori care doar ARATĂ a prefix:
    rămân exact cum sunt. Scriptul nu are voie să ghicească."""
    assert backfill.decide(stored) is None


def test_the_script_and_the_net_never_disagree():
    """Pe orice șir, scriptul fie nu atinge, fie dă EXACT ce dă plasa din
    `triage` — și mereu un cuvânt din enum.

    Două reguli care s-ar abate una de alta ar face ca un rând din istoric și
    unul scris azi să însemne lucruri diferite pentru același răspuns al
    modelului.
    """
    probe = [s for s, *_ in PRODUCTIE] + [
        "BLOCHEAZĂ", " blochează ", "blocheaz" + BS + BS + "u0103", "bloc", "inve",
        "patch", "block", "ignore", "monitor", "investigate", "taie", "ignorez",
        "blocheaz" + BS + "ud800", "blocheaz" + BS + "u00e3", "mon" + BS + "u0103"]
    for s in probe:
        d = backfill.decide(s)
        if d is not None:
            assert d.new == triage._normalise_action(s), s
            assert d.new in triage._ACTION_ENUM, s


def test_final_values_are_read_from_the_net_not_retyped():
    """Lista de valori deja finale vine din aceleași constante ca plasa.

    Un cuvânt adăugat acolo și uitat aici ar fi «reparat» la nesfârșit de
    fiecare rulare, cu `updated_at` mutat de fiecare dată.
    """
    for w in [*triage._ACTION_ENUM, *triage._ACTION_WIRE, "unknown"]:
        assert w in backfill.FINAL_VALUES


class _FakeConn:
    def __init__(self):
        self.executed = []

    async def execute(self, sql, *args):
        self.executed.append(sql)

    async def close(self):
        pass


def _connect_with(monkeypatch, apply):
    conn = _FakeConn()
    seen = {}

    async def fake_connect(dsn, **kw):
        seen["kw"] = kw
        return conn

    monkeypatch.setattr(backfill.asyncpg, "connect", fake_connect)
    monkeypatch.setattr(backfill, "database_dsn", lambda cfg: "postgresql://x")
    asyncio.run(backfill._connect(object(), read_only=not apply))
    return conn, seen


def test_the_dry_run_session_is_read_only_at_the_server(monkeypatch):
    """Modul uscat deschide sesiunea `default_transaction_read_only = on`.

    «Nu apelez UPDATE» e o intenție; asta e un fapt pe care serverul îl
    impune. Fără el, o modificare viitoare care mută un UPDATE în afara lui
    `if apply:` ar scrie în baza de producție în timpul unei rulări «uscate».
    """
    conn, _ = _connect_with(monkeypatch, apply=False)
    assert any("default_transaction_read_only" in sql and "on" in sql
               for sql in conn.executed), conn.executed


def test_the_apply_session_is_not_read_only(monkeypatch):
    """Și invers: cu `--apply` sesiunea NU e read-only, altfel `--apply` ar
    raporta «scrise: 0» pe un server care a refuzat tot — iar un script care
    nu poate scrie nu are voie să arate ca unul care n-avea ce scrie."""
    conn, _ = _connect_with(monkeypatch, apply=True)
    assert not any("read_only" in sql for sql in conn.executed), conn.executed


def test_the_documented_invocation_runs_from_a_copy_outside_the_repository(tmp_path):
    """Pe gazdă nu există `scripts/` și nici depozitul: operatorul copiază
    scriptul într-un director oarecare și dă `PYTHONPATH=/opt/sentinel/lib`,
    exact ca unitățile systemd. Dacă scriptul ar începe să presupună că stă
    lângă `sentinel/` (o cale relativă la depozit, un import din `scripts/lib`),
    comanda din docstring ar cădea pe gazdă și nu aici, unde totul e la locul lui.

    `--help` trece prin importurile de sus (asyncpg, `sentinel.ai.triage`,
    `sentinel.config`) fără să deschidă nicio conexiune.
    """
    copie = tmp_path / "backfill-recommended-action.py"
    shutil.copy(CALE, copie)
    env = {**os.environ, "PYTHONPATH": str(REPO), "PYTHONUTF8": "1",
           "PYTHONDONTWRITEBYTECODE": "1"}
    rulat = subprocess.run([sys.executable, "-B", str(copie), "--help"], cwd=tmp_path,
                           env=env, capture_output=True, text=True, encoding="utf-8")
    assert rulat.returncode == 0, rulat.stderr
    assert "--apply" in rulat.stdout, rulat.stdout
