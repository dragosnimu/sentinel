"""Un Postgres real pentru drumul `recommended_action` și pentru scriptul de
reparat istoricul. Un dublu nu poate spune nimic din ce urmează.

## De ce există fișierul ăsta

**Granița de decodare.** Pe producție, 415 din 791 de verdicte au în
`recommended_action` șase caractere literale (backslash, u, 0103) în loc de `ă`,
în rânduri al căror `summary_ro` are diacritice adevărate. Cauza nu poate fi
stocarea dacă stocarea aduce înapoi exact ce a primit — și asta se află doar
dintr-un `jsonb` și un `asyncpg` adevărate. Primul test fixează fapta: un `ă`
adevărat iese `ă` adevărat, un backslash literal iese backslash literal.

**Backfill-ul.** Dublul din `test_purge_automation_commands.py` își citește
predicatele din textul instrucțiunii și apoi le aplică din propria
reimplementare; aici contează tocmai ce face SERVERUL cu `||` pe jsonb, cu
declanșatorul `updated_at`, cu `default_transaction_read_only`, cu un
compare-and-set care nu potrivește.

OPȚIONAL: rulează când `SENTINEL_TEST_PG_DSN` arată spre un Postgres, sau când
`docker` răspunde (pornește singur un `postgres:16-alpine` de unică folosință).
Altfel se sare, cu motivul spus.

Backslash-ul se construiește din `chr(92)`: unealta prin care se scrie fișierul
înjumătățește barele și convertește secvențele de escape.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import io
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

asyncpg = pytest.importorskip("asyncpg", reason="asyncpg not installed")

from sentinel.ai import triage  # noqa: E402
from sentinel.config import Config  # noqa: E402
from sentinel.db.engine import Database  # noqa: E402
from sentinel.db.migrate import run_migrations  # noqa: E402
from sentinel.db.repo import incidents as inc_repo  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
BS = chr(92)
ESC_A = BS + "u0103"
A_BREVE = chr(0x103)


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "backfill_recommended_action_pg", REPO / "scripts" / "backfill-recommended-action.py")
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul


backfill = _load_script()

#: Valoarea stocată → câte rânduri, EXACT cum le-a măsurat interogarea de pe
#: producție pe 6 octombrie 2026 (791 de verdicte). Baza de test are aceeași formă
#: ca cea reală, deci numerele raportului uscat sunt ale ei.
PRODUCTIE: dict[str, int] = {
    "blocheaz" + ESC_A: 316, "unknown": 169, "investigheaz" + ESC_A: 90,
    "investigheaz": 76, "investigheaza": 75, "blocheaz": 25,
    "investighează": 12, "monitorizeaz" + ESC_A: 9, "blochează": 8,
    "monitorizeaza": 4, "ignor": 3, "blocheaza": 2, "monitorizeaz": 1, "ignora": 1,
}


def _docker_daemon_reachable() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=5, check=True)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _wait_until_reachable(dsn: str, timeout_s: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            conn = await asyncpg.connect(dsn, timeout=3)
        except (OSError, asyncpg.PostgresError):
            await asyncio.sleep(0.5)
            continue
        await conn.close()
        return True
    return False


@pytest.fixture(scope="module")
def pg_dsn():
    """Un Postgres migrat complet, sau o sărire explicită."""
    env_dsn = os.environ.get("SENTINEL_TEST_PG_DSN")
    if env_dsn:
        rc = run_migrations(dry_run=False, dsn=env_dsn)
        if rc != 0:
            pytest.skip(f"SENTINEL_TEST_PG_DSN dat, dar migrațiile au eșuat (rc={rc})")
        yield env_dsn
        return

    if not _docker_daemon_reachable():
        pytest.skip(
            "nici SENTINEL_TEST_PG_DSN, nici un daemon docker accesibil — drumul "
            "`recommended_action` și backfill-ul NU au fost rulate de un Postgres "
            "real; vezi docstring-ul modulului")

    port = _free_tcp_port()
    name = f"sentinel-test-aiverdict-pg-{port}"
    subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name,
         "-e", "POSTGRES_PASSWORD=test", "-e", "POSTGRES_DB=sentinel_test",
         "-p", f"127.0.0.1:{port}:5432", "postgres:16-alpine"],
        check=True, capture_output=True, timeout=60)
    dsn = f"postgresql://postgres:test@127.0.0.1:{port}/sentinel_test"
    try:
        if not asyncio.run(_wait_until_reachable(dsn)):
            pytest.skip("containerul Postgres nu a devenit accesibil la timp")
        rc = run_migrations(dry_run=False, dsn=dsn)
        assert rc == 0, "migrațiile au eșuat pe containerul de test"
        yield dsn
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)


def _verdict(action) -> dict:
    return {"severity": "high", "confidence": 0.95, "is_false_positive": False,
            "prompt_injection_detected": False,
            "summary_ro": "Atac brute-force " + chr(0x219) + "i " + chr(0x21b) + "int" + A_BREVE,
            "recommended_action": action}


async def _seed(conn, histogram: dict[str, int], *, extra: bool = True) -> None:
    """Un incident per verdict, cu `updated_at` în trecut: declanșatorul e doar
    BEFORE UPDATE, deci INSERT-ul își păstrează valoarea."""
    await conn.execute("DELETE FROM incidents")
    n = 0
    rows = []
    for value, count in histogram.items():
        for _ in range(count):
            n += 1
            rows.append((f"fp-{n}", json.dumps(_verdict(value))))
    if extra:
        # Rânduri pe care scriptul n-are voie să le atingă, de patru feluri.
        for payload in (None, json.dumps({"severity": "low"}),
                        json.dumps({"recommended_action": None}),
                        json.dumps({"recommended_action": ["patch"]}),
                        json.dumps(_verdict("bl")), json.dumps(_verdict("sparge tot"))):
            n += 1
            rows.append((f"fp-{n}", payload))
    await conn.executemany(
        "INSERT INTO incidents (fingerprint, severity, title, ai_verdict, updated_at) "
        "VALUES ($1, 'high', 't', $2::jsonb, now() - interval '3 days')", rows)


async def _snapshot(conn) -> dict[int, tuple]:
    return {r["id"]: (r["ai_verdict"], r["updated_at"]) for r in await conn.fetch(
        "SELECT id, ai_verdict::text AS ai_verdict, updated_at FROM incidents")}


def _run(coro):
    return asyncio.run(coro)


# --- granița de decodare -----------------------------------------------------------
def test_storage_returns_exactly_what_it_was_given(pg_dsn):
    """Un `ă` adevărat iese `ă` adevărat din jsonb, iar un backslash literal iese
    backslash literal. Stocarea nu produce și nu repară secvența de escape.

    Asta mută cauza: dacă `set_ai_verdict` n-o poate crea, cele 415 de rânduri
    stricate au sosit deja stricate în procesul nostru. Și pune alături sumarul,
    care în aceleași rânduri iese cu diacritice adevărate.
    """
    async def go():
        db = Database(cfg=Config(), dsn=pg_dsn)
        await db.connect()
        try:
            await db.execute("DELETE FROM incidents")
            iid = await db.fetchval(
                "INSERT INTO incidents (fingerprint, severity, title) "
                "VALUES ('fp-rt', 'high', 't') RETURNING id")
            real = _verdict("bloche" + "az" + A_BREVE)
            await inc_repo.set_ai_verdict(db, iid, ai_severity="high", verdict=real, confidence=0.9)
            row = await db.fetchrow(
                "SELECT ai_verdict->>'recommended_action' a, ai_verdict->>'summary_ro' s "
                "FROM incidents WHERE id=$1", iid)
            assert row["a"] == "bloche" + "az" + A_BREVE
            assert row["s"] == real["summary_ro"]
            literal = _verdict("blocheaz" + ESC_A)
            await inc_repo.set_ai_verdict(db, iid, ai_severity="high", verdict=literal, confidence=0.9)
            row = await db.fetchrow(
                "SELECT ai_verdict->>'recommended_action' a, ai_verdict->>'summary_ro' s "
                "FROM incidents WHERE id=$1", iid)
            assert row["a"] == "blocheaz" + ESC_A and BS in row["a"]
            assert BS not in row["s"], "sumarul a ieșit cu backslash: stocarea strică tot, nu doar enum-ul"
        finally:
            await db.close()
    _run(go())


def test_a_literal_escape_answer_is_stored_as_the_word_with_its_raw_beside_it(pg_dsn):
    """De la răspunsul modelului la rândul din bază: un răspuns cu backslash-u
    literal intră ca `blochează`, cu cheia soră păstrând ce a sosit.

    Fără asta, plasa «funcționează» în memorie și nimeni nu verifică ce ajunge
    în `ai_verdict`, adică exact ce citesc panoul și agregatorul.
    """
    async def go():
        db = Database(cfg=Config(), dsn=pg_dsn)
        await db.connect()
        try:
            await db.execute("DELETE FROM incidents")
            iid = await db.fetchval(
                "INSERT INTO incidents (fingerprint, severity, title) "
                "VALUES ('fp-e2e', 'high', 't') RETURNING id")
            v = triage._clean({"severity": "high", "confidence": 0.9, "summary_ro": "x",
                               "recommended_action": "blocheaz" + ESC_A})
            await inc_repo.set_ai_verdict(db, iid, ai_severity="high", verdict=v, confidence=0.9)
            stored = json.loads(await db.fetchval(
                "SELECT ai_verdict::text FROM incidents WHERE id=$1", iid))
            assert stored["recommended_action"] == "bloche" + "az" + A_BREVE
            assert stored["recommended_action_raw"] == "blocheaz" + BS + BS + "u0103"
        finally:
            await db.close()
    _run(go())


# --- backfill ------------------------------------------------------------------------
def _patched_connect(monkeypatch, dsn):
    monkeypatch.setattr(backfill, "database_dsn", lambda cfg: dsn)


def test_the_dry_run_writes_nothing_and_the_server_would_refuse_if_it_tried(pg_dsn, monkeypatch):
    """Rularea uscată pe baza cu forma producției: raportul numără, baza rămâne
    identică la octet (inclusiv `updated_at`), iar sesiunea refuză orice
    scriere.

    «N-a scris nimic» fără al doilea fapt ar putea fi doar un script care s-a
    abținut — și care ar scrie la prima modificare care mută un UPDATE.
    """
    _patched_connect(monkeypatch, pg_dsn)

    async def go():
        seed = await asyncpg.connect(pg_dsn)
        await _seed(seed, PRODUCTIE)
        before = await _snapshot(seed)
        out = io.StringIO()
        conn = await backfill._connect(Config(), read_only=True)
        try:
            result = await backfill.backfill(conn, apply=False, out=out)
            with pytest.raises(asyncpg.exceptions.ReadOnlySQLTransactionError):
                await conn.execute("UPDATE incidents SET title = 'x'")
        finally:
            await conn.close()
        after = await _snapshot(seed)
        await seed.close()
        return before, after, result, out.getvalue()

    before, after, result, report = _run(go())
    assert before == after, "modul uscat a schimbat baza"
    # Numerele sunt ale formei producției: 415 escape + 105 prefix + 82 fără diacritice.
    assert result["planned"] == 602
    assert result["changed"] == 0
    # Cele două rânduri-capcană cu ȘIR neplasabil («bl», «sparge tot») rămân; un
    # `recommended_action` listă sau null NU e candidat, se numără la «fără șir».
    assert result["left"] == 2
    assert "fără `recommended_action` șir    : 3" in report
    assert "de schimbat                      : 602" in report
    assert "escape 415" in report and "prefix 105" in report and "folded 82" in report
    assert "[uscat]" in report


def test_apply_places_every_deterministic_row_and_touches_nothing_else(pg_dsn, monkeypatch):
    """`--apply`: 602 de rânduri capătă cuvântul din enum, cheia soră păstrează
    valoarea veche, restul verdictului rămâne neatins; cele 169 `unknown`, cele
    20 deja bune și cele șase rânduri-capcană rămân IDENTICE la octet, cu
    `updated_at` neschimbat.

    Eșecul din spate: un `UPDATE` cu un `WHERE` lărgit ar muta `updated_at` pe
    mii de incidente care n-au nimic de reparat și ar retrimite la agregator
    istoria întreagă; unul cu `||` greșit ar șterge `summary_ro`.
    """
    _patched_connect(monkeypatch, pg_dsn)

    async def go():
        seed = await asyncpg.connect(pg_dsn)
        await _seed(seed, PRODUCTIE)
        before = await _snapshot(seed)
        conn = await backfill._connect(Config(), read_only=False)
        try:
            result = await backfill.backfill(conn, apply=True, out=io.StringIO())
        finally:
            await conn.close()
        after = await _snapshot(seed)
        await seed.close()
        return before, after, result

    before, after, result = _run(go())
    assert result["changed"] == 602 and result["raced"] == 0
    assert result["remaining"] == 0, "după scriere mai există rânduri plasabile"

    moved = untouched = 0
    for iid, (old_text, old_ts) in before.items():
        new_text, new_ts = after[iid]
        old = json.loads(old_text) if old_text else None
        d = backfill.decide(old["recommended_action"]) if (
            old and isinstance(old.get("recommended_action"), str)) else None
        if d is None:
            assert (new_text, new_ts) == (old_text, old_ts), f"rândul {iid} a fost atins: {old}"
            untouched += 1
            continue
        new = json.loads(new_text)
        assert new["recommended_action"] == d.new
        assert new["recommended_action_raw"] == triage._render_raw(old["recommended_action"])
        # Tot restul verdictului e identic.
        rest = {k: v for k, v in new.items() if k not in ("recommended_action", "recommended_action_raw")}
        assert rest == {k: v for k, v in old.items() if k != "recommended_action"}
        assert new_ts > old_ts, "declanșatorul n-a mutat updated_at: expeditorul n-ar retrimite rândul"
        moved += 1
    assert (moved, untouched) == (602, 169 + 20 + 6)


def test_a_second_apply_finds_nothing_and_writes_nothing(pg_dsn, monkeypatch):
    """Re-rulabil fără efect: a doua rulare numără zero, iar `updated_at` nu se
    mișcă pe niciun rând — altfel fiecare rulare ar retrimite istoricul."""
    _patched_connect(monkeypatch, pg_dsn)

    async def go():
        seed = await asyncpg.connect(pg_dsn)
        await _seed(seed, PRODUCTIE)
        conn = await backfill._connect(Config(), read_only=False)
        try:
            await backfill.backfill(conn, apply=True, out=io.StringIO())
            between = await _snapshot(seed)
            result = await backfill.backfill(conn, apply=True, out=io.StringIO())
        finally:
            await conn.close()
        after = await _snapshot(seed)
        await seed.close()
        return between, after, result

    between, after, result = _run(go())
    assert result["planned"] == 0 and result["changed"] == 0
    assert between == after


def test_a_row_rewritten_after_it_was_read_is_not_overwritten(pg_dsn, monkeypatch):
    """Compare-and-set: dacă un triaj nou rescrie rândul între citire și scriere,
    scriptul nu-l suprascrie și îl numără ca «schimbat între timp».

    Altfel o corectare a istoricului ar putea șterge un verdict mai nou, scris
    corect, cu o valoare dedusă din cel vechi.
    """
    _patched_connect(monkeypatch, pg_dsn)

    class _Racing:
        """Conexiune care, înaintea primului UPDATE al scriptului, rescrie un
        rând — simulând un triaj comis între cele două pasuri."""

        def __init__(self, real, victim_id):
            self._real, self._victim, self._done = real, victim_id, False

        def transaction(self):
            return self._real.transaction()

        async def fetch(self, *a, **k):
            return await self._real.fetch(*a, **k)

        async def fetchrow(self, *a, **k):
            return await self._real.fetchrow(*a, **k)

        async def execute(self, sql, *args):
            if not self._done and sql.lstrip().startswith("UPDATE"):
                self._done = True
                await self._real.execute(
                    "UPDATE incidents SET ai_verdict = ai_verdict || "
                    "jsonb_build_object('recommended_action', 'patch') WHERE id = $1",
                    self._victim)
            return await self._real.execute(sql, *args)

    async def go():
        seed = await asyncpg.connect(pg_dsn)
        await _seed(seed, {"blocheaz": 2, "investigheaz": 1}, extra=False)
        ids = [r["id"] for r in await seed.fetch(
            "SELECT id FROM incidents ORDER BY id")]
        conn = await backfill._connect(Config(), read_only=False)
        try:
            racing = _Racing(conn, ids[0])
            result = await backfill.backfill(racing, apply=True, out=io.StringIO())
        finally:
            await conn.close()
        rows = {r["id"]: json.loads(r["ai_verdict"]) for r in await seed.fetch(
            "SELECT id, ai_verdict::text AS ai_verdict FROM incidents")}
        await seed.close()
        return ids, result, rows

    ids, result, rows = _run(go())
    assert rows[ids[0]]["recommended_action"] == "patch", "verdictul mai nou a fost suprascris"
    assert "recommended_action_raw" not in rows[ids[0]]
    assert result["raced"] == 1 and result["changed"] == 2
    # Rândul pierdut în cursă rămâne «de plasat»? Nu: acum are un cuvânt valid.
    assert result["remaining"] == 0


class _Lying:
    """Conexiune al cărei `UPDATE` întoarce «UPDATE 1» fără să execute nimic."""

    def __init__(self, real):
        self._real = real

    def transaction(self):
        return self._real.transaction()

    async def fetch(self, *a, **k):
        return await self._real.fetch(*a, **k)

    async def fetchrow(self, *a, **k):
        return await self._real.fetchrow(*a, **k)

    async def execute(self, sql, *args):
        if sql.lstrip().startswith("UPDATE"):
            return "UPDATE 1"
        return await self._real.execute(sql, *args)

    async def close(self):
        await self._real.close()


def test_a_write_the_server_did_not_apply_is_reported_from_the_table_not_from_the_tag(
        pg_dsn, monkeypatch):
    """Un `UPDATE` care întoarce «UPDATE 1» dar n-a schimbat nimic nu face
    raportul să mintă: «mai sunt plasabile după scriere» se renumără din TABELĂ,
    iar codul de ieșire al scriptului e 1.

    Eșecul din spate e `augenrules --load 2>/dev/null`: un cod de retur luat drept
    dovadă. Aici ar însemna «scrise: 5» pe o bază în care nimic nu s-a mișcat.
    """
    _patched_connect(monkeypatch, pg_dsn)

    async def go():
        seed = await asyncpg.connect(pg_dsn)
        await _seed(seed, {"blocheaz": 3, "ignor": 2}, extra=False)
        real = await backfill._connect(Config(), read_only=False)
        out = io.StringIO()
        try:
            result = await backfill.backfill(_Lying(real), apply=True, out=out)
        finally:
            await real.close()

        async def lying_connect(cfg, *, read_only):
            return _Lying(await asyncpg.connect(pg_dsn))

        monkeypatch.setattr(backfill, "_connect", lying_connect)
        monkeypatch.setattr(backfill, "get_config", lambda: Config())
        rc = await backfill._main(argparse.Namespace(apply=True))
        await seed.close()
        return result, out.getvalue(), rc

    result, report, rc = _run(go())
    assert result["remaining"] == 5, "raportul a crezut eticheta, nu tabela"
    assert "NU e zero" in report
    assert rc == 1


def test_the_timeline_copies_are_measured_and_left_exactly_as_written(pg_dsn, monkeypatch):
    """`set_ai_verdict` scrie verdictul și în `incident_timeline`; backfill-ul
    corectează antetul incidentului, NU și cronologia — dar o numără.

    Eșecul din spate: pagina unui incident care zice «blochează» în antet și
    «blocheaz» + backslash-u în cronologie, fără ca raportul scriptului să fi
    pomenit vreodată că a doua copie există. Și invers: un script care ar rescrie
    cronologia ar produce o copie locală corectă și una la agregator veche —
    fluxul ei e pe `id`, un rând modificat nu mai pleacă.
    """
    _patched_connect(monkeypatch, pg_dsn)

    async def go():
        seed = await asyncpg.connect(pg_dsn)
        await _seed(seed, {"blocheaz" + ESC_A: 2, "blochează": 1}, extra=False)
        ids = [r["id"] for r in await seed.fetch("SELECT id FROM incidents ORDER BY id")]
        for iid, action in zip(ids, ("blocheaz" + ESC_A, "blocheaz" + ESC_A, "blochează")):
            await seed.execute(
                "INSERT INTO incident_timeline (incident_id, kind, actor, detail) "
                "VALUES ($1, 'ai_verdict', 'ai', $2::jsonb)", iid, json.dumps(_verdict(action)))
        before = [tuple(r) for r in await seed.fetch(
            "SELECT id, detail::text FROM incident_timeline ORDER BY id")]
        conn = await backfill._connect(Config(), read_only=False)
        out = io.StringIO()
        try:
            result = await backfill.backfill(conn, apply=True, out=out)
        finally:
            await conn.close()
        after = [tuple(r) for r in await seed.fetch(
            "SELECT id, detail::text FROM incident_timeline ORDER BY id")]
        await seed.close()
        return before, after, result, out.getvalue()

    before, after, result, report = _run(go())
    assert before == after, "backfill-ul a rescris cronologia"
    assert result["timeline_stale"] == 2
    assert "incident_timeline: 2 intrări" in report
