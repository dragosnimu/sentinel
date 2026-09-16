"""Real Postgres runs `_attach_orphans`'s guard and window. A dublu nu poate.

## De ce fișierul ăsta, și nu `tests/unit/test_login_projection.py`

Dublul de-acolo (`_DB.execute`, ramura `"UPDATE session_commands c SET
session_id"`) recunoaște instrucțiunea după bucăți de text — `"c.session_id
IS NULL"`, `"c.ts >= s.opened_at"`, `"s.closed_at IS NULL OR c.ts <=
s.closed_at"` — și apoi aplică ACELEAȘI reguli, scrise a doua oară în Python
(vezi funcția `execute`, ramura respectivă). Măsurat de verificator, runda 2,
16 septembrie 2026: cu textul PĂSTRAT dar garda golită — `(c.session_id IS
NULL OR TRUE)` — sau fereastra golită — `OR TRUE`, sau lărgită la o oră —,
suita dublului rămâne **59 passed** de fiecare dată, în timp ce PostgreSQL 16
adevărat atașează 3 comenzi în loc de 1, sau ia un orfan vechi de 90 de zile,
sau amestecă un boot cu următorul. Dublul nu poate vedea nimic din asta: el nu
execută SQL, el îl citește ca text și decide singur ce înseamnă.

Ce apără concret, aici: `_attach_orphans` leagă de o sesiune comenzile care au
sosit înaintea ei — vezi docstring-ul ei din `sentinel/db/repo/logins.py`
pentru numărătoarea măsurată pe gazda n8n (2434 comenzi orfane, 676 din 1037
intrau în fereastra veche de un minut, restul de 331 aparțineau unei singure
sesiuni fabricate cu comenzi la 64–153 de secunde înainte). O gardă lărgită
greșit atașează comanda altcuiva în cronologia cuiva; una îngustată greșit
pierde din nou exact ce a reparat lărgirea.

OPȚIONAL: rulează când `SENTINEL_TEST_PG_DSN` arată spre un Postgres accesibil,
sau când `docker` e în PATH și daemonul răspunde — caz în care își pornește
singur un `postgres:16-alpine` de unică folosință, aplică toate migrațiile prin
rulorul adevărat și îl șterge la final. Altfel se sare, cu motivul spus.

Falsifică: `(c.session_id IS NULL OR TRUE)`, `OR TRUE` pe fereastră,
`interval '1 minute'` devenit `interval '1 hour'`, scoaterea apelurilor
`_attach_orphans` din `project()`, și — runda 3, 16 septembrie 2026 —
reintroducerea marginii lărgite (`COALESCE(max(prev.closed_at), …)` în locul
ferestrei fixe) — fiecare trebuie să pice cu `pass > 0`.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import time
from datetime import datetime, timedelta, timezone

import pytest

asyncpg = pytest.importorskip("asyncpg", reason="asyncpg not installed")

from sentinel.config import Config  # noqa: E402
from sentinel.db.engine import Database  # noqa: E402
from sentinel.db.migrate import run_migrations  # noqa: E402
from sentinel.db.repo import logins  # noqa: E402
from sentinel.model.event import Event  # noqa: E402

NOW = datetime(2026, 9, 16, 9, 0, tzinfo=timezone.utc)


def _login(key: str, ts: datetime, user: str = "dragos") -> Event:
    return Event(ts=ts, source="auditd", action="login", username=user,
                 src_ip="198.51.100.7",
                 raw={"record_type": "USER_LOGIN", "ses": key, "res": "success",
                      "terminal": "ssh", "auid": "1000"})


def _logout(key: str, ts: datetime, user: str = "dragos") -> Event:
    return Event(ts=ts, source="auditd", action="logout", username=user,
                 raw={"record_type": "USER_END", "ses": key, "terminal": "ssh"})


def _command(key: str, ts: datetime, argv: str, user: str = "dragos") -> Event:
    return Event(ts=ts, source="auditd", action="command", username=user,
                 raw={"record_type": "SYSCALL", "ses": key, "argv": argv,
                      "exe": "/usr/bin/ls", "ppid": "100", "success": "yes",
                      "tty": "(none)"})


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
    """Un Postgres migrat complet, sau o sărire explicită.

    Copiat din `tests/integration/test_session_reaper_pg.py`, dinadins: fiecare
    fișier de felul ăsta e autonom — vezi și `test_login_attempts_sql_pg.py` —,
    ca sărirea unuia să nu poată tăcea toate celelalte printr-un fixture comun
    rupt.
    """
    env_dsn = os.environ.get("SENTINEL_TEST_PG_DSN")
    if env_dsn:
        rc = run_migrations(dry_run=False, dsn=env_dsn)
        if rc != 0:
            pytest.skip(f"SENTINEL_TEST_PG_DSN dat, dar migrațiile au eșuat (rc={rc})")
        yield env_dsn
        return

    if not _docker_daemon_reachable():
        pytest.skip(
            "nici SENTINEL_TEST_PG_DSN, nici un daemon docker accesibil — "
            "fereastra lui _attach_orphans NU a fost rulată de un Postgres real; "
            "vezi docstring-ul modulului")

    port = _free_tcp_port()
    name = f"sentinel-test-orphan-attach-pg-{port}"
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


async def _curat(conn) -> None:
    await conn.execute("DELETE FROM session_commands")
    await conn.execute("DELETE FROM login_sessions")


async def _session_id_of(conn, argv: str) -> int | None:
    return await conn.fetchval(
        "SELECT session_id FROM session_commands WHERE argv = $1", argv)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Comportamentul de bază — vezi tabelul din stopper-ul rundei 2
# ---------------------------------------------------------------------------
def test_an_orphan_before_a_fabricated_close_is_attached(pg_dsn):
    """O comandă sosită înaintea unui `USER_END` fără `USER_LOGIN` corespunzător.

    Comanda se scrie orfană (`session_id NULL`) fiindcă nicio sesiune n-o
    acoperă încă. Când `USER_END` sosește, `close_session` fabrică rândul și
    `_attach_orphans` trebuie s-o găsească — altfel comanda rămâne orfană
    pentru totdeauna: nimic altceva n-o mai caută.
    """
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await _curat(conn)

            await logins.project(db, [_command("500", NOW, "whoami-500")])
            async with db.pool.acquire() as conn:
                assert await _session_id_of(conn, "whoami-500") is None

            await logins.project(db, [_logout("500", NOW + timedelta(seconds=5))])

            async with db.pool.acquire() as conn:
                sid = await _session_id_of(conn, "whoami-500")
                assert sid is not None, "orfana n-a fost legată la fabricarea sesiunii"
                assert await conn.fetchval(
                    "SELECT command_count FROM login_sessions WHERE id = $1", sid) == 1
        finally:
            await db.close()

    run(_run())


def test_three_closes_in_the_same_second_attach_the_orphan_only_once(pg_dsn):
    """Măsurat pe gazdă: sshd trimite `USER_LOGOUT` ȘI `USER_END` în aceeași
    secundă, iar `sudo`/`su` mai adaugă un strat — până la trei semnale pentru o
    singură ieșire.

    Garda `c.session_id IS NULL` e ce ține `orphans_attached` la 1: fără ea, al
    doilea și al treilea apel re-numără ACEEAȘI comandă, iar jurnalul ar spune
    «am legat 3 orfane» despre un singur rând scris o singură dată.
    """
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await _curat(conn)

            await logins.project(db, [_command("2604", NOW, "id-2604")])
            counts = await logins.project(db, [
                _logout("2604", NOW + timedelta(seconds=10)),
                _logout("2604", NOW + timedelta(seconds=10)),
                _logout("2604", NOW + timedelta(seconds=10)),
            ])

            async with db.pool.acquire() as conn:
                randuri = await conn.fetch(
                    "SELECT id FROM login_sessions WHERE session_key = '2604'")
                sid = await _session_id_of(conn, "id-2604")
                cc = await conn.fetchval(
                    "SELECT command_count FROM login_sessions WHERE id = $1", sid)

            assert len(randuri) == 1, "trei închideri au fabricat mai mult de-o sesiune"
            assert counts["orphans_attached"] == 1, (
                f"{counts['orphans_attached']} legări pentru o singură comandă — "
                "garda IS NULL nu mai oprește re-numărarea")
            assert cc == 1
        finally:
            await db.close()

    run(_run())


def test_a_ninety_day_old_orphan_is_not_claimed(pg_dsn):
    """O comandă de acum trei luni, cu aceeași cheie, nu are voie să intre în
    cronologia sesiunii de azi — cheia se renumerotează la fiecare repornire.

    Fereastra e fixă, un minut în jurul deschiderii/închiderii sesiunii — nicio
    lărgire spre trecut nu are voie s-o depășească.
    """
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await _curat(conn)

            veche = NOW - timedelta(days=90)
            await logins.project(db, [_command("432", veche, "cat-432-old")])
            await logins.project(db, [_login("432", NOW),
                                      _logout("432", NOW + timedelta(minutes=5))])

            async with db.pool.acquire() as conn:
                assert await _session_id_of(conn, "cat-432-old") is None, (
                    "o comandă de acum trei luni a fost lipită de sesiunea de azi")
        finally:
            await db.close()

    run(_run())


def test_the_fabricated_row_margin_is_exact(pg_dsn):
    """Fereastra de bază, fixă, un minut în jurul închiderii fabricate.

    Patru comenzi, la -5min, -90s, -59s și -1s față de închidere: primele două
    trebuie să rămână orfane, ultimele două să se atașeze. A cincea, la +61s
    DUPĂ închidere, sosește într-un lot separat — sesiunea e deja închisă, deci
    nimic n-o mai caută vreodată, și trebuie să rămână orfană.
    """
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await _curat(conn)

            inchidere = NOW
            comenzi = [
                ("m5", inchidere - timedelta(minutes=5)),
                ("s90", inchidere - timedelta(seconds=90)),
                ("s59", inchidere - timedelta(seconds=59)),
                ("s1", inchidere - timedelta(seconds=1)),
            ]
            await logins.project(
                db, [_command("777", ts, f"cmd-{argv}") for argv, ts in comenzi])
            await logins.project(db, [_logout("777", inchidere)])

            async with db.pool.acquire() as conn:
                legate = {
                    argv: (await _session_id_of(conn, f"cmd-{argv}")) is not None
                    for argv, _ in comenzi
                }
            assert legate == {"m5": False, "s90": False, "s59": True, "s1": True}, legate

            await logins.project(
                db, [_command("777", inchidere + timedelta(seconds=61), "cmd-p61")])
            async with db.pool.acquire() as conn:
                assert await _session_id_of(conn, "cmd-p61") is None, (
                    "o comandă de la 61s DUPĂ o sesiune deja închisă a fost legată — "
                    "nimic n-ar mai fi trebuit s-o mai caute vreodată")
        finally:
            await db.close()

    run(_run())


def test_login_then_command_and_logout_in_one_batch(pg_dsn):
    """Firul de la capăt la capăt: deschidere, comandă, închidere — TOATE în
    ACELAȘI lot, prin `project()` adevărat peste o bază adevărată.

    Verifică nu doar `_attach_orphans`, ci și `_refresh_counters` peste rânduri
    scrise chiar de PostgreSQL, nu simulate.
    """
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await _curat(conn)

            counts = await logins.project(db, [
                _login("2630", NOW),
                _command("2630", NOW + timedelta(seconds=1), "uptime-2630"),
                _logout("2630", NOW + timedelta(minutes=1)),
            ])

            async with db.pool.acquire() as conn:
                sid = await _session_id_of(conn, "uptime-2630")
                cc = await conn.fetchval(
                    "SELECT command_count FROM login_sessions WHERE id = $1", sid)
            assert sid is not None
            assert cc == 1
            assert counts["sessions_opened"] == 1 and counts["sessions_closed"] == 1
        finally:
            await db.close()

    run(_run())


# ---------------------------------------------------------------------------
# Runda 3, 16 septembrie 2026: lărgirea marginii de jos până la închiderea
# sesiunii anterioare cu aceeași cheie a fost RETRASĂ. Simulată pe producție,
# `session_key` se reciclează NUMAI la reboot — deci orice sesiune anterioară
# găsită era, prin construcție, dincolo de o repornire, iar granița „lărgită"
# nu apăra nimic: întindea fereastra peste boot. 1616 comenzi orfane s-ar fi
# legat greșit, 1607 peste graniță de reboot, toate cu utilizator diferit de
# al sesiunii care le-ar fi înghițit. Testul de mai jos fixează decizia
# inversă: dacă lărgirea revine vreodată — `COALESCE(max(prev.closed_at), …)`
# adăugat înapoi în `_attach_orphans` — el trebuie să pice.
# ---------------------------------------------------------------------------
def test_a_reused_key_does_not_reach_past_its_own_window_into_the_gap(pg_dsn):
    """Aceeași cheie, folosită de două ori: o sesiune veche, închisă, și una
    nouă care o refolosește mult mai târziu — exact tiparul măsurat pe
    producție (o sesiune `sentinel-deploy` de 7 septembrie a moștenit comenzi
    de 24 august prin cheia reciclată).

    O comandă sosită la 30 de minute DUPĂ ce vechea sesiune s-a închis cade în
    afara ferestrei fixe de un minut din jurul FIECĂREIA dintre cele două
    sesiuni — deci rămâne orfană pentru totdeauna, nu se mută la cea nouă.
    Dacă cineva reintroduce granița lărgită (`COALESCE(max(prev.closed_at),
    …)` în locul ferestrei fixe), comanda asta s-ar lega de sesiunea nouă și
    testul ar pica — asta e punctul lui.

    O comandă de acum 90 de zile, cu aceeași cheie, e controlul: trebuie să
    rămână orfană indiferent de granița folosită, ca eșecul primei aserțiuni
    să nu poată fi confundat cu o fereastră general stricată.
    """
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await _curat(conn)

            veche_deschisa = NOW
            veche_inchisa = NOW + timedelta(minutes=10)
            await logins.project(db, [_login("143", veche_deschisa),
                                      _logout("143", veche_inchisa)])

            ancestral = NOW - timedelta(days=90)
            await logins.project(db, [_command("143", ancestral, "ancient-143")])

            in_gol = veche_inchisa + timedelta(minutes=30)
            await logins.project(db, [_command("143", in_gol, "midgap-143")])

            noua_deschisa = veche_inchisa + timedelta(hours=1)
            noua_inchisa = noua_deschisa + timedelta(minutes=5)
            await logins.project(db, [_login("143", noua_deschisa),
                                      _logout("143", noua_inchisa)])

            async with db.pool.acquire() as conn:
                sid_gol = await _session_id_of(conn, "midgap-143")
                sid_ancestral = await _session_id_of(conn, "ancient-143")

            assert sid_gol is None, (
                "comanda din golul dintre cele două sesiuni a fost legată de cea "
                "nouă — marginea de jos s-a lărgit din nou peste fereastra fixă "
                "de un minut, exact reparația retrasă în runda 3")
            assert sid_ancestral is None, (
                "o comandă de acum 90 de zile a fost lipită de sesiunea reciclată")
        finally:
            await db.close()

    run(_run())


def test_the_floor_never_becomes_the_earlier_sessions_close(pg_dsn):
    """Minimal, dinadins: o singură sesiune anterioară cu aceeași cheie, o
    singură comandă orfană în golul de după închiderea ei, o singură sesiune
    nouă. Nimic altceva care ar putea explica un verdict greșit.

    Ăsta e testul care fixează decizia rundei 3, separat de cel de mai sus
    (care mai poartă și controlul ancestral): dacă `_attach_orphans` capătă
    din nou o margine de jos legată de `prev.closed_at` — fie ca alternativă
    la fereastra fixă, fie ca înlocuire a ei — comanda din gol se leagă de
    sesiunea nouă și aserțiunea de mai jos pică. Verificat prin falsificare:
    reintroducerea exactă a clauzei retrase din runda 2 face testul roșu.
    """
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await _curat(conn)

            veche_inchisa = NOW + timedelta(minutes=10)
            await logins.project(db, [_login("206", NOW), _logout("206", veche_inchisa)])

            in_gol = veche_inchisa + timedelta(minutes=2)
            await logins.project(db, [_command("206", in_gol, "gap-206")])

            noua_deschisa = veche_inchisa + timedelta(hours=2)
            await logins.project(db, [_login("206", noua_deschisa),
                                      _logout("206", noua_deschisa + timedelta(minutes=1))])

            async with db.pool.acquire() as conn:
                sid = await _session_id_of(conn, "gap-206")
            assert sid is None, (
                "o comandă din golul de după închiderea sesiunii anterioare a "
                "fost legată de sesiunea nouă — floor-ul a redevenit "
                "prev.closed_at în loc de fereastra fixă de un minut")
        finally:
            await db.close()

    run(_run())
