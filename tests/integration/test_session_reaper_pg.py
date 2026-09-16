"""Postgres real rulează instrucțiunea reaper-ului. Un dublu nu poate.

## De ce există fișierul ăsta pe lângă `tests/unit/test_session_reaper.py`

Dublul de acolo recunoaște clauzele reaper-ului după bucăți de text și apoi
aplică ACELEAȘI reguli, scrise a doua oară în Python. Asta prinde o clauză
ȘTEARSĂ. Nu prinde una LĂRGITĂ: `candidat.ultima < now() - make_interval(secs
=> $2)` schimbat în `<=`, `NOT (... = ANY($1))` devenit `... <> ALL($1)` cu un
NULL în listă, `closed_at IS NULL` mutat în CTE unde nu mai filtrează nimic —
în toate, textul pe care dublul îl caută e încă acolo, iar el răspunde din
propria reimplementare. Aceeași constatare a fost făcută pe 8 septembrie 2026
despre `FakeDB` din `test_web_login_lockout.py`, și tot atunci s-a scris
primul fișier de felul ăsta.

Ce apără concret, aici: reaper-ul ÎNCHIDE sesiuni și, prin asta, trimite
rezumate. O clauză lărgită într-o direcție închide o sesiune în care omul e
încă la tastatură — mesajul „🔓 Sesiune încheiată" despre cineva care tocmai
scrie o comandă. În cealaltă, nu închide nimic, iar rezumatul rămâne la
douăsprezece ore, adică la niciodată.

În plus, e singurul loc în care se află dacă instrucțiunea se COMPILEAZĂ:
`make_interval(secs => $N)` cu un parametru legat, un `NOT (... = ANY($1::
text[]))` cu listă goală și un `UPDATE ... FROM` peste un CTE nu sunt lucruri
despre care un dublu poate spune nimic. Trei defecte de tipul ăsta au trecut
de suita verde într-o singură zi — vezi `tests/security/test_sql_parameters_are_typed.py`.

OPȚIONAL: rulează când `SENTINEL_TEST_PG_DSN` arată spre un Postgres accesibil,
sau când `docker` e în PATH și daemonul răspunde — caz în care își pornește
singur un `postgres:16-alpine` de unică folosință, aplică toate migrațiile prin
rulorul adevărat și îl șterge la final. Altfel se sare, cu motivul spus: o
verificare care tace și raportează succes e chiar tiparul din CLAUDE.md.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone

import pytest

asyncpg = pytest.importorskip("asyncpg", reason="asyncpg not installed")

from sentinel.collectors.audit_sessions import LiveAuditSessions  # noqa: E402
from sentinel.config import Config  # noqa: E402
from sentinel.db.engine import Database  # noqa: E402
from sentinel.db.migrate import run_migrations  # noqa: E402
from sentinel.db.repo import logins  # noqa: E402

#: Vechimea instantaneului din `/proc`, în secunde, pentru testele care nu ea
#: o măsoară: „m-am uitat la gazdă chiar acum".
PROASPAT = 0.0


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
            "nici SENTINEL_TEST_PG_DSN, nici un daemon docker accesibil — "
            "instrucțiunea reaper-ului NU a fost rulată de un Postgres real; "
            "vezi docstring-ul modulului")

    port = _free_tcp_port()
    name = f"sentinel-test-reaper-pg-{port}"
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


async def _sesiune(conn, cheie: str, *, deschisa_acum_min: float,
                   ultima_comanda_min: float | None) -> int:
    """O sesiune interactivă, cu sau fără o comandă la momentul cerut.

    Momentele se scriu ca decalaj față de `now()` AL BAZEI, nu față de ceasul
    procesului de test: instrucțiunea se compară tot cu `now()`, iar o diferență
    de câteva secunde între cele două ceasuri ar face testul să treacă sau să
    pice după cum e vremea.
    """
    sid = await conn.fetchval(
        """
        INSERT INTO login_sessions
            (session_key, username, terminal, interactive, opened_at, alerted_at)
        VALUES ($1, 'operator', 'pts0', true,
                now() - make_interval(secs => $2::double precision), now())
        RETURNING id
        """,
        cheie, deschisa_acum_min * 60.0)
    if ultima_comanda_min is not None:
        await conn.execute(
            """
            INSERT INTO session_commands (session_id, session_key, ts, username, exe, argv)
            VALUES ($1, $2, now() - make_interval(secs => $3::double precision),
                    'operator', '/usr/bin/ls', 'ls -la')
            """,
            sid, cheie, ultima_comanda_min * 60.0)
    return sid


def test_the_real_statement_closes_only_what_is_really_gone(pg_dsn):
    """Patru sesiuni, un singur rând închis — și chiar cel care trebuie.

    Fiecare dintre celelalte trei e o pană dacă instrucțiunea se lărgește:
    sesiunea VIE ar produce «Sesiune încheiată» despre cineva care tastează,
    cea abia tăcută ar fi închisă de cursa dintre instantaneu și instrucțiune,
    iar cea veche de patru zile ar fi prima picătură dintr-un val de rezumate
    la prima rulare pe o gazdă cu restanță.
    """
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await conn.execute("DELETE FROM session_commands")
                await conn.execute("DELETE FROM login_sessions")
                vie = await _sesiune(conn, "2472", deschisa_acum_min=60,
                                     ultima_comanda_min=30)
                moarta = await _sesiune(conn, "2604", deschisa_acum_min=60,
                                        ultima_comanda_min=11)
                proaspata = await _sesiune(conn, "2630", deschisa_acum_min=1,
                                           ultima_comanda_min=0.5)
                veche = await _sesiune(conn, "163", deschisa_acum_min=60 * 96,
                                       ultima_comanda_min=60 * 95)

            vii = LiveAuditSessions(frozenset({"2472"}), True, "", 187)
            assert await logins.reap_dead_sessions(db, vii, PROASPAT) == 1

            async with db.pool.acquire() as conn:
                randuri = {r["id"]: r for r in await conn.fetch(
                    "SELECT id, closed_at, closed_inferred FROM login_sessions")}

            assert randuri[vie]["closed_at"] is None, (
                "o sesiune cu procese vii pe gazdă a fost declarată încheiată")
            assert randuri[proaspata]["closed_at"] is None, (
                "o sesiune tăcută de treizeci de secunde a fost închisă — "
                "răgazul nu mai apără cursa dintre citirea din /proc și UPDATE")
            assert randuri[veche]["closed_at"] is None, (
                "un rând vechi de patru zile a fost închis aici în loc să "
                "rămână al măturătoarei — prima rulare devine un val de mesaje")
            assert randuri[moarta]["closed_at"] is not None, (
                "sesiunea moartă a rămas deschisă; rezumatul ei nu pleacă "
                "decât peste douăsprezece ore")
            assert randuri[moarta]["closed_inferred"] is True
        finally:
            await db.close()

    asyncio.run(_run())


def test_the_real_statement_stamps_the_last_command(pg_dsn):
    """Momentul pus e ultima activitate, nu clipa observației.

    Diferența ajunge direct în «Durată» pe telefonul operatorului: cu `now()`,
    o sesiune care a tăcut la 09:45 și a fost observată la 11:30 ar fi raportată
    ca o oră și trei sferturi de lucru care n-au existat.
    """
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await conn.execute("DELETE FROM session_commands")
                await conn.execute("DELETE FROM login_sessions")
                cu_comenzi = await _sesiune(conn, "2604", deschisa_acum_min=180,
                                            ultima_comanda_min=45)
                fara_comenzi = await _sesiune(conn, "2572", deschisa_acum_min=90,
                                              ultima_comanda_min=None)
                asteptat = {
                    cu_comenzi: await conn.fetchval(
                        "SELECT max(ts) FROM session_commands WHERE session_id = $1",
                        cu_comenzi),
                    fara_comenzi: await conn.fetchval(
                        "SELECT opened_at FROM login_sessions WHERE id = $1",
                        fara_comenzi),
                }

            assert await logins.reap_dead_sessions(
                db, LiveAuditSessions(frozenset(), True, "", 187), PROASPAT) == 2

            async with db.pool.acquire() as conn:
                for sid, moment in asteptat.items():
                    inchis = await conn.fetchval(
                        "SELECT closed_at FROM login_sessions WHERE id = $1", sid)
                    assert inchis == moment, (
                        "momentul închiderii nu e ultima activitate cunoscută; "
                        "durata din rezumat descrie altceva decât s-a întâmplat")
        finally:
            await db.close()

    asyncio.run(_run())


def test_a_blind_scan_does_not_reach_the_database(pg_dsn):
    """`trusted = False` e starea de sub `ProtectProc=invisible`, unde scanul
    vede zero sesiuni. Dacă ar ajunge la instrucțiune, lista goală ar închide
    fiecare sesiune deschisă a gazdei și ar trimite un rezumat pentru fiecare."""
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await conn.execute("DELETE FROM session_commands")
                await conn.execute("DELETE FROM login_sessions")
                sid = await _sesiune(conn, "2604", deschisa_acum_min=60,
                                     ultima_comanda_min=30)

            orb = LiveAuditSessions(frozenset(), False, "hidepid", 0)
            assert await logins.reap_dead_sessions(db, orb, PROASPAT) == 0

            async with db.pool.acquire() as conn:
                assert await conn.fetchval(
                    "SELECT closed_at FROM login_sessions WHERE id = $1", sid) is None
        finally:
            await db.close()

    asyncio.run(_run())


def test_an_empty_live_list_is_accepted_by_postgres(pg_dsn):
    """`= ANY($1::text[])` cu listă goală: forma pe care o ia o gazdă pe care
    chiar nu e nimeni logat. Dacă Postgres ar refuza-o, reaper-ul ar eșua exact
    în cazul în care are cel mai mult de lucru, iar eroarea ar apărea o dată la
    câteva zile într-un jurnal."""
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await conn.execute("DELETE FROM session_commands")
                await conn.execute("DELETE FROM login_sessions")
                sid = await _sesiune(conn, "2604", deschisa_acum_min=60,
                                     ultima_comanda_min=30)

            assert await logins.reap_dead_sessions(
                db, LiveAuditSessions(frozenset(), True, "", 187), PROASPAT) == 1

            async with db.pool.acquire() as conn:
                assert await conn.fetchval(
                    "SELECT closed_at FROM login_sessions WHERE id = $1",
                    sid) is not None
        finally:
            await db.close()

    asyncio.run(_run())


def test_the_two_windows_leave_no_gap(pg_dsn):
    """Reaper-ul sub `STALE_SESSION_H`, măturătoarea peste. Dacă marginile n-ar
    fi lipite, rândurile din fereastra dintre ele n-ar fi închise de nimeni, iar
    sesiunea ar rămâne deschisă pentru totdeauna."""
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await conn.execute("DELETE FROM session_commands")
                await conn.execute("DELETE FROM login_sessions")
                sub = await _sesiune(
                    conn, "2604", deschisa_acum_min=60 * logins.STALE_SESSION_H - 5,
                    ultima_comanda_min=60 * logins.STALE_SESSION_H - 5)
                peste = await _sesiune(
                    conn, "2572", deschisa_acum_min=60 * logins.STALE_SESSION_H + 5,
                    ultima_comanda_min=60 * logins.STALE_SESSION_H + 5)

            assert await logins.reap_dead_sessions(
                db, LiveAuditSessions(frozenset(), True, "", 187), PROASPAT) == 1
            assert await logins.close_stale_sessions(db) == 1

            async with db.pool.acquire() as conn:
                for sid in (sub, peste):
                    assert await conn.fetchval(
                        "SELECT closed_at FROM login_sessions WHERE id = $1",
                        sid) is not None, (
                        "un rând a rămas deschis: cele două ferestre nu se ating")
        finally:
            await db.close()

    asyncio.run(_run())


def test_the_real_statement_measures_both_edges_from_the_observation(pg_dsn):
    """Un instantaneu ținut în mână nu are voie să închidă o sesiune deschisă
    DUPĂ el.

    Reaper-ul păstrează scanul din `/proc` până a citit coada de audit dincolo
    de clipa în care l-a luat — o fracțiune de secundă pe o gazdă liniștită,
    minute pe una unde ingestia recuperează un vârf de înregistrări. Cine se
    loghează între timp lipsește dintr-un instantaneu luat înainte să existe.

    Dacă răgazul s-ar măsura din `now()`, rândul lui ar fi închis la două
    minute după logare, cu tot cu «🔓 Sesiune încheiată» pe telefon despre
    cineva care tocmai s-a conectat. Măsurat din clipa observației, nu poate fi
    atins — iar asta o poate spune numai Postgres, fiindcă e aritmetică de
    interval pe ceasul LUI.
    """
    db = Database(cfg=Config(), dsn=pg_dsn)
    vechime = 600.0

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await conn.execute("DELETE FROM session_commands")
                await conn.execute("DELETE FROM login_sessions")
                # Scanul e de acum zece minute. Sesiunea asta s-a deschis acum
                # nouă, adică după el, și n-a mai rulat nimic de atunci.
                dupa_scan = await _sesiune(conn, "2630", deschisa_acum_min=9,
                                           ultima_comanda_min=None)
                # Asta tăcea deja de douăzeci de minute când s-a luat scanul.
                inainte = await _sesiune(conn, "2604", deschisa_acum_min=60,
                                         ultima_comanda_min=30)

            vii = LiveAuditSessions(frozenset(), True, "", 187)
            assert await logins.reap_dead_sessions(db, vii, vechime) == 1

            async with db.pool.acquire() as conn:
                randuri = {r["id"]: r for r in await conn.fetch(
                    "SELECT id, closed_at FROM login_sessions")}

            assert randuri[dupa_scan]["closed_at"] is None, (
                "o sesiune deschisă după instantaneu a fost închisă de el: "
                "răgazul nu se mai măsoară din clipa în care s-a citit gazda, "
                "iar operatorul primește rezumatul cuiva care tocmai s-a logat")
            assert randuri[inainte]["closed_at"] is not None, (
                "un instantaneu vechi n-a mai închis nimic; reaper-ul se "
                "oprește exact când ingestia are de recuperat")
        finally:
            await db.close()

    asyncio.run(_run())


def test_a_negative_observation_age_is_clamped_by_the_statement(pg_dsn):
    """Un ceas sărit înapoi poate da o vechime negativă. Dusă neatinsă în
    `make_interval`, ar muta AMBELE margini în viitor: o sesiune tăcută de
    zece secunde ar fi socotită tăcută de două minute și s-ar închide sub omul
    care tastează. Tăierea la zero e în funcția care scrie instrucțiunea, deci
    aici se verifică pe motorul care o execută."""
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await conn.execute("DELETE FROM session_commands")
                await conn.execute("DELETE FROM login_sessions")
                proaspata = await _sesiune(conn, "2630", deschisa_acum_min=1,
                                           ultima_comanda_min=0.5)

            vii = LiveAuditSessions(frozenset(), True, "", 187)
            assert await logins.reap_dead_sessions(db, vii, -3600.0) == 0

            async with db.pool.acquire() as conn:
                assert await conn.fetchval(
                    "SELECT closed_at FROM login_sessions WHERE id = $1",
                    proaspata) is None
        finally:
            await db.close()

    asyncio.run(_run())


def test_the_reaper_state_row_is_accepted_by_postgres(pg_dsn):
    """Urma pe care o citește `/selfcheck` chiar se poate scrie și reciti.

    Un dublu de test primește instrucțiunea ca text și valorile ca obiecte
    Python, deci n-ar observa niciodată că baza refuză perechea — exact felul
    de defect care a doborât ingestia de trei ori într-o zi pe 24 august 2026
    (vezi `tests/security/test_sql_parameters_are_typed.py`). Aici: un
    `timestamptz` legat ca parametru într-un `INSERT … ON CONFLICT`, și un
    `NULL` pe aceeași coloană pentru starea „n-am măsurat încă niciun
    filigran".

    Dacă ar cădea, ar cădea tăcut: `record_reaper_state` își înghite eroarea
    dinadins, ca raportarea să nu poată opri închiderea sesiunilor. Adică
    verificarea ar spune „reaper-ul n-a raportat niciodată" pe o gazdă unde
    reaper-ul lucrează perfect, la nesfârșit.
    """
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await conn.execute(
                    "DELETE FROM collector_cursors WHERE name = $1",
                    logins.REAPER_MARKER)

            assert await logins.read_reaper_state(db) is None, (
                "urma raportează o stare pe o bază în care n-a scris nimeni")

            filigran = datetime(2026, 9, 15, 11, 30, tzinfo=timezone.utc)
            await logins.record_reaper_state(db, logins.REAPER_WAITING, filigran)
            urma = await logins.read_reaper_state(db)
            assert urma["cursor"] == logins.REAPER_WAITING
            assert urma["cursor_at"] == filigran, (
                "filigranul nu s-a întors din bază; fără el nu se poate spune "
                "CÂT de în urmă e ingestia, doar că e")
            assert urma["updated_at"] is not None

            # A doua scriere trece prin `ON CONFLICT`, nu prin `INSERT`: e
            # calea pe care o ia daemonul de la a doua trecere încolo, adică
            # toate în afară de prima.
            await logins.record_reaper_state(db, logins.REAPER_WORKING, None)
            urma = await logins.read_reaper_state(db)
            assert urma["cursor"] == logins.REAPER_WORKING
            assert urma["cursor_at"] is None, (
                "„n-am măsurat niciun filigran” s-a scris ca altceva decât NULL")
        finally:
            await db.close()

    asyncio.run(_run())
