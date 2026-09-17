"""`_rollup_lag` citește `cursor_at` și `cursor` dintr-un SINGUR `fetchrow`,
nu din două interogări separate — verifică pe un Postgres adevărat că perechea
citită corespunde cu ce a scris `_advance_rollup`.

## Ce ținea inițial fișierul ăsta, și de ce nu mai e aici

Fișierul avea și un al doilea test, care pretindea să forțeze cursa dintre
DOUĂ `fetchval` separate — varianta veche a lui `_rollup_lag`, dinainte ca el
să treacă pe un singur `fetchrow` atomic. Interceptorul (`_RacingDb`) prindea
apeluri de `fetchval`; codul reparat nu mai face niciun `fetchval` pe
`collector_cursors`, deci interceptorul nu se mai declanșa NICIODATĂ — cursa
n-avea cum să pornească, iar testul măsura pur și simplu starea NErasată
(cursorul vechi, neavansat). S-a dovedit că, pe datele semănate, starea aia
„neavansată" arăta `pending == 1` din ACELAȘI motiv pentru care ar fi arătat
`pending == 1` și cu cursa reușită și cu formula veche de vârstă: comparația
`(updated_at, bucket) > (cursor_at, cursor)` a lui Postgres e dominată de
prima jumătate, iar `updated_at`-ul rândului semănat era mai nou decât
`cursor_at`-ul vechi în ambele scenarii. Asertul `pending == 1` trecea deci
indiferent dacă cursa avea loc sau nu — un test care nu poate pica nu
falsifică nimic, e decor.

A repara testul ar cere fie interceptarea unei citiri ATOMICE la mijlocul ei
(imposibil de la nivel Python — un singur `fetchrow` e un singur du-te-vino pe
rețea, exact proprietatea pe care reparația o exploatează), fie o cursă
adevărată la nivel de conexiuni Postgres (blocaje explicite, `pg_sleep`),
disproporționată față de ce ar dovedi: că un `SELECT` unic vede un snapshot
consistent e o garanție a protocolului, nu ceva ce cade sau trece în funcție
de codul din `shipper.py`. A rămas testul de mai jos, care verifică
proprietatea utilă și REALĂ — că citirea atomică raportează corect „la zi"
pentru un rând a cărui poziție e chiar cea din urmă pereche scrisă de
`_advance_rollup`.

OPȚIONAL: rulează cu `SENTINEL_TEST_PG_DSN`, sau își pornește singur un
`postgres:16-alpine` prin docker — vezi `test_orphan_attach_pg.py` pentru
exact același tipar de fixture, copiat dinadins ca fiecare fișier să fie
autonom.
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
from sentinel.report import shipper  # noqa: E402
from sentinel.selfcheck.checks import SHIP_LAG_GRACE_MIN  # noqa: E402


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

    Copiat din `test_orphan_attach_pg.py`, dinadins — vezi docstring-ul de-acolo
    pentru de ce fiecare fișier își are propriul fixture.
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
            "nici SENTINEL_TEST_PG_DSN, nici un daemon docker accesibil — cursa "
            "pe `collector_cursors` NU a fost rulată de un Postgres real; vezi "
            "docstring-ul modulului")

    port = _free_tcp_port()
    name = f"sentinel-test-rollup-lag-torn-pg-{port}"
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


def run(coro):
    return asyncio.run(coro)


NAME = "ship:event_rollup_1h"
TABLE = "event_rollup_1h"


async def _seed(conn, *, bucket: datetime, updated_at: datetime,
                old_cursor_at: datetime, old_cursor_bucket: datetime) -> None:
    await conn.execute("DELETE FROM event_rollup_1h")
    await conn.execute("DELETE FROM collector_cursors WHERE name = ANY($1)",
                       [NAME, f"{NAME}:stall"])
    # Rândul e deja EXPEDIAT sub perechea finală (updated_at, bucket) — vezi
    # asertul de mai jos cu citirea atomică, care trebuie să-l vadă la zi.
    await conn.execute(
        """
        INSERT INTO event_rollup_1h
            (bucket, asset_id, source, action, n, uniq_src,
             bytes_in, bytes_out, p95_latency_ms, updated_at)
        VALUES ($1, 0, 'nginx', 'request', 10, 1, 0, 0, NULL, $2)
        """,
        bucket, updated_at)
    # Perechea VECHE, dinaintea avansării pe care o simulează cursa.
    await conn.execute(
        """
        INSERT INTO collector_cursors (name, cursor, cursor_at, updated_at)
        VALUES ($1, $2::timestamptz::text, $2::timestamptz, now())
        """,
        NAME, old_cursor_at)
    await conn.execute(
        "UPDATE collector_cursors SET cursor = $2::timestamptz::text WHERE name = $1",
        NAME, old_cursor_bucket)


def test_atomic_pair_after_advance_reports_at_zi(pg_dsn):
    """Sub perechea FINALĂ (scrisă atomic, ca de `_advance_rollup`), rândul deja
    expediat trebuie să arate `pending = 0` — altfel `_rollup_lag` ar ține o
    restanță fantomă chiar și când cursorul chiar a trecut de rând, iar
    `check_ship_lag` ar ține o alarmă aprinsă pe purtarea corectă a
    mecanismului.
    """
    now = datetime.now(timezone.utc)
    bucket = (now - timedelta(hours=2)).replace(minute=0, second=0, microsecond=0)
    updated_at = now - timedelta(minutes=55)

    async def _run() -> None:
        db = Database(cfg=Config(), dsn=pg_dsn)
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await _seed(conn, bucket=bucket, updated_at=updated_at,
                            old_cursor_at=now - timedelta(hours=1, minutes=58),
                            old_cursor_bucket=bucket - timedelta(hours=1))
                # Perechea finală, scrisă ATOMIC de o singură instrucțiune —
                # exact ce face `_advance_rollup`.
                await conn.execute(
                    "UPDATE collector_cursors SET cursor = $2::timestamptz::text, "
                    "cursor_at = $2::timestamptz WHERE name = $1",
                    NAME, updated_at)

            lag = await shipper._rollup_lag(db, shipper.EVENT_ROLLUP_1H)
            assert lag.pending == 0, (
                f"controlul e stricat: perechea finală ar trebui să arate rândul "
                f"deja expediat, dar pending={lag.pending}")
        finally:
            await db.close()

    run(_run())


def test_a_bucket_rewritten_late_ages_from_when_it_became_visible(pg_dsn):
    """Falsifică alarma falsă din 17 septembrie 2026 pe `ship:lag:event_rollup_1h`.

    `sentinel-maintenance` nu rescrie neapărat un interval exact la închiderea
    lui: o rundă fără evenimente nu scrie nimic, iar runda următoare care GĂSEȘTE
    date rescrie ATUNCI, cu `updated_at` = momentul rescrierii. Un bucket închis
    de 2 ore, dar scris abia acum câteva secunde, trebuie să arate vechi de
    câteva secunde — nu de aproape 2 ore calculate din eticheta lui —, altfel
    `check_ship_lag` trece pragul de grație (15 min) pe purtarea CORECTĂ a
    mecanismului și trimite o alertă „a rămas în urmă” care se stinge singură la
    privirea următoare. Măsurat pe gazda reală: 13 rânduri, „cel mai vechi de
    1h 1m", stins 3 secunde mai târziu.
    """
    now = datetime.now(timezone.utc)
    bucket = (now - timedelta(hours=2)).replace(minute=0, second=0, microsecond=0)
    updated_at = now - timedelta(seconds=3)
    old_cursor_at = bucket - timedelta(hours=1)
    old_cursor_bucket = bucket - timedelta(hours=1)

    async def _run() -> None:
        db = Database(cfg=Config(), dsn=pg_dsn)
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await _seed(conn, bucket=bucket, updated_at=updated_at,
                            old_cursor_at=old_cursor_at,
                            old_cursor_bucket=old_cursor_bucket)

            lag = await shipper._rollup_lag(db, shipper.EVENT_ROLLUP_1H)

            assert lag.pending == 1, (
                f"semănarea nu a lăsat rândul restant — pending={lag.pending}, "
                f"testul nu verifică nimic")
            assert lag.oldest_pending_min is not None
            # Formula veche (`now() - (bucket + 1h)`) ar fi raportat aproape 60
            # de minute aici, deși rândul are, la forma finală, câteva secunde.
            # Toleranță de un minut pentru timpul scurs între semănare și
            # interogare.
            assert lag.oldest_pending_min < 1.0, (
                f"vârsta se citește tot din eticheta intervalului, nu din "
                f"momentul în care rândul a devenit vizibil: raportat "
                f"{lag.oldest_pending_min} min, așteptat sub 1 min")
        finally:
            await db.close()

    run(_run())


def test_a_genuine_stall_still_reads_as_old_despite_the_late_rewrite_fix(pg_dsn):
    """Falsifică inversul reparației de mai sus: `GREATEST` nu are voie să
    ascundă o restanță ADEVĂRATĂ doar fiindcă acum ia și `updated_at`-ul mai
    mare dintre cele două.

    O mutație care mută paranteza — `now() - (min(GREATEST(...)) + interval
    '1 hour')` în loc de `now() - min(GREATEST(..., ... + interval '1
    hour')))` — păstrează fiecare substring pe care testele de sursă îl caută
    (`"interval '1 "`, `"min("`, `"+ interval"`) și trece nevătămată testul de
    mai sus (bucketul rescris târziu, unde vârsta așteptată e sub un minut,
    deci diferența dintre formule nu se vede). Pe un rând scris LA TIMP — nu
    rescris — cu cursorul rămas o oră în urmă, mutația scade o oră întreagă în
    plus din vârsta reală: măsurat pe acest scenariu (rând vechi de facto
    ~67,5 min), formula reparată raportează ~67,5 min, iar cea mutată
    raportează ~7,5 min — SUB răgazul de 15 minute, deci `check_ship_lag` ar
    tăcea exact pe restanța de peste o oră pe care trebuie s-o semnaleze. Pe un
    rând mai vechi decât o oră suplimentară, aceeași mutație iese chiar
    negativă.
    """
    now = datetime.now(timezone.utc)
    bucket = (now - timedelta(hours=2)).replace(minute=0, second=0, microsecond=0)
    updated_at = bucket + timedelta(hours=1, minutes=4)
    old_cursor_at = bucket - timedelta(hours=1)
    old_cursor_bucket = bucket - timedelta(hours=1)

    async def _run() -> None:
        db = Database(cfg=Config(), dsn=pg_dsn)
        await db.connect()
        try:
            async with db.pool.acquire() as conn:
                await _seed(conn, bucket=bucket, updated_at=updated_at,
                            old_cursor_at=old_cursor_at,
                            old_cursor_bucket=old_cursor_bucket)

            lag = await shipper._rollup_lag(db, shipper.EVENT_ROLLUP_1H)

            assert lag.pending == 1, (
                f"semănarea nu a lăsat rândul restant — pending={lag.pending}, "
                f"testul nu verifică nimic")
            assert lag.oldest_pending_min is not None

            expected_min = (
                (datetime.now(timezone.utc) - updated_at).total_seconds() / 60)
            assert abs(lag.oldest_pending_min - expected_min) < 1.0, (
                f"vârsta raportată ({lag.oldest_pending_min} min) nu "
                f"corespunde cu momentul în care rândul a devenit expediabil "
                f"({expected_min} min) — cu paranteza mutată din jurul lui "
                f"GREATEST, formula scade o oră întreagă în plus și subestimează "
                f"o restanță reală")
            assert lag.oldest_pending_min > SHIP_LAG_GRACE_MIN, (
                f"o restanță de {lag.oldest_pending_min} min ar trebui să "
                f"depășească răgazul ({SHIP_LAG_GRACE_MIN} min) — sub el, "
                f"check_ship_lag ar tăcea pe o restanță reală de peste o oră")
        finally:
            await db.close()

    run(_run())
