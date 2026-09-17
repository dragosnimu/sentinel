"""Falsifică ipoteza „mentenanța scrie sursele unei ore cu momente diferite".

## Ipoteza de investigat

Alarma de producție `ship:lag:event_rollup_1h`: 13 rânduri neexpediate, cel mai
vechi de 1h 1m, stinsă cinci minute mai târziu. Un candidat: `updated_at`
diferă între sursele (`nginx`, `sshd`, ...) scrise de `sentinel_rollup_events_1h`
pentru ACEEAȘI oră, într-o SINGURĂ trecere de mentenanță — deci filigranul
expeditorului ar putea veni la odihnă ÎNĂUNTRUL acelui interval, lăsând un rând
deasupra lui, nevăzut până la rescrierea următoare (o oră mai târziu).

## Ce spune codul, și de ce nu e de ajuns să fie citit

`sentinel/db/migrations/0023_ship_watermarks.sql`, `set_updated_at()`:

    -- `now()` e ora de ÎNCEPUT a tranzacției, nu a instrucțiunii. Alegerea e
    -- deliberată [...]: două rânduri atinse de aceeași tranzacție primesc
    -- același moment, deci fie pleacă amândouă, fie niciunul. Cu
    -- `clock_timestamp()` ar fi putut cădea de o parte și de alta a unui
    -- filigran [...].

Comentariul spune direct că ipoteza e exact ce migrația a fost scrisă să
prevină. Dar un fișier de migrație pe disc nu e dovadă că nucleul se poartă
așa — e chiar avertismentul din capul `shipper.py` despre `augenrules
--load`. Testul ăsta EXECUTĂ `sentinel_rollup_events_1h` pe un Postgres
adevărat, cu mai multe surse în aceeași oră, și citește înapoi `updated_at`
al fiecărui rând scris.

Rezultat: identice, la microsecundă. Ipoteza e falsă — un rând scris de
ACEEAȘI trecere de mentenanță nu poate sta de o parte a filigranului în timp
ce un altul, din același apel, stă de cealaltă. (Cauza reală a alarmei era
formula de vârstă din `_rollup_lag`, care număra de la eticheta intervalului
în loc de momentul în care rândul a devenit expediabil — vezi
`test_rollup_lag_torn_read_pg.py`. Citirea perechii `(cursor_at, cursor)` se
făcea prin două `fetchval` separate și a devenit atomică, printr-un singur
`fetchrow`, în aceeași schimbare — dar aia e o corectitudine separată, nu
cauza alarmei: ambele avansări de cursor au căzut în afara ferestrei de
citire a verificării.)

OPȚIONAL: rulează cu `SENTINEL_TEST_PG_DSN`, sau pornește singur un
`postgres:16-alpine` prin docker — vezi `test_orphan_attach_pg.py`.

Falsifică: `CREATE OR REPLACE FUNCTION set_updated_at() ... NEW.updated_at :=
clock_timestamp()`, rulat pe conexiunea de test înainte de a doua trecere
(cea prin trigger, nu prin DEFAULT-ul coloanei) — pică determinist, cu 6
valori distincte în loc de una: bucla `plpgsql` din interiorul unei singure
instrucțiuni `INSERT ... ON CONFLICT DO UPDATE` ia suficiente microsecunde
între rânduri cât să se vadă. Verificat prin execuție, nu presupus.
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

from sentinel.db.migrate import run_migrations  # noqa: E402


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
            "nici SENTINEL_TEST_PG_DSN, nici un daemon docker accesibil — "
            "trigger-ul `set_updated_at()` NU a fost rulat de un Postgres real; "
            "vezi docstring-ul modulului")

    port = _free_tcp_port()
    name = f"sentinel-test-rollup-finalize-ts-pg-{port}"
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


def test_one_maintenance_pass_gives_every_source_the_same_updated_at(pg_dsn):
    """Falsifică ipoteza inițială din investigația `ship:lag:event_rollup_1h`.

    Șase surse diferite, aceeași oră, o SINGURĂ trecere prin
    `sentinel_rollup_events_1h`. Dacă `updated_at` ar diferi între ele, un
    filigran ar putea veni la odihnă între două surse ale ACELEIAȘI ore — exact
    scenariul din care pornea investigația. Diferă = testul pică.
    """
    hour = datetime(2026, 9, 17, 6, 0, tzinfo=timezone.utc)
    hour_end = datetime(2026, 9, 17, 7, 0, tzinfo=timezone.utc)
    sources = ("nginx", "sshd", "auditd", "fail2ban", "ufw", "postgres")

    async def _run() -> None:
        conn = await asyncpg.connect(pg_dsn)
        try:
            await conn.execute("DELETE FROM event_rollup_1h WHERE bucket = $1", hour)
            await conn.execute(
                "DELETE FROM event_rollup_1m WHERE bucket >= $1 AND bucket < $2",
                hour, hour_end)
            for source in sources:
                # Câteva minute distincte în interiorul orei, câte una pentru
                # fiecare sursă — ca `sentinel_rollup_events_1h` să aibă
                # efectiv ceva de sumat, nu doar un singur minut repetat.
                await conn.execute(
                    """
                    INSERT INTO event_rollup_1m
                        (bucket, asset_id, source, action, n, uniq_src,
                         bytes_in, bytes_out, p95_latency_ms)
                    VALUES ($1, 0, $2, 'event', 10, 1, 0, 0, NULL)
                    """,
                    hour, source)

            # Apelul real: fereastra unei ore întregi, ca la mentenanță. PRIMUL
            # apel scrie rânduri NOI (`INSERT`) — `updated_at` iese din
            # DEFAULT-ul coloanei, nu din trigger, fiindcă triggerul e doar
            # `BEFORE UPDATE`.
            n = await conn.fetchval(
                "SELECT sentinel_rollup_events_1h($1, $2)", hour, hour_end)
            assert n == len(sources), f"scrise {n} din {len(sources)} surse așteptate"

            rows = await conn.fetch(
                "SELECT source, updated_at FROM event_rollup_1h WHERE bucket = $1",
                hour)
            assert len(rows) == len(sources)
            stamps = {r["updated_at"] for r in rows}
            assert len(stamps) == 1, (
                f"sursele aceleiași ore, din ACEEAȘI trecere, au `updated_at` "
                f"diferit — ipoteza inițială s-ar confirma: {sorted(stamps)}")
            first_stamp = next(iter(stamps))

            # AL DOILEA apel: fereastra RECALCULEAZĂ aceleași rânduri, deci
            # `ON CONFLICT ... DO UPDATE` — de data asta chiar triggerul
            # `set_updated_at()` scrie `updated_at`, nu DEFAULT-ul coloanei.
            # Ăsta e drumul pe care 0023 îl descrie explicit.
            n2 = await conn.fetchval(
                "SELECT sentinel_rollup_events_1h($1, $2)", hour, hour_end)
            assert n2 == len(sources)
            rows2 = await conn.fetch(
                "SELECT source, updated_at FROM event_rollup_1h WHERE bucket = $1",
                hour)
            stamps2 = {r["updated_at"] for r in rows2}
            assert len(stamps2) == 1, (
                f"a doua trecere (prin trigger, nu prin DEFAULT) a dat "
                f"`updated_at` diferit între surse — ipoteza inițială s-ar "
                f"confirma: {sorted(stamps2)}")
            second_stamp = next(iter(stamps2))
            assert second_stamp > first_stamp, (
                "un interval RECALCULAT trebuie să-și mute `updated_at` "
                "înainte, altfel rescrierea n-ar mai trece de filigran")
        finally:
            await conn.close()

    run(_run())
