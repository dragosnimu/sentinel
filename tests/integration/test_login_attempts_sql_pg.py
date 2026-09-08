"""Real Postgres runs the (account, source) lockout query the way a fake
database, backed by its own Python re-implementation of the same filter,
cannot.

CONFIRMED finding (verifier audit, round 2, 8 Sep 2026), W-F2 M3:
`tests/security/test_web_login_lockout.py` models the database with `FakeDB`,
which recognises `recent_failures_for_account_from_ip`'s SQL by a few key
substrings and then answers the count with its OWN Python filter -- the same
filter, written a second time. A mutation to the real SQL (loosening
`result = 'bad_password'` to `result <> 'ok'`, or dropping the `username = $1`
or `stage = 'password'` predicate) changes what the query returns without
changing what `FakeDB`'s Python filter returns, so every test in that file
keeps passing. Only a database that actually executes the query text can
catch that class of mutation; `FakeDB`'s strict dispatch (added this round)
catches a predicate being dropped outright, but not one being loosened while
the clause name it dispatches on stays in the string.

OPTIONAL: runs when either `SENTINEL_TEST_PG_DSN` names a reachable Postgres,
or `docker` is on PATH and its daemon answers -- in the second case this
spins up its own disposable `postgres:16-alpine` container, applies every
migration through the real runner (`sentinel.db.migrate.run_migrations`), and
removes the container afterwards. Skipped, with the reason stated, when
neither is available: a security check that silently reports nothing is
exactly the failure mode this whole file exists to avoid (see CLAUDE.md).

Falsify: change `result = 'bad_password'` to `result <> 'ok'` in
`recent_failures_for_account_from_ip` (sentinel/db/repo/users.py) and rerun
with Docker running. Every assertion below goes red — this file catches that,
`test_web_login_lockout.py::FakeDB` does not (that was the finding).
"""

from __future__ import annotations

import asyncio
import os
import secrets
import shutil
import socket
import subprocess
import time

import pytest

asyncpg = pytest.importorskip("asyncpg", reason="asyncpg not installed")

from sentinel.config import Config  # noqa: E402
from sentinel.db.engine import Database  # noqa: E402
from sentinel.db.migrate import run_migrations  # noqa: E402
from sentinel.db.repo import users  # noqa: E402


def _docker_daemon_reachable() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(
            ["docker", "info"], capture_output=True, timeout=5, check=True,
        )
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
    """A reachable, fully-migrated Postgres DSN, or an explicit skip.

    Prefers `SENTINEL_TEST_PG_DSN` so CI can point this at a service
    container it already manages. Otherwise, if Docker is usable, starts and
    tears down a throwaway `postgres:16-alpine` of its own. Migrations run
    through the real runner (`sentinel.db.migrate`), not a hand-copied
    schema, so this test sees exactly the columns and constraints a
    deployment would.
    """
    env_dsn = os.environ.get("SENTINEL_TEST_PG_DSN")
    if env_dsn:
        rc = run_migrations(dry_run=False, dsn=env_dsn)
        if rc != 0:
            pytest.skip(f"SENTINEL_TEST_PG_DSN set but migrations failed (rc={rc})")
        yield env_dsn
        return

    if not _docker_daemon_reachable():
        pytest.skip(
            "neither SENTINEL_TEST_PG_DSN nor a reachable docker daemon is "
            "available -- the real-SQL check for W-F2 M3 did not run; see "
            "this module's docstring for how to run it"
        )

    port = _free_tcp_port()
    name = f"sentinel-test-pg-{port}"
    subprocess.run(
        [
            "docker", "run", "-d", "--rm", "--name", name,
            "-e", "POSTGRES_PASSWORD=test", "-e", "POSTGRES_DB=sentinel_test",
            "-p", f"127.0.0.1:{port}:5432",
            "postgres:16-alpine",
        ],
        check=True, capture_output=True, timeout=30,
    )
    dsn = f"postgresql://postgres:test@127.0.0.1:{port}/sentinel_test"
    try:
        if not asyncio.run(_wait_until_reachable(dsn)):
            pytest.skip("throwaway Postgres container did not become reachable in time")
        rc = run_migrations(dry_run=False, dsn=dsn)
        assert rc == 0, "migrations failed against the throwaway test container"
        yield dsn
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15)


async def _seed(conn, *, username: str, ip: str, stage: str, result: str, minutes_ago: float) -> None:
    await conn.execute(
        """
        INSERT INTO login_attempts (username, ip, user_agent, result, stage, at)
        VALUES ($1, $2::inet, 'pytest', $3, $4, now() - make_interval(mins => $5))
        """,
        username, ip, result, stage, minutes_ago,
    )


def test_account_source_window_matches_real_postgres(pg_dsn):
    """11 seeded rows, reproduced by hand against `postgres:16` in the round-2
    audit; four counts that only agree with the design if the SQL text still
    has every predicate it is supposed to have."""
    db = Database(cfg=Config(), dsn=pg_dsn)

    async def _run() -> None:
        await db.connect()
        try:
            suffix = secrets.token_hex(4)
            owner, other, probe = f"owner_{suffix}", f"other_{suffix}", f"probe_{suffix}"
            async with db.pool.acquire() as conn:
                for name in (owner, other, probe):
                    await conn.execute(
                        "INSERT INTO users (username, password_hash) VALUES ($1, 'x')",
                        name,
                    )
                try:
                    # -- rows that count toward acct(owner, 9.9.9.9) = 4 ------
                    await _seed(conn, username=owner, ip="9.9.9.9", stage="password",
                                result="bad_password", minutes_ago=2)
                    await _seed(conn, username=owner, ip="9.9.9.9", stage="password",
                                result="bad_password", minutes_ago=5)
                    await _seed(conn, username=owner, ip="9.9.9.9", stage="password",
                                result="bad_password", minutes_ago=10)
                    await _seed(conn, username=owner, ip="9.9.9.9", stage="password",
                                result="bad_password", minutes_ago=14)
                    # -- outside the 15-minute window: must NOT count --------
                    await _seed(conn, username=owner, ip="9.9.9.9", stage="password",
                                result="bad_password", minutes_ago=20)
                    # -- wrong stage: must NOT count for the account window,
                    #    but DOES count for the per-IP window ----------------
                    await _seed(conn, username=owner, ip="9.9.9.9", stage="totp",
                                result="bad_password", minutes_ago=3)
                    # -- wrong result (M3 canary): a `result <> 'ok'` mutation
                    #    would wrongly pull this into the account count -------
                    await _seed(conn, username=owner, ip="9.9.9.9", stage="password",
                                result="unknown_user", minutes_ago=3)
                    # -- wrong account (M1 canary): counts for acct(other) and
                    #    for the per-IP window, not for acct(owner) -----------
                    await _seed(conn, username=other, ip="9.9.9.9", stage="password",
                                result="bad_password", minutes_ago=3)
                    # -- wrong ip: counts for acct(owner, 5.5.5.5) only -------
                    await _seed(conn, username=owner, ip="5.5.5.5", stage="password",
                                result="bad_password", minutes_ago=3)
                    # -- a real success: must not count anywhere --------------
                    await _seed(conn, username=owner, ip="9.9.9.9", stage="password",
                                result="ok", minutes_ago=3)
                    # -- a different account entirely, ip-only signal ---------
                    await _seed(conn, username=probe, ip="9.9.9.9", stage="totp",
                                result="bad_totp", minutes_ago=3)

                    assert await users.recent_failures_for_account_from_ip(
                        db, owner, "9.9.9.9", 15
                    ) == 4
                    assert await users.recent_failures_for_account_from_ip(
                        db, other, "9.9.9.9", 15
                    ) == 1
                    assert await users.recent_failures_for_account_from_ip(
                        db, owner, "5.5.5.5", 15
                    ) == 1
                    assert await users.recent_failures_from_ip(db, "9.9.9.9", 15) == 8
                    # No IP at all: guarded in Python before any query runs.
                    assert await users.recent_failures_for_account_from_ip(
                        db, owner, None, 15
                    ) == 0

                    # -- W-F1: lock_reset_at excludes everything before it,
                    #    even inside an otherwise-live window -----------------
                    await conn.execute(
                        "UPDATE users SET lock_reset_at = now() - make_interval(mins => 7) "
                        "WHERE username = $1",
                        owner,
                    )
                    assert await users.recent_failures_for_account_from_ip(
                        db, owner, "9.9.9.9", 15
                    ) == 2, (
                        "lock_reset_at did not exclude the failures logged before it "
                        "-- unlock()/set_password() would report success without effect"
                    )
                finally:
                    await conn.execute(
                        "DELETE FROM login_attempts WHERE username = ANY($1::text[])",
                        [owner, other, probe],
                    )
                    await conn.execute(
                        "DELETE FROM users WHERE username = ANY($1::text[])",
                        [owner, other, probe],
                    )
        finally:
            await db.close()

    asyncio.run(_run())
