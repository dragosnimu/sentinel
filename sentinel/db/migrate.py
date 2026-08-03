"""Forward-only SQL migration runner.

Deliberately simple: numbered `.sql` files, applied in order, recorded in
`schema_version`. No down-migrations — reversing a schema change on a live
security database is a fantasy, and pretending otherwise encourages people to
try it during an incident. The way back is the pre-deploy snapshot.

Each file runs inside a single transaction. PostgreSQL supports transactional
DDL, so a failing migration leaves nothing half-applied.

    sentinel migrate --dry-run
    sentinel migrate
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

import asyncpg

from sentinel.config import database_dsn
from sentinel.errors import StorageError
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
_NAME_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")

BOOTSTRAP = """
CREATE TABLE IF NOT EXISTS schema_version (
    version     integer      PRIMARY KEY,
    name        text         NOT NULL,
    checksum    text         NOT NULL,
    applied_at  timestamptz  NOT NULL DEFAULT now(),
    duration_ms integer      NOT NULL
);
"""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: Path
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()[:16]


def discover() -> list[Migration]:
    if not MIGRATIONS_DIR.is_dir():
        raise StorageError(f"migrations directory not found: {MIGRATIONS_DIR}")

    found: list[Migration] = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        match = _NAME_RE.match(path.name)
        if not match:
            raise StorageError(
                f"migration filename {path.name!r} does not match NNNN_name.sql"
            )
        found.append(
            Migration(
                version=int(match.group(1)),
                name=match.group(2),
                path=path,
                sql=path.read_text(encoding="utf-8"),
            )
        )

    versions = [m.version for m in found]
    if len(set(versions)) != len(versions):
        duplicates = {v for v in versions if versions.count(v) > 1}
        raise StorageError(f"duplicate migration version(s): {sorted(duplicates)}")
    return found


async def _apply(dsn: str, dry_run: bool) -> int:
    conn = await asyncpg.connect(dsn, timeout=15)
    try:
        await conn.execute(BOOTSTRAP)
        applied = {
            r["version"]: r
            for r in await conn.fetch("SELECT version, name, checksum FROM schema_version")
        }

        migrations = discover()
        pending = [m for m in migrations if m.version not in applied]

        # A changed file that has already been applied means someone edited
        # history. That is how two environments silently diverge.
        for m in migrations:
            row = applied.get(m.version)
            if row and row["checksum"] != m.checksum:
                raise StorageError(
                    f"migration {m.version:04d}_{m.name} was already applied but its "
                    f"content has changed (recorded {row['checksum']}, file "
                    f"{m.checksum}). Migrations are immutable once applied — add a "
                    "new one instead of editing this."
                )

        if not pending:
            log.info("schema up to date", extra={"applied": len(applied)})
            return 0

        if dry_run:
            for m in pending:
                print(f"would apply {m.version:04d}_{m.name}  ({len(m.sql)} bytes)")
            return 0

        for m in pending:
            log.info("applying migration", extra={"version": m.version, "migration": m.name})
            started = asyncio.get_running_loop().time()
            async with conn.transaction():
                try:
                    await conn.execute(m.sql)
                except asyncpg.PostgresError as exc:
                    raise StorageError(
                        f"migration {m.version:04d}_{m.name} failed and was rolled "
                        f"back: {exc}"
                    ) from exc
                duration_ms = int((asyncio.get_running_loop().time() - started) * 1000)
                await conn.execute(
                    "INSERT INTO schema_version (version, name, checksum, duration_ms) "
                    "VALUES ($1, $2, $3, $4)",
                    m.version,
                    m.name,
                    m.checksum,
                    duration_ms,
                )
            log.info(
                "migration applied",
                extra={"version": m.version, "migration": m.name, "duration_ms": duration_ms},
            )

        return 0
    finally:
        await conn.close()


def run_migrations(dry_run: bool = False, dsn: str | None = None) -> int:
    try:
        return asyncio.run(_apply(dsn or database_dsn(), dry_run))
    except StorageError as exc:
        log.error("migration failed", extra={"detail": str(exc)})
        print(f"migration failed: {exc}")
        return 1
    except (asyncpg.PostgresError, OSError) as exc:
        log.error("cannot reach the database", extra={"detail": str(exc)})
        print(f"cannot reach the database: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(run_migrations())
