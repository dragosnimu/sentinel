"""Create a restore point, seal it, and record it.

Two properties matter more than anything else:

  1. **A backup is not a backup until it has been read back.** The executor
     re-checksums every artifact when the point is sealed, rather than trusting
     the digests this side remembers from creation time. A corrupt archive
     discovered after the patch is worth nothing.
  2. **The way back must not depend on the thing that broke.** Sealing writes a
     standalone `restore.sh` next to the archives. If PostgreSQL is down, if the
     venv is gone, if Sentinel will not start — that script still restores,
     using nothing but tar, zstd and coreutils.

The script is generated inside the executor, never here. Writing text this side
composes into a root-owned executable file is how a privilege boundary turns
into a rootkit, so the caller passes a restore-point id and nothing else.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from sentinel.db.engine import Database
from sentinel.db.repo import patches as repo
from sentinel.logging_setup import get_logger
from sentinel.respond.executor_client import ExecutorClient

log = get_logger(__name__)

_client = ExecutorClient()

# Refuse to back up unless the filesystem has this multiple of the estimate
# free. Filling the disk while making a safety copy turns one problem into two.
DEFAULT_SPACE_MULTIPLIER = 3


class BackupRefused(Exception):
    """Preconditions for a safe backup are not met. Nothing usable was written."""


def restore_point_id(plan_db_id: int | None = None) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    return f"{stamp}-plan{plan_db_id}" if plan_db_id else stamp


async def check_space(estimated_mb: int,
                      multiplier: int = DEFAULT_SPACE_MULTIPLIER) -> int:
    """Free megabytes under the backup root. Raises when there is not enough."""
    try:
        info = await asyncio.to_thread(_client.call, "disk_free",
                                       path="/var/backups/sentinel")
    except Exception as exc:  # noqa: BLE001
        raise BackupRefused(f"nu pot verifica spațiul liber: {exc}") from exc
    if not info.get("ok", True):
        raise BackupRefused(f"nu pot verifica spațiul liber: {info.get('error')}")
    free_mb = int(info.get("free", 0)) // 1_048_576
    needed = max(1, estimated_mb) * multiplier
    if free_mb < needed:
        raise BackupRefused(
            f"spațiu insuficient: {free_mb} MB liberi, sunt necesari {needed} MB "
            f"({multiplier}× estimarea de {estimated_mb} MB)")
    return free_mb


async def create(db: Database, *, plan_db_id: int | None, asset_id: int | None,
                 items: list[dict[str, Any]],
                 estimated_mb: int = 100) -> tuple[int, str, dict[str, Any]]:
    """Back up every item, seal the point, record it.

    Returns (restore_point_db_id, restore_point_id, manifest). Raises
    BackupRefused if anything fails — a partial restore point is more dangerous
    than none, because it looks like a way back.
    """
    await check_space(estimated_mb)
    if not items:
        raise BackupRefused("niciun element de salvat — un punct de restaurare gol "
                            "arată ca o cale de întoarcere, dar nu este")

    rp_id = restore_point_id(plan_db_id)
    for item in items:
        source = item.get("source", "")
        try:
            res = await asyncio.to_thread(
                _client.call, "backup_create",
                kind=item.get("kind", "path"), source=source, restore_point_id=rp_id)
        except Exception as exc:  # noqa: BLE001
            raise BackupRefused(f"backup eșuat pentru {source}: {exc}") from exc
        if not res.get("ok", True):
            raise BackupRefused(f"backup eșuat pentru {source}: {res.get('error')}")

    # Sealing is where verification happens: the executor re-reads each artifact
    # and computes its checksum independently of what creation reported.
    try:
        sealed = await asyncio.to_thread(_client.call, "backup_finalize",
                                         restore_point_id=rp_id)
    except Exception as exc:  # noqa: BLE001
        raise BackupRefused(f"nu pot sigila punctul de restaurare: {exc}") from exc
    if not sealed.get("ok"):
        raise BackupRefused(f"sigilare eșuată: {sealed.get('error')}")

    manifest = {
        "restore_point_id": rp_id,
        "items": sealed.get("items", []),
        "manifest_path": sealed.get("manifest_path"),
        "restore_script": sealed.get("restore_script"),
        "sources": [i.get("source") for i in items],
    }
    total = int(sealed.get("total_bytes", 0))
    path = f"/var/backups/sentinel/{rp_id}"

    rp_db_id = await repo.record_restore_point(
        db, path=path, manifest=manifest, size_bytes=total,
        asset_id=asset_id, plan_db_id=plan_db_id)
    # Sealing succeeded, which means every artifact was read back and hashed.
    await repo.mark_verified(db, rp_db_id, error=None)

    log.warning("restore point created",
                extra={"restore_point": rp_id, "items": len(manifest["items"]),
                       "size_mb": round(total / 1_048_576, 1)})
    return rp_db_id, rp_id, manifest


async def prune(db: Database, cfg: Any) -> int:
    """Delete restore points past retention.

    Three things survive pruning, and the third is the one that matters: the
    most recent point PER ASSET, however old. Retention that can delete the only
    way back for a machine nobody has patched in months is not retention, it is
    data loss on a timer.
    """
    candidates = await repo.prunable_restore_points(
        db, keep_count=cfg.patch.retention_count, keep_days=cfg.patch.retention_days)
    removed = 0
    for row in candidates:
        path = await db.fetchval("SELECT path FROM restore_points WHERE id = $1", row["id"])
        if not path:
            continue
        # Pass the id, not the path: the executor rebuilds the path under its
        # own backup root, so nothing this side composes can point elsewhere.
        rp_id = str(path).rstrip("/").rsplit("/", 1)[-1]
        try:
            res = await asyncio.to_thread(_client.call, "backup_prune",
                                          restore_point_id=rp_id)
        except Exception as exc:  # noqa: BLE001 - a failed delete is not fatal
            log.warning("could not remove restore point",
                        extra={"path": path, "detail": str(exc)})
            continue
        if not res.get("ok"):
            continue
        await repo.mark_deleted(db, row["id"])
        removed += 1
    if removed:
        log.info("restore points pruned", extra={"removed": removed})
    return removed
