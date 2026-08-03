"""Sample host capacity: CPU, load, memory, disk, connections, per-service RSS.

Read-only introspection via psutil. Cheap enough to run on every 30s tick; the
per-mount and per-service detail goes into JSONB for drill-down while the busiest
disk is denormalised for the "anything nearly full?" query.
"""

from __future__ import annotations

import os
from typing import Any

import psutil

from sentinel.db.engine import Database
from sentinel.db.repo import capacity as capacity_repo
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

# Process names worth tracking RSS for individually. Everything else is noise on
# a security dashboard; these are the things whose growth predicts a problem.
_WATCHED_PREFIXES = ("sentinel", "postgres", "nginx", "suricata", "dockerd", "containerd")


def sample() -> dict[str, Any]:
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    try:
        load1, load5, load15 = os.getloadavg()
    except (OSError, AttributeError):
        load1 = load5 = load15 = None

    disks: dict[str, Any] = {}
    disk_used_pct_max = 0.0
    inode_used_pct_max = 0.0
    for part in psutil.disk_partitions(all=False):
        # Skip pseudo/removable filesystems: only real mounts can fill up in a
        # way worth alerting on.
        if part.fstype in ("", "squashfs", "tmpfs", "devtmpfs", "overlay"):
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue
        disks[part.mountpoint] = {
            "used_pct": round(usage.percent, 1),
            "free_gb": round(usage.free / (1024**3), 1),
        }
        disk_used_pct_max = max(disk_used_pct_max, usage.percent)
        inode = _inode_pct(part.mountpoint)
        if inode is not None:
            inode_used_pct_max = max(inode_used_pct_max, inode)

    per_service_rss: dict[str, int] = {}
    for proc in psutil.process_iter(["name", "memory_info"]):
        try:
            name = (proc.info["name"] or "").lower()
            if not any(name.startswith(p) for p in _WATCHED_PREFIXES):
                continue
            rss_mb = int(proc.info["memory_info"].rss / (1024**2))
            key = next(p for p in _WATCHED_PREFIXES if name.startswith(p))
            per_service_rss[key] = per_service_rss.get(key, 0) + rss_mb
        except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError, TypeError):
            continue

    try:
        conn_count = len(psutil.net_connections(kind="tcp"))
    except (psutil.AccessDenied, OSError):
        conn_count = None

    return {
        "cpu_pct": round(psutil.cpu_percent(interval=0.5), 1),
        "load1": round(load1, 2) if load1 is not None else None,
        "load5": round(load5, 2) if load5 is not None else None,
        "load15": round(load15, 2) if load15 is not None else None,
        "mem_total_mb": int(vm.total / (1024**2)),
        "mem_used_mb": int(vm.used / (1024**2)),
        "mem_available_mb": int(vm.available / (1024**2)),
        "swap_used_mb": int(swap.used / (1024**2)),
        "disks": disks,
        "disk_used_pct": round(disk_used_pct_max, 1),
        "inode_used_pct": round(inode_used_pct_max, 1) if inode_used_pct_max else None,
        "conn_count": conn_count,
        "per_service_rss": per_service_rss,
    }


def _inode_pct(mountpoint: str) -> float | None:
    # statvfs is POSIX-only; on a non-Unix host (a developer's machine running
    # the tests) there simply is no inode figure, and that is fine.
    if not hasattr(os, "statvfs"):
        return None
    try:
        st = os.statvfs(mountpoint)
    except OSError:
        return None
    if st.f_files == 0:
        return None
    used = st.f_files - st.f_ffree
    return round(100.0 * used / st.f_files, 1)


async def sample_and_record(db: Database) -> dict[str, Any]:
    s = sample()
    await capacity_repo.record_sample(db, s)
    log.info(
        "capacity sampled",
        extra={
            "cpu_pct": s["cpu_pct"],
            "mem_available_mb": s["mem_available_mb"],
            "disk_used_pct": s["disk_used_pct"],
        },
    )
    return s
