"""Host capacity samples: CPU, load, memory, disk, connections.

One row every probe tick. The busiest disk and its inode usage are denormalised
onto the row so the common "is anything nearly full" query does not have to open
the JSONB. Per-mount detail and per-service RSS stay in JSONB for the drill-down.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sentinel.db.engine import Database


@dataclass
class CapacitySample:
    ts: datetime
    cpu_pct: float | None
    load1: float | None
    mem_total_mb: int | None
    mem_used_mb: int | None
    mem_available_mb: int | None
    swap_used_mb: int | None
    disk_used_pct: float | None
    inode_used_pct: float | None
    conn_count: int | None
    disks: dict[str, Any]
    per_service_rss: dict[str, Any]


async def record_sample(db: Database, s: dict[str, Any]) -> None:
    await db.execute(
        """
        INSERT INTO capacity_samples (
            ts, cpu_pct, load1, load5, load15,
            mem_total_mb, mem_used_mb, mem_available_mb, swap_used_mb,
            disks, disk_used_pct, inode_used_pct, conn_count, per_service_rss
        ) VALUES (
            now(), $1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13::jsonb
        )
        """,
        s.get("cpu_pct"),
        s.get("load1"),
        s.get("load5"),
        s.get("load15"),
        s.get("mem_total_mb"),
        s.get("mem_used_mb"),
        s.get("mem_available_mb"),
        s.get("swap_used_mb"),
        json.dumps(s.get("disks", {})),
        s.get("disk_used_pct"),
        s.get("inode_used_pct"),
        s.get("conn_count"),
        json.dumps(s.get("per_service_rss", {})),
    )


def _row(row: Any) -> CapacitySample:
    d = dict(row)
    disks = d.get("disks") or {}
    rss = d.get("per_service_rss") or {}
    if isinstance(disks, str):
        disks = json.loads(disks)
    if isinstance(rss, str):
        rss = json.loads(rss)
    return CapacitySample(
        ts=d["ts"],
        cpu_pct=float(d["cpu_pct"]) if d["cpu_pct"] is not None else None,
        load1=float(d["load1"]) if d["load1"] is not None else None,
        mem_total_mb=d["mem_total_mb"],
        mem_used_mb=d["mem_used_mb"],
        mem_available_mb=d["mem_available_mb"],
        swap_used_mb=d["swap_used_mb"],
        disk_used_pct=float(d["disk_used_pct"]) if d["disk_used_pct"] is not None else None,
        inode_used_pct=float(d["inode_used_pct"]) if d["inode_used_pct"] is not None else None,
        conn_count=d["conn_count"],
        disks=dict(disks),
        per_service_rss=dict(rss),
    )


async def latest(db: Database) -> CapacitySample | None:
    row = await db.fetchrow(
        """
        SELECT ts, cpu_pct, load1, mem_total_mb, mem_used_mb, mem_available_mb,
               swap_used_mb, disks, disk_used_pct, inode_used_pct, conn_count,
               per_service_rss
        FROM capacity_samples ORDER BY ts DESC LIMIT 1
        """
    )
    return _row(row) if row else None


async def history(db: Database, hours: int = 24, buckets: int = 96) -> list[dict]:
    """Down-sampled CPU / memory / disk history for the capacity chart."""
    rows = await db.fetch(
        """
        WITH b AS (
            SELECT generate_series(
                date_trunc('minute', now()) - make_interval(mins => $1 * 60),
                date_trunc('minute', now()),
                make_interval(mins => ($1 * 60) / $2)
            ) AS bucket
        )
        SELECT b.bucket AS t,
               round(avg(s.cpu_pct), 1)               AS cpu_pct,
               round(avg(s.disk_used_pct), 1)         AS disk_used_pct,
               min(s.mem_available_mb)                AS mem_available_mb
        FROM b
        LEFT JOIN capacity_samples s
               ON s.ts >= b.bucket
              AND s.ts <  b.bucket + make_interval(mins => ($1 * 60) / $2)
        GROUP BY b.bucket
        ORDER BY b.bucket
        """,
        hours,
        buckets,
    )
    return [
        {
            "t": r["t"].isoformat(),
            "cpu_pct": float(r["cpu_pct"]) if r["cpu_pct"] is not None else None,
            "disk_used_pct": float(r["disk_used_pct"]) if r["disk_used_pct"] is not None else None,
            "mem_available_mb": r["mem_available_mb"],
        }
        for r in rows
    ]
