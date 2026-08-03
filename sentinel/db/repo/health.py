"""Availability samples, outage records, and uptime queries.

A *sample* is one probe result. An *outage* is a span the operator cares about,
opened when an asset has been down for `down_after_failures` consecutive samples
and closed when it recovers. Availability is computed from samples, not from
outages, so a flapping service still shows its true uptime percentage.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sentinel.db.engine import Database

STATUSES = ("up", "degraded", "down", "unknown")


@dataclass
class Sample:
    asset_id: int
    status: str
    latency_ms: int | None
    http_status: int | None
    error: str | None
    probe: str
    ts: datetime


@dataclass
class LiveStatus:
    asset_id: int
    status: str
    latency_ms: int | None
    error: str | None
    ts: datetime
    uptime_24h: float          # percent, degraded counts as up
    open_since: datetime | None  # start of the current outage, if down


async def record_sample(
    db: Database,
    *,
    asset_id: int,
    status: str,
    latency_ms: int | None = None,
    http_status: int | None = None,
    error: str | None = None,
    probe: str = "http",
) -> None:
    await db.execute(
        """
        INSERT INTO health_samples (ts, asset_id, status, latency_ms, http_status, error, probe)
        VALUES (now(), $1, $2, $3, $4, $5, $6)
        """,
        asset_id,
        status,
        latency_ms,
        http_status,
        (error or "")[:500] or None,
        probe,
    )


async def consecutive_failures(db: Database, asset_id: int, limit: int = 10) -> int:
    """How many of the most recent samples in a row were not 'up'/'degraded'.

    Used to decide when a run of failures becomes an outage worth recording,
    without a separate counter that could drift from the samples themselves.
    """
    rows = await db.fetch(
        "SELECT status FROM health_samples WHERE asset_id = $1 ORDER BY ts DESC LIMIT $2",
        asset_id,
        limit,
    )
    n = 0
    for r in rows:
        if r["status"] in ("down", "unknown"):
            n += 1
        else:
            break
    return n


async def open_outage_id(db: Database, asset_id: int) -> int | None:
    return await db.fetchval(
        "SELECT id FROM outages WHERE asset_id = $1 AND ended_at IS NULL ORDER BY started_at DESC LIMIT 1",
        asset_id,
    )


async def open_outage(db: Database, asset_id: int, *, kind: str = "down", cause: str | None = None) -> None:
    if await open_outage_id(db, asset_id) is not None:
        return  # already open — do not stack outages for the same asset
    await db.execute(
        "INSERT INTO outages (asset_id, started_at, kind, cause) VALUES ($1, now(), $2, $3)",
        asset_id,
        kind,
        (cause or "")[:500] or None,
    )


async def close_outage(db: Database, asset_id: int) -> None:
    await db.execute(
        """
        UPDATE outages
           SET ended_at = now(),
               duration_s = GREATEST(0, EXTRACT(EPOCH FROM (now() - started_at))::int)
         WHERE asset_id = $1 AND ended_at IS NULL
        """,
        asset_id,
    )


async def live_status(db: Database) -> dict[int, LiveStatus]:
    """The current state of every asset, plus its 24h uptime, in one round trip.

    DISTINCT ON gives the newest sample per asset; a lateral aggregate gives the
    24h availability (degraded counts as up). Assets with no samples yet are
    simply absent from the result — the caller renders them as 'unknown'.
    """
    rows = await db.fetch(
        """
        SELECT s.asset_id, s.status, s.latency_ms, s.error, s.ts,
               COALESCE(a.up_pct, 0)::float AS uptime_24h,
               o.started_at AS open_since
        FROM (
            SELECT DISTINCT ON (asset_id) asset_id, status, latency_ms, error, ts
            FROM health_samples
            WHERE ts > now() - interval '10 minutes'
            ORDER BY asset_id, ts DESC
        ) s
        LEFT JOIN LATERAL (
            SELECT 100.0 * count(*) FILTER (WHERE status IN ('up','degraded')) / NULLIF(count(*), 0) AS up_pct
            FROM health_samples
            WHERE asset_id = s.asset_id AND ts > now() - interval '24 hours'
        ) a ON true
        LEFT JOIN outages o ON o.asset_id = s.asset_id AND o.ended_at IS NULL
        """
    )
    out: dict[int, LiveStatus] = {}
    for r in rows:
        out[r["asset_id"]] = LiveStatus(
            asset_id=r["asset_id"],
            status=r["status"],
            latency_ms=r["latency_ms"],
            error=r["error"],
            ts=r["ts"],
            uptime_24h=round(r["uptime_24h"], 2),
            open_since=r["open_since"],
        )
    return out


async def sparkline(db: Database, asset_id: int, hours: int = 24, buckets: int = 48) -> list[dict]:
    """One up-fraction value per time bucket, for a compact 24h uptime chart.

    Server-computed so the page ships numbers, not raw samples — a security
    dashboard has no business streaming thousands of rows to a browser.
    """
    rows = await db.fetch(
        """
        WITH b AS (
            SELECT generate_series(
                date_trunc('minute', now()) - make_interval(mins => $2 * 60),
                date_trunc('minute', now()),
                make_interval(mins => ($2 * 60) / $3)
            ) AS bucket
        )
        SELECT b.bucket,
               count(s.*) AS n,
               count(s.*) FILTER (WHERE s.status IN ('up','degraded')) AS up
        FROM b
        LEFT JOIN health_samples s
               ON s.asset_id = $1
              AND s.ts >= b.bucket
              AND s.ts <  b.bucket + make_interval(mins => ($2 * 60) / $3)
        GROUP BY b.bucket
        ORDER BY b.bucket
        """,
        asset_id,
        hours,
        buckets,
    )
    return [
        {
            "t": r["bucket"].isoformat(),
            "up": (round(100.0 * r["up"] / r["n"], 1) if r["n"] else None),
        }
        for r in rows
    ]
