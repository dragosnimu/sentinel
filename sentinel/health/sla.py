"""Daily availability rollups.

Raw health_samples are kept only for the retention window (default 30 days).
Before they age out, each day is summarised into availability_rollup — sample
counts, uptime percent (degraded counts as up), and latency percentiles — so the
long-term uptime history survives without keeping every probe forever.

Idempotent: re-rolling a day overwrites its row, so a maintenance run that
covers the same day twice cannot double-count.
"""

from __future__ import annotations

from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger

log = get_logger(__name__)


async def rollup_day(db: Database, days_back: int = 1) -> int:
    """Roll up availability for `days_back` days ago (default: yesterday).

    Yesterday, not today, because today is still accumulating samples — rolling a
    partial day would record an uptime figure that changes every time it runs.
    Returns the number of asset rows written.
    """
    rows = await db.fetch(
        """
        INSERT INTO availability_rollup (
            asset_id, day, samples, up_samples, degraded_samples, down_samples,
            uptime_pct, p50_latency_ms, p95_latency_ms, p99_latency_ms, max_latency_ms
        )
        SELECT
            asset_id,
            (now() - make_interval(days => $1))::date AS day,
            count(*),
            count(*) FILTER (WHERE status = 'up'),
            count(*) FILTER (WHERE status = 'degraded'),
            count(*) FILTER (WHERE status IN ('down','unknown')),
            round(100.0 * count(*) FILTER (WHERE status IN ('up','degraded')) / NULLIF(count(*), 0), 3),
            percentile_disc(0.50) WITHIN GROUP (ORDER BY latency_ms)::int,
            percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms)::int,
            percentile_disc(0.99) WITHIN GROUP (ORDER BY latency_ms)::int,
            max(latency_ms)
        FROM health_samples
        WHERE ts >= (now() - make_interval(days => $1))::date
          AND ts <  (now() - make_interval(days => $1 - 1))::date
        GROUP BY asset_id
        ON CONFLICT (asset_id, day) DO UPDATE SET
            samples          = EXCLUDED.samples,
            up_samples       = EXCLUDED.up_samples,
            degraded_samples = EXCLUDED.degraded_samples,
            down_samples     = EXCLUDED.down_samples,
            uptime_pct       = EXCLUDED.uptime_pct,
            p50_latency_ms   = EXCLUDED.p50_latency_ms,
            p95_latency_ms   = EXCLUDED.p95_latency_ms,
            p99_latency_ms   = EXCLUDED.p99_latency_ms,
            max_latency_ms   = EXCLUDED.max_latency_ms
        RETURNING asset_id
        """,
        days_back,
    )
    log.info("availability rolled up", extra={"day_offset": days_back, "assets": len(rows)})
    return len(rows)
