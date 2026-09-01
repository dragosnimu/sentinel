"""Robust seasonal baselines — the deterministic core of prediction.

For each (asset, metric, hour-of-week) we keep the MEDIAN and MAD of the
per-minute count, not the mean and stddev. Attack traffic destroys the mean; the
median barely moves, so a baseline built on it is not poisoned by the very spikes
it exists to catch. The anomaly score is the robust z:

    z = 0.6745 * (x - median) / MAD

0.6745 makes MAD a consistent estimator of stddev for normal data, so a z of 3.5
means roughly what it would for mean/stddev — without the fragility.

Seasonality is hour-of-week (0..167): "1200 requests at 04:00 Sunday is abnormal
even though 1200 at 14:00 Tuesday is not." A flat threshold cannot express that.

WARM-UP IS NOT OPTIONAL. Until there are `baseline_warmup_days` of history, every
row is warm=false and the anomaly rule records but does NOT alert. Skipping this
is how you get several hundred false positives on day one.

Events are not asset-mapped at ingest on this host, so the updater resolves each
metric's source to its asset by name (sshd events → the sshd asset). A metric
whose asset is absent is simply skipped.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from datetime import datetime

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

# EWMA smoothing. Low enough that a single noisy minute does not swing the
# recency-weighted level, high enough to track a real shift within a day.
_EWMA_ALPHA = 0.2

# The MAD of an all-identical series is 0; a floor keeps the z-score finite and
# stops one-unit jitter from reading as an infinite anomaly.
_MAD_FLOOR = 1.0


@dataclass(frozen=True)
class Metric:
    name: str
    source: str
    action: str | None   # None = any action for that source
    asset_name: str       # resolved to asset_id by name at update time


METRICS: tuple[Metric, ...] = (
    Metric("requests_per_min", "nginx", None, "nginx"),
    Metric("failed_auth_per_min", "sshd", "auth_fail", "sshd"),
    # F04, secondary signal (novelty is primary — see
    # `predict/behaviour.py`'s `outbound_dst` dimension). Needs an asset named
    # "host" (`kind: host`) added to inventory.yaml by the operator; none is
    # seeded by default (see `tests/unit/test_inventory_examples.py`), so
    # until it exists this metric is silently skipped by `_asset_id` below —
    # the same degradation every other metric here already has if its asset
    # is missing, not a new failure mode.
    Metric("outbound_connections_per_min", "conntrack", "connect", "host"),
)


def hour_of_week(ts: datetime) -> int:
    """0..167. Monday 00:00 = 0. Matches Postgres extract(isodow)-1)*24+hour."""
    return (ts.isoweekday() - 1) * 24 + ts.hour


def robust_z(x: float, median: float, mad: float) -> float:
    """The seasonal anomaly score. MAD is floored so the result is always finite."""
    return 0.6745 * (x - median) / max(mad, _MAD_FLOOR)


def summarize(values: list[float]) -> tuple[float, float, float]:
    """(median, MAD, EWMA) for one hour-of-week bucket's per-minute counts.
    `values` must be in time order for the EWMA to mean anything."""
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values]) if values else 0.0
    ewma = values[0]
    for v in values[1:]:
        ewma = _EWMA_ALPHA * v + (1 - _EWMA_ALPHA) * ewma
    return med, mad, ewma


async def _asset_id(db: Database, name: str) -> int | None:
    return await db.fetchval("SELECT id FROM assets WHERE name = $1", name)


async def update(db: Database, cfg: Config) -> dict[str, int]:
    """Recompute every baseline from raw_events. Idempotent: safe to run on a
    timer. Returns a small summary for the log."""
    window_days = max(cfg.detection.baseline_warmup_days, 28)
    warmup_days = cfg.detection.baseline_warmup_days

    rows_written = 0
    warm_metrics = 0
    for metric in METRICS:
        asset_id = await _asset_id(db, metric.asset_name)
        if asset_id is None:
            continue

        # Per-minute counts, tagged with hour-of-week, over the window.
        per_min = await db.fetch(
            """
            SELECT (extract(isodow from ts)::int - 1) * 24 + extract(hour from ts)::int AS how,
                   date_trunc('minute', ts) AS minute,
                   count(*) AS n
            FROM raw_events
            WHERE source = $1 AND ($2::text IS NULL OR action = $2)
              AND ts > now() - make_interval(days => $3)
            GROUP BY how, minute
            ORDER BY how, minute
            """,
            metric.source, metric.action, window_days,
        )
        if not per_min:
            continue

        span_days = (per_min[-1]["minute"] - per_min[0]["minute"]).total_seconds() / 86_400
        warm = span_days >= warmup_days
        if warm:
            warm_metrics += 1

        buckets: dict[int, list[float]] = {}
        for r in per_min:
            buckets.setdefault(int(r["how"]), []).append(float(r["n"]))

        for how, values in buckets.items():
            median, mad, ewma = summarize(values)
            await db.execute(
                """
                INSERT INTO baselines
                    (asset_id, metric, hour_of_week, median, mad, ewma, sample_count, warm, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
                ON CONFLICT (asset_id, metric, hour_of_week) DO UPDATE SET
                    median = EXCLUDED.median, mad = EXCLUDED.mad, ewma = EXCLUDED.ewma,
                    sample_count = EXCLUDED.sample_count, warm = EXCLUDED.warm,
                    updated_at = now()
                """,
                asset_id, metric.name, how, median, mad, ewma, len(values), warm,
            )
            rows_written += 1

    log.info("baselines updated", extra={"rows": rows_written, "warm_metrics": warm_metrics})
    return {"rows": rows_written, "warm_metrics": warm_metrics}


async def warmup_status(db: Config | Database, cfg: Config | None = None) -> dict[str, object]:
    """For the dashboard banner: are we still learning, and how far in?"""
    db_: Database = db  # type: ignore[assignment]
    warmup_days = cfg.detection.baseline_warmup_days if cfg else 14
    row = await db_.fetchrow(
        """
        SELECT count(*) AS rows,
               count(*) FILTER (WHERE warm) AS warm_rows,
               min(first_sample_at) AS first_sample
        FROM baselines
        """
    )
    rows = int(row["rows"] or 0)
    warm_rows = int(row["warm_rows"] or 0)
    first = row["first_sample"]
    return {
        "learning": warm_rows == 0,
        "rows": rows,
        "warm_rows": warm_rows,
        "warmup_days": warmup_days,
        "first_sample_at": first.isoformat() if first else None,
    }
