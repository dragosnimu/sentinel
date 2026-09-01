#!/usr/bin/env python3
"""Read-only named queries against the Sentinel database.

The catalog below is the only SQL these scripts will run. Parameters are bound,
never interpolated — a query name and its declared parameters are the entire
surface. This exists so that an agent (or a prompt-injected agent) cannot
construct arbitrary SQL.

Usage:
    sentinel_query.py                          # list the catalog
    sentinel_query.py <name> --help            # show one query's parameters
    sentinel_query.py open_incidents --param limit=20 --format table
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import Any

import _common as c


@dataclass(frozen=True)
class Query:
    name: str
    description: str
    sql: str
    params: dict[str, str] = field(default_factory=dict)  # name -> "type[:default]"


# ---------------------------------------------------------------------------
# The catalog
# ---------------------------------------------------------------------------
QUERIES: list[Query] = [
    # -- Incidents -----------------------------------------------------------
    Query(
        "open_incidents",
        "Open incidents, most severe and most recent first.",
        """
        SELECT i.id, i.severity, i.ai_severity, i.status, i.title, i.actor_key,
               a.name AS asset, i.detection_count,
               i.first_detection_at, i.last_detection_at
        FROM incidents i
        LEFT JOIN assets a ON a.id = i.asset_id
        WHERE i.status IN ('open', 'acknowledged')
        ORDER BY array_position(
                   ARRAY['critical','high','medium','low','info'],
                   COALESCE(i.ai_severity, i.severity)),
                 i.last_detection_at DESC
        LIMIT $1
        """,
        {"limit": "int:25"},
    ),
    Query(
        "recent_incidents",
        "All incidents in a time window, regardless of status.",
        """
        SELECT i.id, i.severity, i.ai_severity, i.status, i.title, i.actor_key,
               a.name AS asset, i.detection_count, i.first_detection_at, i.resolved_at
        FROM incidents i
        LEFT JOIN assets a ON a.id = i.asset_id
        WHERE i.first_detection_at >= $1
        ORDER BY i.first_detection_at DESC
        LIMIT $2
        """,
        {"since": "window:24h", "limit": "int:100"},
    ),
    Query(
        "incident_detections",
        "Every detection folded into one incident, in order.",
        """
        SELECT d.id, d.ts, d.rule_id, d.rule_family, d.severity, d.score,
               d.src_ip, d.evidence
        FROM detections d
        WHERE d.incident_id = $1
        ORDER BY d.ts
        LIMIT 500
        """,
        {"incident_id": "int"},
    ),
    Query(
        "incident_stats",
        "Incident counts and MTTD/MTTR by severity over a window.",
        """
        SELECT COALESCE(ai_severity, severity) AS severity,
               count(*) AS total,
               count(*) FILTER (WHERE status = 'resolved') AS resolved,
               count(*) FILTER (WHERE status IN ('open','acknowledged')) AS still_open,
               count(*) FILTER (WHERE status = 'false_positive') AS false_positives,
               round(avg(EXTRACT(EPOCH FROM (first_detection_at - created_at)))::numeric, 1)
                   AS mttd_seconds,
               round(avg(EXTRACT(EPOCH FROM (resolved_at - first_detection_at)))
                     FILTER (WHERE resolved_at IS NOT NULL)::numeric, 1) AS mttr_seconds
        FROM incidents
        WHERE first_detection_at >= $1
        GROUP BY 1
        ORDER BY array_position(ARRAY['critical','high','medium','low','info'], 1::text)
        """,
        {"since": "window:7d"},
    ),
    # -- Actors --------------------------------------------------------------
    Query(
        "top_actors",
        "Most active actors in a window, by detection count.",
        """
        SELECT ac.actor_key, ac.killchain_stage, ac.stage_entered_at, ac.risk_score,
               ac.countries, ac.asns, ac.reputation, ac.is_blocked, ac.is_allowlisted,
               count(d.id) AS detections, max(d.ts) AS last_seen
        FROM actors ac
        JOIN detections d ON d.actor_key = ac.actor_key
        WHERE d.ts >= $1
        GROUP BY ac.actor_key, ac.killchain_stage, ac.stage_entered_at, ac.risk_score,
                 ac.countries, ac.asns, ac.reputation, ac.is_blocked, ac.is_allowlisted
        ORDER BY detections DESC
        LIMIT $2
        """,
        {"since": "window:24h", "limit": "int:20"},
    ),
    Query(
        "actor_profile",
        "Everything known about one actor.",
        """
        SELECT * FROM actors WHERE actor_key = $1
        """,
        {"actor_key": "text"},
    ),
    Query(
        "actor_timeline",
        "Chronological detections for one actor.",
        """
        SELECT d.ts, d.rule_id, d.severity, d.src_ip, a.name AS asset, d.evidence
        FROM detections d
        LEFT JOIN assets a ON a.id = d.asset_id
        WHERE d.actor_key = $1 AND d.ts >= $2
        ORDER BY d.ts
        LIMIT 500
        """,
        {"actor_key": "text", "since": "window:7d"},
    ),
    Query(
        "killchain_transition_stats",
        "Empirical P(advance from a stage within a horizon). The basis for predictions.",
        """
        WITH at_stage AS (
            SELECT actor_key, at AS entered
            FROM killchain_transitions
            WHERE to_stage = $1 AND at >= $3
        ),
        advanced AS (
            SELECT s.actor_key
            FROM at_stage s
            JOIN killchain_transitions t
              ON t.actor_key = s.actor_key
             AND t.from_stage = $1
             AND t.at BETWEEN s.entered AND s.entered + make_interval(mins => $2)
        )
        SELECT $1 AS from_stage,
               $2 AS horizon_minutes,
               (SELECT count(*) FROM at_stage)                    AS denominator,
               (SELECT count(DISTINCT actor_key) FROM advanced)   AS numerator,
               CASE WHEN (SELECT count(*) FROM at_stage) = 0 THEN NULL
                    ELSE round((SELECT count(DISTINCT actor_key) FROM advanced)::numeric
                               / (SELECT count(*) FROM at_stage), 3)
               END AS probability
        """,
        {"stage": "int", "horizon_minutes": "int:30", "since": "window:60d"},
    ),
    # -- Blocklist -----------------------------------------------------------
    Query(
        "active_blocks",
        "Currently active blocks with remaining TTL and hit counts.",
        """
        SELECT ip, reason, rule_id, incident_id, blocked_at, expires_at,
               hit_count, created_by,
               CASE WHEN expires_at IS NULL THEN NULL
                    ELSE EXTRACT(EPOCH FROM (expires_at - now()))::bigint
               END AS ttl_remaining_s
        FROM blocklist
        WHERE active
        ORDER BY blocked_at DESC
        LIMIT $1
        """,
        {"limit": "int:100"},
    ),
    Query(
        "block_effectiveness",
        "Did blocking help? Blocks with post-block hit counts and actor reappearance.",
        """
        SELECT b.ip, b.blocked_at, b.hit_count, b.reason,
               EXISTS (
                   SELECT 1 FROM detections d
                   JOIN actors ac ON ac.actor_key = d.actor_key
                   WHERE d.ts > b.blocked_at
                     AND d.src_ip <> b.ip
                     AND ac.actor_key = (SELECT actor_key FROM blocklist WHERE id = b.id)
               ) AS actor_returned_from_other_ip
        FROM blocklist b
        WHERE b.blocked_at >= $1
        ORDER BY b.hit_count DESC
        LIMIT $2
        """,
        {"since": "window:7d", "limit": "int:50"},
    ),
    # -- Vulnerabilities -----------------------------------------------------
    Query(
        "open_findings",
        "Open vulnerability findings, ranked by computed priority (not by CVSS).",
        """
        SELECT f.id, f.cve, f.severity, f.cvss, f.epss, f.kev, f.priority,
               f.package, f.installed_version, f.fixed_version, f.location,
               a.name AS asset, a.is_internet_exposed, a.criticality,
               f.first_seen, (now() - f.first_seen) AS age
        FROM findings f
        LEFT JOIN assets a ON a.id = f.asset_id
        WHERE f.status = 'open'
        ORDER BY f.priority DESC, f.cvss DESC NULLS LAST
        LIMIT $1
        """,
        {"limit": "int:50"},
    ),
    Query(
        "kev_findings",
        "Open findings that are in the CISA Known Exploited Vulnerabilities catalog.",
        """
        SELECT f.id, f.cve, f.cvss, f.epss, f.priority, f.package,
               f.installed_version, f.fixed_version, a.name AS asset,
               f.first_seen, (now() - f.first_seen) AS age
        FROM findings f
        LEFT JOIN assets a ON a.id = f.asset_id
        WHERE f.status = 'open' AND f.kev
        ORDER BY f.priority DESC
        """,
    ),
    Query(
        "findings_for_asset",
        "All open findings on one asset — used for exposure crossing.",
        """
        SELECT f.id, f.cve, f.severity, f.cvss, f.epss, f.kev, f.priority,
               f.package, f.installed_version, f.fixed_version, f.location, f.first_seen
        FROM findings f
        WHERE f.asset_id = $1 AND f.status = 'open'
        ORDER BY f.priority DESC
        """,
        {"asset_id": "int"},
    ),
    Query(
        "vulnerability_burndown",
        "Open findings by severity and age bucket. The number that should be falling.",
        """
        SELECT severity,
               count(*) AS open_count,
               count(*) FILTER (WHERE first_seen >= now() - interval '7 days')  AS age_lt_7d,
               count(*) FILTER (WHERE first_seen <  now() - interval '30 days') AS age_gt_30d,
               round(avg(EXTRACT(EPOCH FROM (now() - first_seen)) / 86400)::numeric, 1) AS avg_age_days
        FROM findings
        WHERE status = 'open'
        GROUP BY severity
        """,
    ),
    # -- Patching ------------------------------------------------------------
    Query(
        "patch_plans",
        "Patch plans by state.",
        """
        SELECT p.id, p.plan_id, p.status, p.risk_level, p.requires_reboot,
               p.estimated_downtime_s, a.name AS asset, p.finding_ids,
               p.created_at, p.approved_by, p.approved_at
        FROM patch_plans p
        LEFT JOIN assets a ON a.id = p.asset_id
        WHERE ($1::text IS NULL OR p.status = $1)
        ORDER BY p.created_at DESC
        LIMIT $2
        """,
        {"status": "text:", "limit": "int:25"},
    ),
    Query(
        "patch_steps",
        "Every step of one patch execution, in order. Read this to diagnose a failure.",
        """
        SELECT s.phase, s.step_id, s.argv, s.exit_code, s.duration_ms,
               s.started_at, s.finished_at,
               left(s.stderr, 2000) AS stderr_head
        FROM patch_steps s
        WHERE s.execution_id = $1
        ORDER BY s.started_at
        """,
        {"execution_id": "int"},
    ),
    Query(
        "restore_points",
        "Available restore points, newest first.",
        """
        SELECT r.id, r.path, r.size_bytes, a.name AS asset, r.plan_id,
               r.created_at, r.verified_at, r.retention_hold,
               (now() - r.created_at) AS age
        FROM restore_points r
        LEFT JOIN assets a ON a.id = r.asset_id
        ORDER BY r.created_at DESC
        LIMIT $1
        """,
        {"limit": "int:30"},
    ),
    Query(
        "restore_drill_items",
        "Per-artifact verdicts of one restore drill (Funcționalitatea 07) — "
        "read this to see WHICH artifact failed and why, not just that the "
        "drill as a whole did.",
        """
        SELECT i.artifact, i.is_archive, i.sha256_ok, i.verdict, i.detail
        FROM restore_drill_items i
        WHERE i.drill_id = $1
        ORDER BY i.id
        """,
        {"drill_id": "int"},
    ),
    # -- Assets, health, capacity -------------------------------------------
    Query(
        "assets",
        "The asset inventory.",
        """
        SELECT id, name, kind, bind_addr, port, is_internet_exposed, criticality,
               systemd_unit, container_image, webroot, repo_path, stack,
               protected, confirmed_by_operator, last_seen
        FROM assets
        ORDER BY is_internet_exposed DESC, criticality DESC, name
        """,
    ),
    Query(
        "service_health",
        "Latest health sample per asset.",
        """
        SELECT DISTINCT ON (h.asset_id)
               a.name AS asset, h.status, h.latency_ms, h.http_status, h.error, h.ts
        FROM health_samples h
        JOIN assets a ON a.id = h.asset_id
        WHERE h.ts >= now() - interval '10 minutes'
        ORDER BY h.asset_id, h.ts DESC
        """,
    ),
    Query(
        "availability",
        "Uptime percentage per asset over a window.",
        """
        SELECT a.name AS asset,
               round(100.0 * sum(r.up_samples) / NULLIF(sum(r.samples), 0), 3) AS uptime_pct,
               sum(r.samples) AS samples,
               sum(r.down_samples) AS down_samples,
               round(avg(r.p95_latency_ms)::numeric, 1) AS avg_p95_latency_ms,
               sum(r.incidents_count) AS incidents
        FROM availability_rollup r
        JOIN assets a ON a.id = r.asset_id
        WHERE r.day >= (now() - $1::interval)::date
        GROUP BY a.name
        ORDER BY uptime_pct
        """,
        {"since": "window:30d"},
    ),
    Query(
        "capacity_trend",
        "Hourly capacity samples — CPU, memory, disk.",
        """
        SELECT date_trunc('hour', ts) AS hour,
               round(avg(cpu_pct)::numeric, 1)        AS cpu_pct_avg,
               max(cpu_pct)                            AS cpu_pct_max,
               round(avg(mem_available_mb)::numeric, 0) AS mem_available_mb_avg,
               min(mem_available_mb)                   AS mem_available_mb_min,
               round(avg(disk_used_pct)::numeric, 1)  AS disk_used_pct_avg,
               max(conn_count)                         AS conn_count_max
        FROM capacity_samples
        WHERE ts >= $1
        GROUP BY 1
        ORDER BY 1 DESC
        LIMIT 720
        """,
        {"since": "window:24h"},
    ),
    # -- Events and traffic --------------------------------------------------
    Query(
        "traffic_vs_baseline",
        "Recent traffic per asset against the hour-of-week baseline.",
        """
        SELECT a.name AS asset, r.bucket, r.n AS requests,
               b.median AS baseline_median, b.mad AS baseline_mad, b.warm AS baseline_warm,
               CASE WHEN b.mad IS NULL OR b.mad = 0 THEN NULL
                    ELSE round((0.6745 * (r.n - b.median) / b.mad)::numeric, 2)
               END AS robust_z
        FROM event_rollup_1h r
        JOIN assets a ON a.id = r.asset_id
        LEFT JOIN baselines b
               ON b.asset_id = r.asset_id
              AND b.metric = 'requests_per_hour'
              AND b.hour_of_week = EXTRACT(DOW FROM r.bucket) * 24
                                 + EXTRACT(HOUR FROM r.bucket)
        WHERE r.bucket >= $1
        ORDER BY r.bucket DESC, a.name
        LIMIT 500
        """,
        {"since": "window:24h"},
    ),
    Query(
        "top_targeted_paths",
        "Most requested paths that produced detections — what attackers are looking for.",
        """
        SELECT e.http_path, count(*) AS hits, count(DISTINCT e.src_ip) AS uniq_sources,
               array_agg(DISTINCT e.http_status) AS statuses
        FROM raw_events e
        WHERE e.ts >= $1 AND e.http_path IS NOT NULL AND e.http_status >= 400
        GROUP BY e.http_path
        ORDER BY hits DESC
        LIMIT $2
        """,
        {"since": "window:24h", "limit": "int:30"},
    ),
    Query(
        "detections_by_rule",
        "Detection counts per rule — the first place to look for a noisy rule.",
        """
        SELECT rule_id, rule_family, severity,
               count(*) AS n, count(DISTINCT actor_key) AS uniq_actors
        FROM detections
        WHERE ts >= $1
        GROUP BY rule_id, rule_family, severity
        ORDER BY n DESC
        LIMIT $2
        """,
        {"since": "window:24h", "limit": "int:40"},
    ),
    # -- Prediction calibration ---------------------------------------------
    Query(
        "prediction_calibration",
        "Scored predictions and the Brier score. Honest performance, not claimed.",
        """
        SELECT count(*) AS scored,
               count(*) FILTER (WHERE outcome) AS came_true,
               round(avg(CASE WHEN outcome THEN 1 ELSE 0 END)::numeric, 3) AS hit_rate,
               round(avg(power(probability - CASE WHEN outcome THEN 1 ELSE 0 END, 2))::numeric, 4)
                   AS brier_score
        FROM predictions
        WHERE scored_at IS NOT NULL AND made_at >= $1
        """,
        {"since": "window:30d"},
    ),
    # -- Sentinel's own health ----------------------------------------------
    Query(
        "ai_budget",
        "AI spend today and this month.",
        """
        SELECT
          round(sum(cost_usd) FILTER (WHERE at >= date_trunc('day', now()))::numeric, 4)   AS today_usd,
          round(sum(cost_usd) FILTER (WHERE at >= date_trunc('month', now()))::numeric, 4) AS month_usd,
          count(*) FILTER (WHERE at >= date_trunc('day', now()))                            AS calls_today,
          sum(input_tokens)  FILTER (WHERE at >= date_trunc('day', now()))                  AS input_tokens_today,
          sum(output_tokens) FILTER (WHERE at >= date_trunc('day', now()))                  AS output_tokens_today
        FROM ai_usage
        """,
    ),
    Query(
        "ai_queue",
        "AI job queue depth by state — a growing queue means the worker is stuck.",
        """
        SELECT kind, state, count(*) AS n, min(enqueued_at) AS oldest
        FROM ai_jobs
        GROUP BY kind, state
        ORDER BY state, kind
        """,
    ),
    Query(
        "audit_recent",
        "Recent privileged operations from the hash-chained audit log.",
        """
        SELECT id, at, actor, operation, target, result, source
        FROM audit_log
        WHERE at >= $1
        ORDER BY at DESC
        LIMIT $2
        """,
        {"since": "window:24h", "limit": "int:100"},
    ),
]

BY_NAME = {q.name: q for q in QUERIES}


# ---------------------------------------------------------------------------
def _coerce(spec: str, raw: str | None) -> Any:
    kind, _, default = spec.partition(":")
    value = raw if raw is not None else (default or None)
    if value in (None, ""):
        if kind == "text":
            return None
        c.die(f"missing required parameter (type {kind})")
    if kind == "int":
        try:
            return int(value)  # type: ignore[arg-type]
        except ValueError:
            c.die(f"expected an integer, got {value!r}")
    if kind == "window":
        return c.since(str(value))
    return str(value)


def list_catalog() -> None:
    print("Named queries. Run: sentinel_query.py <name> [--param key=value ...]\n")
    width = max(len(q.name) for q in QUERIES)
    for q in QUERIES:
        params = ", ".join(f"{k}={v}" for k, v in q.params.items()) or "—"
        print(f"  {q.name.ljust(width)}  {q.description}")
        print(f"  {' ' * width}  params: {params}\n")


async def _execute(query: Query, values: list[Any], fmt: str) -> None:
    conn = await c.connect()
    try:
        rows = await conn.fetch(query.sql, *values)
    finally:
        await conn.close()
    c.emit(c.rows_to_dicts(rows), fmt)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("query", nargs="?", help="query name; omit to list the catalog")
    parser.add_argument("--param", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("-h", "--help", action="store_true")
    c.add_format_arg(parser)
    args = parser.parse_args()

    if args.query is None:
        list_catalog()
        return

    query = BY_NAME.get(args.query)
    if query is None:
        c.die(f"unknown query {args.query!r}. Run with no arguments to list the catalog.")

    if args.help:
        print(f"{query.name}\n  {query.description}\n")
        for k, v in query.params.items():
            kind, _, default = v.partition(":")
            print(f"  --param {k}=<{kind}>" + (f"   (default: {default})" if default else ""))
        print(f"\nSQL:\n{query.sql}")
        return

    supplied: dict[str, str] = {}
    for item in args.param:
        if "=" not in item:
            c.die(f"malformed --param {item!r}; expected key=value")
        key, _, value = item.partition("=")
        if key not in query.params:
            c.die(f"unknown parameter {key!r} for {query.name}. Allowed: {list(query.params)}")
        supplied[key] = value

    values = [_coerce(spec, supplied.get(name)) for name, spec in query.params.items()]
    c.run(_execute(query, values, args.format))


if __name__ == "__main__":
    c.main_wrapper(main)
