"""Patch plans, executions, steps and restore points.

Every write here happens BEFORE the thing it describes is attempted, not after.
That ordering is the whole point: a crash in the middle of applying a patch must
leave a complete record of what had already run, because the operator's first
question will be "what state is the machine in?" — and an audit trail written
afterwards cannot answer it.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sentinel.db.engine import Database

# A plan that has not been approved and applied within this window is stale: the
# installed versions it was written against have probably moved on.
PLAN_TTL_HOURS = 72


@dataclass
class PlanRow:
    id: int
    plan_id: uuid.UUID
    plan_hash: str
    plan: dict[str, Any]
    status: str
    risk_level: str | None
    requires_reboot: bool
    reversible: bool
    estimated_downtime_s: int | None
    asset_id: int | None
    created_at: datetime
    approved_by: str | None
    approved_at: datetime | None
    validation_errors: Any


_PLAN_COLS = """
    id, plan_id, plan_hash, plan, status, risk_level, requires_reboot, reversible,
    estimated_downtime_s, asset_id, created_at, approved_by, approved_at, validation_errors
"""


def _plan(row: Any) -> PlanRow:
    d = dict(row)
    for key in ("plan", "validation_errors"):
        if isinstance(d.get(key), str):
            d[key] = json.loads(d[key])
    return PlanRow(**{k: d[k] for k in PlanRow.__dataclass_fields__})


# --- plans ------------------------------------------------------------------
async def store_plan(db: Database, *, plan: dict[str, Any], plan_hash: str,
                     status: str, asset_id: int | None = None,
                     finding_ids: list[int] | None = None,
                     validation_errors: list[dict[str, str]] | None = None,
                     generated_by: str = "manual", model: str | None = None) -> int:
    risk = plan.get("risk") or {}
    return int(await db.fetchval(
        """
        INSERT INTO patch_plans
            (plan_id, plan_hash, plan, asset_id, finding_ids, status, risk_level,
             blast_radius, requires_reboot, reversible, estimated_downtime_s,
             confidence, validation_errors, generated_by, model)
        VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14, $15)
        RETURNING id
        """,
        uuid.uuid4(), plan_hash, json.dumps(plan), asset_id, finding_ids or [],
        status, risk.get("level"), risk.get("blast_radius"),
        bool(risk.get("requires_reboot", False)), bool(risk.get("reversible", True)),
        risk.get("estimated_downtime_s"), risk.get("confidence"),
        json.dumps(validation_errors) if validation_errors else None,
        generated_by, model))


async def get_plan(db: Database, plan_db_id: int) -> PlanRow | None:
    row = await db.fetchrow(f"SELECT {_PLAN_COLS} FROM patch_plans WHERE id = $1", plan_db_id)
    return _plan(row) if row else None


async def list_plans(db: Database, *, limit: int = 50) -> list[PlanRow]:
    rows = await db.fetch(
        f"SELECT {_PLAN_COLS} FROM patch_plans ORDER BY created_at DESC LIMIT $1", limit)
    return [_plan(r) for r in rows]


async def approve_plan(db: Database, plan_db_id: int, *, by: str, expected_hash: str) -> bool:
    """Approve — but only if the plan is byte-identical to what was shown.

    The hash is checked inside the UPDATE rather than read-then-write: if the
    plan were regenerated between the operator reading it and tapping approve,
    a check-then-act would approve a plan nobody had seen.
    """
    row = await db.fetchrow(
        """
        UPDATE patch_plans SET status = 'approved', approved_by = $2, approved_at = now()
        WHERE id = $1 AND plan_hash = $3 AND status = 'validated'
        RETURNING id
        """,
        plan_db_id, by, expected_hash)
    return row is not None


async def reject_plan(db: Database, plan_db_id: int, *, by: str, reason: str) -> None:
    await db.execute(
        "UPDATE patch_plans SET status = 'rejected', rejected_by = $2, rejected_reason = $3 "
        "WHERE id = $1 AND status IN ('validated','approved','draft')",
        plan_db_id, by, reason[:500])


async def set_plan_status(db: Database, plan_db_id: int, status: str) -> None:
    await db.execute("UPDATE patch_plans SET status = $2 WHERE id = $1", plan_db_id, status)


async def expire_stale_plans(db: Database) -> int:
    rows = await db.fetch(
        """
        UPDATE patch_plans SET status = 'expired'
        WHERE status IN ('validated', 'approved')
          AND created_at < now() - make_interval(hours => $1)
        RETURNING id
        """,
        PLAN_TTL_HOURS)
    return len(rows)


# --- executions -------------------------------------------------------------
async def start_execution(db: Database, plan_db_id: int, *, mode: str,
                          triggered_by: str) -> int:
    return int(await db.fetchval(
        "INSERT INTO patch_executions (plan_id, mode, triggered_by) VALUES ($1,$2,$3) "
        "RETURNING id",
        plan_db_id, mode, triggered_by))


async def finish_execution(db: Database, execution_id: int, *, status: str,
                           result: dict[str, Any] | None = None,
                           error: str | None = None,
                           rollback_reason: str | None = None,
                           post_ok: bool | None = None) -> None:
    await db.execute(
        """
        UPDATE patch_executions SET status = $2, finished_at = now(),
            duration_ms = (extract(epoch from (now() - started_at)) * 1000)::int,
            result = $3::jsonb, error = $4, rollback_reason = $5,
            rollback_at = CASE WHEN $5 IS NULL THEN rollback_at ELSE now() END,
            post_verification_passed = $6
        WHERE id = $1
        """,
        execution_id, status, json.dumps(result or {}), error, rollback_reason, post_ok)


async def attach_restore_point(db: Database, execution_id: int, restore_point_id: int) -> None:
    await db.execute("UPDATE patch_executions SET restore_point_id = $2 WHERE id = $1",
                     execution_id, restore_point_id)


# --- steps ------------------------------------------------------------------
async def begin_step(db: Database, execution_id: int, *, phase: str, step_id: str,
                     seq: int, argv: list[str], cwd: str | None = None) -> int:
    """Record a step BEFORE running it. A crash mid-command then leaves a row in
    'running' — which is exactly the state the operator needs to know about."""
    return int(await db.fetchval(
        """
        INSERT INTO patch_steps (execution_id, phase, step_id, seq, argv, cwd)
        VALUES ($1, $2, $3, $4, $5, $6) RETURNING id
        """,
        execution_id, phase, step_id, seq, argv, cwd))


async def end_step(db: Database, step_row_id: int, *, status: str,
                   exit_code: int | None = None, stdout: str = "", stderr: str = "",
                   timed_out: bool = False) -> None:
    await db.execute(
        """
        UPDATE patch_steps SET status = $2, exit_code = $3,
            stdout = $4, stderr = $5, timed_out = $6, finished_at = now(),
            duration_ms = (extract(epoch from (now() - started_at)) * 1000)::int
        WHERE id = $1
        """,
        step_row_id, status, exit_code, stdout[:20000], stderr[:20000], timed_out)


async def execution_steps(db: Database, execution_id: int) -> list[dict[str, Any]]:
    rows = await db.fetch(
        "SELECT phase, step_id, seq, argv, status, exit_code, duration_ms, "
        "       stdout, stderr, timed_out, started_at "
        "FROM patch_steps WHERE execution_id = $1 ORDER BY seq", execution_id)
    return [dict(r) for r in rows]


async def get_execution(db: Database, execution_id: int) -> dict[str, Any] | None:
    row = await db.fetchrow(
        "SELECT id, plan_id, mode, status, started_at, finished_at, duration_ms, "
        "       restore_point_id, triggered_by, rollback_reason, error, "
        "       post_verification_passed FROM patch_executions WHERE id = $1",
        execution_id)
    return dict(row) if row else None


# --- restore points ---------------------------------------------------------
async def record_restore_point(db: Database, *, path: str, manifest: dict[str, Any],
                               size_bytes: int, asset_id: int | None,
                               plan_db_id: int | None) -> int:
    return int(await db.fetchval(
        """
        INSERT INTO restore_points (asset_id, plan_id, path, manifest, size_bytes)
        VALUES ($1, $2, $3, $4::jsonb, $5) RETURNING id
        """,
        asset_id, plan_db_id, path, json.dumps(manifest), size_bytes))


async def mark_verified(db: Database, restore_point_id: int, *, error: str | None) -> None:
    await db.execute(
        "UPDATE restore_points SET verified_at = now(), verify_error = $2 WHERE id = $1",
        restore_point_id, error)


async def list_restore_points(db: Database, *, limit: int = 50) -> list[dict[str, Any]]:
    rows = await db.fetch(
        """
        SELECT r.id, r.path, r.size_bytes, r.created_at, r.verified_at, r.verify_error,
               r.restored_at, r.retention_hold, a.name AS asset_name
        FROM restore_points r LEFT JOIN assets a ON a.id = r.asset_id
        WHERE r.deleted_at IS NULL ORDER BY r.created_at DESC LIMIT $1
        """,
        limit)
    return [dict(r) for r in rows]


async def prunable_restore_points(db: Database, *, keep_count: int,
                                  keep_days: int) -> list[dict[str, Any]]:
    """Points that may be deleted.

    Three things are never pruned, and the third is the one that matters: the
    most recent successful point PER ASSET, however old. Retention that can
    delete the only way back for a machine nobody has patched in months is not
    retention, it is data loss on a timer.
    """
    rows = await db.fetch(
        """
        WITH ranked AS (
            SELECT id, asset_id, created_at, retention_hold,
                   row_number() OVER (ORDER BY created_at DESC) AS overall_rank,
                   row_number() OVER (PARTITION BY asset_id ORDER BY created_at DESC) AS per_asset_rank
            FROM restore_points
            WHERE deleted_at IS NULL AND verify_error IS NULL
        )
        SELECT id, created_at FROM ranked
        WHERE NOT retention_hold
          AND overall_rank > $1
          AND created_at < now() - make_interval(days => $2)
          AND per_asset_rank > 1
        ORDER BY created_at
        """,
        keep_count, keep_days)
    return [dict(r) for r in rows]


async def mark_deleted(db: Database, restore_point_id: int) -> None:
    await db.execute("UPDATE restore_points SET deleted_at = now() WHERE id = $1",
                     restore_point_id)
