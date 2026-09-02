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
    # Implicit `False`, ca fiecare `PlanRow(...)` scris deja în teste (dinainte
    # de Funcționalitatea 08) să rămână valid fără să numească un câmp de care
    # nu-i pasă.
    proposed_by_window: bool = False


_PLAN_COLS = """
    id, plan_id, plan_hash, plan, status, risk_level, requires_reboot, reversible,
    estimated_downtime_s, asset_id, created_at, approved_by, approved_at, validation_errors,
    proposed_by_window
"""


def _plan(row: Any) -> PlanRow:
    d = dict(row)
    for key in ("plan", "validation_errors"):
        if isinstance(d.get(key), str):
            d[key] = json.loads(d[key])
    # `.get(k, False)` only for `proposed_by_window`: a real row from
    # `_PLAN_COLS` always carries it, but plenty of tests build a bare dict by
    # hand to stand in for a row, predating Funcționalitatea 08 — those must
    # keep meaning "not released by the window" rather than fail to construct.
    return PlanRow(**{k: d.get(k, False) if k == "proposed_by_window" else d[k]
                      for k in PlanRow.__dataclass_fields__})


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


# --- push queue -------------------------------------------------------------
#
# The bot claims rows from these two queries and stamps them. Everything else
# about patching is pull-based (the operator asks); these are the only places
# the system speaks first, so both are deliberately narrow.
async def unnotified_plans(db: Database, *, limit: int = 3) -> list[PlanRow]:
    """Validated plans the operator has never been shown.

    `limit` is small on purpose. A scan that turns up eight exploited CVEs at
    3 a.m. should not produce eight approval prompts stacked on a phone — the
    rest are still listed by `/patches`, and the next pass will offer them.

    A plan drafted by the automatic planner (`generated_by = 'ai'`) is held
    back from this fast, unconditional channel until `sentinel-patch-window`
    (Funcționalitatea 08) has released it — `proposed_by_window`. Without this,
    the window's eligibility gate (întoarcere dovedită prin exercițiul de
    restaurare) would be decorative: every AI-drafted plan already reaches
    `status = 'validated'` the moment it is generated, and this loop runs every
    15 seconds, so it would offer the plan long before the weekly window ever
    got a say. A plan from any OTHER origin (today: none, but the column exists
    for a future manual-generation path) is unaffected — the split is about the
    risk of unattended model output, not about patching in general.

    The recency filter is skipped once a plan is window-released, for the same
    reason: the window runs weekly, `PLAN_TTL_HOURS` is 72, so a plan old
    enough to need the window's slower cadence would otherwise fall outside its
    own release window the moment the window finally clears it.
    """
    rows = await db.fetch(
        f"""
        SELECT {_PLAN_COLS} FROM patch_plans
        WHERE notified_at IS NULL AND status = 'validated'
          AND (created_at > now() - make_interval(hours => $1) OR proposed_by_window)
          AND (generated_by <> 'ai' OR proposed_by_window)
        ORDER BY created_at
        LIMIT $2
        """,
        PLAN_TTL_HOURS, limit)
    return [_plan(r) for r in rows]


async def mark_plan_notified(db: Database, plan_db_id: int) -> None:
    await db.execute("UPDATE patch_plans SET notified_at = now() WHERE id = $1", plan_db_id)


async def unnotified_executions(db: Database, *, limit: int = 5) -> list[dict[str, Any]]:
    """Finished executions whose outcome has not been reported.

    Telegram-triggered runs are excluded: `on_dry_run` already edits its own
    message with the result, and announcing it a second time would train the
    operator to ignore the announcements.
    """
    rows = await db.fetch(
        """
        SELECT e.id, e.plan_id, e.mode, e.status, e.duration_ms, e.error,
               e.triggered_by, e.rollback_reason
        FROM patch_executions e
        WHERE e.notified_at IS NULL AND e.finished_at IS NOT NULL
          AND e.triggered_by NOT LIKE 'telegram:%'
        ORDER BY e.finished_at
        LIMIT $1
        """,
        limit)
    return [dict(r) for r in rows]


async def mark_execution_notified(db: Database, execution_id: int) -> None:
    await db.execute("UPDATE patch_executions SET notified_at = now() WHERE id = $1",
                     execution_id)


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
    # Every parameter is cast explicitly. $5 in particular: its only other use is
    # `rollback_reason = $5`, and Postgres resolves an UPDATE SET assignment
    # AFTER parameter type inference — so the bare `$5 IS NULL` left it with no
    # type at all and the statement failed to prepare. Without the cast this
    # errors on every call, whatever the values are.
    await db.execute(
        """
        UPDATE patch_executions SET status = $2::text, finished_at = now(),
            duration_ms = (extract(epoch from (now() - started_at)) * 1000)::int,
            result = $3::jsonb, error = $4::text, rollback_reason = $5::text,
            rollback_at = CASE WHEN $5::text IS NULL THEN rollback_at ELSE now() END,
            post_verification_passed = $6::boolean
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


# --- restore drills (Funcționalitatea 07) ------------------------------------
async def pick_restore_point_for_drill(db: Database) -> dict[str, Any] | None:
    """Punctul de restaurare cel mai potrivit pentru drill-ul din luna asta.

    Cel niciodată testat trece înaintea celui testat demult, iar între doi
    niciodată testați câștigă cel mai vechi — altfel un punct nou, creat ieri,
    ar sări în față și unul vechi de un an n-ar mai ajunge testat niciodată.
    Un singur punct pe rulare: exercițiul cere lunar, deci acoperirea vine din
    rotație, nu dintr-o singură trecere.
    """
    row = await db.fetchrow(
        """
        SELECT rp.id, rp.path, rp.manifest, rp.asset_id, rp.created_at,
               ld.last_drill_at
        FROM restore_points rp
        LEFT JOIN LATERAL (
            SELECT max(performed_at) AS last_drill_at
            FROM restore_drills d WHERE d.restore_point_id = rp.id
        ) ld ON true
        WHERE rp.deleted_at IS NULL
        ORDER BY ld.last_drill_at ASC NULLS FIRST, rp.created_at ASC
        LIMIT 1
        """)
    if row is None:
        return None
    d = dict(row)
    if isinstance(d.get("manifest"), str):
        d["manifest"] = json.loads(d["manifest"])
    return d


async def any_live_restore_point(db: Database) -> bool:
    return bool(await db.fetchval(
        "SELECT EXISTS(SELECT 1 FROM restore_points WHERE deleted_at IS NULL)"))


async def record_drill(db: Database, *, restore_point_id: int | None,
                       automated: bool, performed_by: str, succeeded: bool,
                       duration_ms: int | None, notes: str,
                       result: dict[str, Any] | None,
                       items: list[dict[str, Any]]) -> int:
    """Scrie drill-ul ȘI artefactele lui într-o singură tranzacție.

    Un drill fără artefactele lui e o afirmație fără dovadă: rândul-cap ar
    spune «reușit» sau «eșuat» și nimic n-ar mai spune despre CE anume a fost
    verificat — exact separarea pe care 08 trebuie s-o poată citi.
    """
    async with db.transaction() as conn:
        drill_id = int(await conn.fetchval(
            """
            INSERT INTO restore_drills
                (restore_point_id, automated, performed_by, succeeded,
                 duration_ms, notes, result)
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
            RETURNING id
            """,
            restore_point_id, automated, performed_by, succeeded,
            duration_ms, notes, json.dumps(result or {})))
        for item in items:
            await conn.execute(
                """
                INSERT INTO restore_drill_items
                    (drill_id, artifact, is_archive, sha256_ok, verdict, detail)
                VALUES ($1, $2, $3, $4, $5, $6)
                """,
                drill_id, str(item.get("artifact", "")),
                bool(item.get("is_archive")), bool(item.get("sha256_ok")),
                str(item.get("verdict")), str(item.get("detail", ""))[:2000])
    return drill_id


async def live_restore_points_with_last_drill(db: Database) -> list[dict[str, Any]]:
    """Fiecare punct viu, cu ultimul lui drill AUTOMAT — sau `None` dacă n-a
    rulat niciodată niciunul. Sursa pentru verificarea de sănătate: unul câte
    unul, ca un punct stricat să nu-l ascundă pe cel bun de lângă el.

    Vârsta ultimului drill se calculează AICI, cu ceasul bazei — nu în Python,
    cu ceasul gazdei care rulează verificarea — din același motiv ca la
    `check_last_scan`: un decalaj de ceas ar apărea ca o vechime inventată.
    """
    rows = await db.fetch(
        """
        SELECT rp.id, rp.asset_id, rp.created_at, a.name AS asset_name,
               ld.id AS drill_id, ld.performed_at, ld.succeeded, ld.notes, ld.result,
               EXTRACT(EPOCH FROM (now() - ld.performed_at))/60 AS drill_age_min
        FROM restore_points rp
        LEFT JOIN assets a ON a.id = rp.asset_id
        LEFT JOIN LATERAL (
            SELECT id, performed_at, succeeded, notes, result
            FROM restore_drills d
            WHERE d.restore_point_id = rp.id AND d.automated
            ORDER BY performed_at DESC LIMIT 1
        ) ld ON true
        WHERE rp.deleted_at IS NULL
        ORDER BY rp.created_at
        """)
    out = []
    for row in rows:
        d = dict(row)
        if isinstance(d.get("result"), str):
            d["result"] = json.loads(d["result"])
        out.append(d)
    return out


# --- patch window (Funcționalitatea 08) --------------------------------------
async def window_candidate_plans(db: Database, *, limit: int = 10) -> list[PlanRow]:
    """Planuri validate pe care fereastra nu le-a considerat încă „eliberate".

    Ordonate de la cel mai vechi: un plan care așteaptă de o săptămână are
    prioritate față de unul generat aseară — altfel unul nou ar sări mereu
    înainte și cele vechi n-ar mai ajunge niciodată evaluate.
    """
    rows = await db.fetch(
        f"""
        SELECT {_PLAN_COLS} FROM patch_plans
        WHERE status = 'validated' AND NOT proposed_by_window
        ORDER BY created_at
        LIMIT $1
        """,
        limit)
    return [_plan(r) for r in rows]


async def outstanding_window_plan(db: Database) -> dict[str, Any] | None:
    """Un plan deja eliberat de fereastră care încă așteaptă o decizie.

    Cât timp există unul, fereastra nu mai eliberează altul — nu fiindcă
    două propuneri simultane ar strica ceva prin ele însele, ci ca operatorul
    să nu găsească mai multe decizii automate stivuite atunci când se
    întoarce dintr-o săptămână ocupată.
    """
    row = await db.fetchrow(
        """
        SELECT id, created_at FROM patch_plans
        WHERE proposed_by_window AND status = 'validated'
        ORDER BY created_at LIMIT 1
        """)
    return dict(row) if row else None


async def mark_proposed_by_window(db: Database, plan_db_id: int) -> None:
    await db.execute(
        "UPDATE patch_plans SET proposed_by_window = true WHERE id = $1", plan_db_id)


async def window_halt(db: Database) -> dict[str, Any] | None:
    """Execuția care a oprit fereastra, dacă vreuna dintre propunerile ei a
    eșuat la aplicare — sau `None` dacă fereastra poate propune în continuare.

    Cea mai VECHE execuție eșuată, nu cea mai nouă: „oprire la primul eșec"
    înseamnă că raportul arată planul care a declanșat oprirea, nu ultimul din
    listă. Recalculată la fiecare apel, din `patch_executions` +
    `patch_plans.proposed_by_window` — nicio stare separată de „oprit" nu se
    ține minte, ca să nu existe două surse de adevăr care se pot contrazice.
    """
    row = await db.fetchrow(
        """
        SELECT e.id AS execution_id, e.plan_id, e.status, e.finished_at
        FROM patch_executions e
        JOIN patch_plans p ON p.id = e.plan_id
        WHERE p.proposed_by_window AND e.mode = 'apply'
          AND e.status IN ('failed', 'rolled_back', 'rollback_failed')
        ORDER BY e.finished_at ASC
        LIMIT 1
        """)
    return dict(row) if row else None


async def latest_archive_drill_summary(db: Database) -> dict[str, Any] | None:
    """Ce arată, ÎN ANSAMBLU, cel mai recent exercițiu de restaurare care a
    atins măcar o arhivă (`is_archive`) — indiferent de punctul de restaurare
    din care venea. `None` dacă niciun exercițiu n-a atins vreodată o arhivă.

    Agregată pe TOATE artefactele-arhivă din acel exercițiu, nu pe unul
    singur: un exercițiu care a extras două arhive, una bună și una coruptă,
    nu are voie să raporteze doar partea bună — vezi
    `restore_drill.py`, aceeași regulă la nivel de punct.
    """
    row = await db.fetchrow(
        """
        WITH latest AS (
            SELECT d.id, d.performed_at
            FROM restore_drills d
            JOIN restore_drill_items i ON i.drill_id = d.id AND i.is_archive
            GROUP BY d.id, d.performed_at
            ORDER BY d.performed_at DESC
            LIMIT 1
        )
        SELECT l.performed_at,
               EXTRACT(EPOCH FROM (now() - l.performed_at)) / 86400 AS age_days,
               bool_or(i.verdict IN ('corrupt', 'structure_mismatch')) AS any_bad,
               bool_and(i.verdict = 'restorable_verified') AS all_good
        FROM latest l
        JOIN restore_drill_items i ON i.drill_id = l.id AND i.is_archive
        GROUP BY l.performed_at
        """)
    return dict(row) if row else None


async def record_window_run(db: Database, *, candidates: int,
                            proposed_plan_id: int | None, halted: bool,
                            detail: str, skipped: list[dict[str, Any]]) -> int:
    """Un rând PE RULARE, indiferent de rezultat — vezi migrația 0043 pentru
    motivul separării de «niciodată rulat»."""
    return int(await db.fetchval(
        """
        INSERT INTO patch_window_runs
            (candidates, proposed_plan_id, halted, detail, skipped)
        VALUES ($1, $2, $3, $4, $5::jsonb)
        RETURNING id
        """,
        candidates, proposed_plan_id, halted, detail[:2000], json.dumps(skipped)))


async def last_window_run(db: Database) -> dict[str, Any] | None:
    row = await db.fetchrow(
        """
        SELECT id, ran_at, candidates, proposed_plan_id, halted, detail, skipped
        FROM patch_window_runs ORDER BY ran_at DESC LIMIT 1
        """)
    if row is None:
        return None
    d = dict(row)
    if isinstance(d.get("skipped"), str):
        d["skipped"] = json.loads(d["skipped"])
    return d
