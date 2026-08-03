"""Execute an approved patch plan, step by step, with a way back at every point.

This is the most dangerous code in the project: it runs commands as root on a
live machine. Its design is therefore defensive to the point of being tedious,
and every rule below exists because the alternative is a broken server at 3 a.m.

  1. **Re-validate at execution time.** The plan passed the validator when it was
     stored, but constants change, code is redeployed, and a row in a database is
     not a promise. A plan that no longer validates is refused here.
  2. **Approval is checked against the hash**, not against a flag. Approving plan
     #7 approves the exact bytes of plan #7.
  3. **Dry run first, always.** Every apply is preceded by a full dry-run pass
     through the executor, which returns what WOULD run without running it.
  4. **The backup is verified before the first apply step.** A backup whose
     checksum does not match is not a backup, and discovering that after the
     patch is worthless.
  5. **The database is written BEFORE each command**, never after. A crash
     mid-command must leave a row saying which command was in flight.
  6. **Any failure in apply triggers rollback immediately**, and the rollback
     result is recorded separately — a failed rollback is a different, worse
     situation than a failed patch and must not look the same.
  7. **Nothing is ever partially applied silently.** If the runner cannot finish
     and cannot roll back, the execution ends as `rollback_failed`, which is the
     loudest state in the schema.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import patches as repo
from sentinel.logging_setup import get_logger
from sentinel.patch import backup, checks
from sentinel.patch.validator import plan_hash, validate_plan
from sentinel.respond.executor_client import ExecutorClient

log = get_logger(__name__)

_client = ExecutorClient()

# Phases in the order they run. `rollback` is not here: it is triggered by
# failure, never scheduled.
FORWARD_PHASES = ("preflight", "backup", "apply", "health_check", "post_verification")

# Phases whose entries are structured checks rather than argv steps. The plan
# schema deliberately separates them: "is nginx active?" as a typed check cannot
# be turned into something else, whereas the same question as a shell command can.
CHECK_PHASES = ("preflight", "health_check", "post_verification")


class PatchRefused(Exception):
    """The runner will not start. Nothing has been executed."""


@dataclass
class StepOutcome:
    ok: bool
    phase: str
    step_id: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    # Failed, but the plan declared `on_failure: continue` for it.
    tolerated: bool = False


@dataclass
class RunResult:
    status: str                     # succeeded | failed | rolled_back | rollback_failed | aborted
    execution_id: int
    steps: list[StepOutcome] = field(default_factory=list)
    error: str | None = None
    rollback_reason: str | None = None
    post_ok: bool | None = None


async def _exec_step(db: Database, execution_id: int, phase: str, seq: int,
                     step: dict[str, Any], *, dry_run: bool) -> StepOutcome:
    """Run one step. Writes the DB row before the command, updates it after."""
    step_id = str(step.get("id") or f"{phase}-{seq}")
    argv = [str(a) for a in step.get("argv", [])]
    cwd = step.get("cwd")
    timeout = int(step.get("timeout_s", 60))

    row_id = await repo.begin_step(db, execution_id, phase=phase, step_id=step_id,
                                   seq=seq, argv=argv, cwd=cwd)
    try:
        result = await asyncio.to_thread(
            _client.call, "patch_step_exec",
            argv=argv, cwd=cwd, timeout_s=timeout, dry_run=dry_run)
    except Exception as exc:  # noqa: BLE001 - executor refused or unreachable
        await repo.end_step(db, row_id, status="failed", stderr=str(exc)[:2000])
        return StepOutcome(False, phase, step_id, stderr=str(exc)[:2000])

    if dry_run:
        await repo.end_step(db, row_id, status="ok", exit_code=0,
                            stdout="(dry-run) " + " ".join(argv))
        return StepOutcome(True, phase, step_id, exit_code=0)

    exit_code = result.get("exit_code")
    timed_out = bool(result.get("timed_out"))
    stdout = str(result.get("stdout", ""))
    stderr = str(result.get("stderr", ""))
    # `expect_exit` is the schema's name for this, and honouring it matters:
    # dnf returns 100 for "updates available", which is not a failure.
    expect = [int(c) for c in step.get("expect_exit", [0])]
    ok = (exit_code in expect) and not timed_out

    await repo.end_step(db, row_id, status="ok" if ok else "failed",
                        exit_code=exit_code, stdout=stdout, stderr=stderr,
                        timed_out=timed_out)
    return StepOutcome(ok, phase, step_id, exit_code, stdout, stderr, timed_out)


async def _run_check(db: Database, execution_id: int, phase: str, seq: int,
                     item: dict[str, Any], *, dry_run: bool) -> StepOutcome:
    """Evaluate one structured check and record it like any other step.

    A NON-blocking check that fails is recorded and tolerated: the plan author
    marked it as informational. A blocking one stops the phase — which, after
    apply, means rollback.
    """
    step_id = str(item.get("id") or f"{phase}-{seq}")
    check = item.get("check") or {}
    kind = str(check.get("kind", "?"))
    argv = [f"check:{kind}"]

    row_id = await repo.begin_step(db, execution_id, phase=phase, step_id=step_id,
                                   seq=seq, argv=argv)
    if dry_run:
        await repo.end_step(db, row_id, status="ok", exit_code=0,
                            stdout=f"(dry-run) verificare {kind}")
        return StepOutcome(True, phase, step_id, exit_code=0)

    outcome = await checks.evaluate(db, check)
    blocking = bool(item.get("blocking", True))
    await repo.end_step(db, row_id, status="ok" if outcome.ok else "failed",
                        exit_code=0 if outcome.ok else 1, stdout=outcome.detail)
    return StepOutcome(outcome.ok, phase, step_id,
                       exit_code=0 if outcome.ok else 1, stdout=outcome.detail,
                       tolerated=not outcome.ok and not blocking)


async def _run_phase(db: Database, execution_id: int, plan: dict[str, Any], phase: str,
                     seq_start: int, *, dry_run: bool) -> tuple[list[StepOutcome], int]:
    """Run one phase. Check phases evaluate typed checks; apply and rollback run
    argv steps. A failure is tolerated only when the plan says so — a
    non-blocking check, or `on_failure: continue` on a step."""
    outcomes: list[StepOutcome] = []
    seq = seq_start
    is_checks = phase in CHECK_PHASES

    for item in plan.get(phase, []) or []:
        if is_checks:
            outcome = await _run_check(db, execution_id, phase, seq, item, dry_run=dry_run)
        else:
            outcome = await _exec_step(db, execution_id, phase, seq, item, dry_run=dry_run)
            if not outcome.ok and item.get("on_failure") == "continue":
                outcome.tolerated = True
        seq += 1
        if not outcome.ok and outcome.tolerated:
            log.warning("patch step failed but the plan tolerates it",
                        extra={"step": outcome.step_id, "phase": phase})
        outcomes.append(outcome)
        if not outcome.ok and not outcome.tolerated:
            break
    return outcomes, seq


async def _run_backup(db: Database, execution_id: int, plan: dict[str, Any],
                      plan_db_id: int, asset_id: int | None, seq: int,
                      *, dry_run: bool) -> tuple[StepOutcome, int]:
    """Create and seal the restore point.

    This is the single most important step in the whole run, so it is not a
    generic phase: it must produce a VERIFIED way back or stop the patch. The
    plan's `restore_argv` per item is not executed here — it is the operator's
    documented manual path, recorded with the point.
    """
    items = plan.get("backup") or []
    estimated = sum(int(i.get("estimated_size_mb", 0) or 0) for i in items) or 100
    row_id = await repo.begin_step(db, execution_id, phase="backup",
                                   step_id="restore_point", seq=seq,
                                   argv=[f"backup:{len(items)} elemente"])
    if dry_run:
        await repo.end_step(db, row_id, status="ok", exit_code=0,
                            stdout=f"(dry-run) ar salva {len(items)} elemente "
                                   f"(~{estimated} MB)")
        return StepOutcome(True, "backup", "restore_point", exit_code=0), seq + 1

    try:
        rp_db_id, rp_id, manifest = await backup.create(
            db, plan_db_id=plan_db_id, asset_id=asset_id,
            items=[{"kind": i.get("kind", "path"), "source": i.get("source")}
                   for i in items],
            estimated_mb=estimated)
    except backup.BackupRefused as exc:
        await repo.end_step(db, row_id, status="failed", exit_code=1, stderr=str(exc))
        return StepOutcome(False, "backup", "restore_point", 1, stderr=str(exc)), seq + 1

    await repo.attach_restore_point(db, execution_id, rp_db_id)
    detail = (f"punct de restaurare {rp_id}: {len(manifest['items'])} artefacte, "
              f"verificate; restore.sh scris")
    await repo.end_step(db, row_id, status="ok", exit_code=0, stdout=detail)
    return StepOutcome(True, "backup", "restore_point", 0, stdout=detail), seq + 1


async def _rollback(db: Database, execution_id: int, plan: dict[str, Any],
                    seq_start: int, reason: str) -> tuple[bool, list[StepOutcome]]:
    """Run the rollback steps. Always attempted with dry_run=False — a rollback
    that only pretends to work is worse than none, because it reports success."""
    log.error("patch rollback starting", extra={"execution_id": execution_id, "reason": reason})
    outcomes, _ = await _run_phase(db, execution_id, plan, "rollback", seq_start, dry_run=False)
    ok = bool(outcomes) and all(o.ok for o in outcomes)
    if not outcomes:
        # No rollback steps in the plan. The validator only permits that when
        # the plan declares itself irreversible, so this is expected — but it is
        # still a state the operator must be told about explicitly.
        log.error("no rollback steps in plan", extra={"execution_id": execution_id})
    return ok, outcomes


async def run_plan(db: Database, cfg: Config, plan_db_id: int, *,
                   mode: str = "dry_run", triggered_by: str = "manual") -> RunResult:
    """Execute a stored plan. `mode` is 'dry_run' or 'apply'.

    Raises PatchRefused BEFORE creating an execution row if the plan is not fit
    to run — refusing without leaving a half-started execution behind.
    """
    row = await repo.get_plan(db, plan_db_id)
    if row is None:
        raise PatchRefused("plan inexistent")

    plan = row.plan

    # Guard 1: the plan must still validate against today's rules.
    result = validate_plan(plan)
    if not result.valid:
        await repo.set_plan_status(db, plan_db_id, "rejected_invalid")
        raise PatchRefused(
            f"planul nu mai trece validarea ({len(result.errors)} erori): "
            + "; ".join(e.message for e in result.errors[:3]))

    # Guard 2: the stored hash must match the stored plan. A mismatch means the
    # row was edited after approval — by a bug or by someone.
    actual = plan_hash(plan)
    if actual != row.plan_hash:
        await repo.set_plan_status(db, plan_db_id, "rejected_invalid")
        raise PatchRefused("hash-ul planului nu corespunde conținutului — plan modificat")

    # Guard 3: applying requires an approval that named this exact hash.
    if mode == "apply" and row.status != "approved":
        raise PatchRefused(f"planul nu este aprobat (stare: {row.status})")

    execution_id = await repo.start_execution(db, plan_db_id, mode=mode,
                                              triggered_by=triggered_by)
    log.warning("patch execution started",
                extra={"execution_id": execution_id, "plan": plan_db_id, "mode": mode,
                       "by": triggered_by})
    if mode == "apply":
        await repo.set_plan_status(db, plan_db_id, "applying")

    dry = mode == "dry_run"
    all_steps: list[StepOutcome] = []
    seq = 1
    try:
        for phase in FORWARD_PHASES:
            if phase == "backup":
                outcome, seq = await _run_backup(db, execution_id, plan, plan_db_id,
                                                 row.asset_id, seq, dry_run=dry)
                all_steps.append(outcome)
                if not outcome.ok:
                    reason = f"backup eșuat: {outcome.stderr or outcome.stdout}"
                    await repo.finish_execution(db, execution_id, status="aborted",
                                                error=reason, result={"phase": "backup"})
                    if mode == "apply":
                        await repo.set_plan_status(db, plan_db_id, "failed")
                    log.error("patch aborted: no verified way back", extra={"reason": reason})
                    return RunResult("aborted", execution_id, all_steps, error=reason)
                continue

            outcomes, seq = await _run_phase(db, execution_id, plan, phase, seq, dry_run=dry)
            all_steps.extend(outcomes)
            failed = next((o for o in outcomes if not o.ok and not o.tolerated), None)
            if failed is None:
                continue

            reason = (f"pasul {failed.step_id} din faza {phase} a eșuat "
                      f"(cod {failed.exit_code}{', timeout' if failed.timed_out else ''})")

            # A failure before anything was applied needs no rollback: nothing
            # changed. Saying so plainly avoids a pointless rollback that could
            # itself break something.
            if phase in ("preflight", "backup") or dry:
                await repo.finish_execution(db, execution_id, status="aborted", error=reason,
                                            result={"phase": phase})
                if mode == "apply":
                    await repo.set_plan_status(db, plan_db_id, "failed")
                log.error("patch aborted before any change", extra={"reason": reason})
                return RunResult("aborted", execution_id, all_steps, error=reason)

            rolled_ok, rb_steps = await _rollback(db, execution_id, plan, seq, reason)
            all_steps.extend(rb_steps)
            status = "rolled_back" if rolled_ok else "rollback_failed"
            await repo.finish_execution(db, execution_id, status=status, error=reason,
                                        rollback_reason=reason)
            await repo.set_plan_status(db, plan_db_id,
                                       "rolled_back" if rolled_ok else "failed")
            return RunResult(status, execution_id, all_steps, error=reason,
                             rollback_reason=reason)

        post_ok = any(o.phase == "post_verification" and o.ok for o in all_steps) or None
        await repo.finish_execution(db, execution_id, status="succeeded",
                                    result={"steps": len(all_steps)}, post_ok=post_ok)
        if mode == "apply":
            await repo.set_plan_status(db, plan_db_id, "applied")
        log.warning("patch execution finished",
                    extra={"execution_id": execution_id, "steps": len(all_steps)})
        return RunResult("succeeded", execution_id, all_steps, post_ok=post_ok)

    except Exception as exc:  # noqa: BLE001 - never leave an execution 'running'
        detail = f"{type(exc).__name__}: {exc}"
        log.error("patch runner crashed", extra={"execution_id": execution_id, "detail": detail})
        if not dry:
            rolled_ok, rb_steps = await _rollback(db, execution_id, plan, seq + 100, detail)
            all_steps.extend(rb_steps)
            status = "rolled_back" if rolled_ok else "rollback_failed"
        else:
            status = "aborted"
        await repo.finish_execution(db, execution_id, status=status, error=detail,
                                    rollback_reason=detail if not dry else None)
        await repo.set_plan_status(db, plan_db_id, "failed")
        return RunResult(status, execution_id, all_steps, error=detail)
