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
  8. **A rollback needs something to roll back.** An apply step the executor
     REFUSED never ran, so when the first one is refused nothing has changed and
     the execution ends `aborted` with no rollback: rolling back a machine nobody
     touched is how a plan that "could not run" became a red "rollback failed -
     restore by hand" for a server that was fine.
  9. **"Not over yet" is not "failed".** A package transaction the executor could
     not follow to its end (it was restarted under it) is still owned by systemd and
     may finish fine; the executor says so in the reply. The runner then does not
     roll back - a rollback would race the transaction it is meant to undo and, after
     an executor restart, is refused for want of an approval (the registry is in the
     executor's memory) - it asks the executor for its own record of how
     that transaction ended and puts that in front of the operator
     (`RunResult.unknown_outcome`), with the execution ending `failed`.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import patches as repo
from sentinel.errors import ExecutorRejected
from sentinel.logging_setup import get_logger
from sentinel.patch import approval, backup, checks
from sentinel.patch.validator import plan_hash, validate_plan
from sentinel.respond.executor_client import TIMEOUT_MARGIN_S, ExecutorClient

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
    # The executor said NO before running anything (`ExecutorRejected`): the step
    # never ran, so it changed nothing and there is nothing to undo.
    refused: bool = False
    # The executor said the step's transaction is not over, or that it cannot tell how
    # it ended (`transaction.still_running_or_unknown`). Neither a failure nor a success.
    open: bool = False
    # `(plan_hash, step_index)` of the registered step this was, when it was one.
    binding: tuple[str, int] | None = None
    # The restore point a backup step made: its id (a directory name) and its script.
    restore_point: str | None = None
    restore_script: str | None = None


@dataclass
class RunResult:
    status: str                     # succeeded | failed | rolled_back | rollback_failed | aborted
    execution_id: int
    steps: list[StepOutcome] = field(default_factory=list)
    error: str | None = None
    rollback_reason: str | None = None
    post_ok: bool | None = None
    # What the executor itself recorded about the apply transaction whose outcome was
    # unknown when the run stopped (see rule 9). `None` when no step was in that state.
    unknown_outcome: dict[str, Any] | None = None
    # For a `rollback_failed`: what the executor recorded for each apply step that ran
    # (step id -> its `transaction_outcome`), so the operator is not sent to restore a
    # change the executor's own end row says finished.
    apply_verdicts: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def restore_point(self) -> str | None:
        """The id of the restore point this run made, if it got that far."""
        return next((s.restore_point for s in self.steps if s.restore_point), None)

    @property
    def restore_script(self) -> str | None:
        return next((s.restore_script for s in self.steps if s.restore_script), None)

    @property
    def restore_path(self) -> str | None:
        point = self.restore_point
        return backup.restore_point_path(point) if point else None


async def _exec_step(db: Database, execution_id: int, phase: str, seq: int,
                     step: dict[str, Any], *, dry_run: bool,
                     binding: tuple[str, int] | None = None) -> StepOutcome:
    """Run one step. Writes the DB row before the command, updates it after.

    `binding` is `(plan_hash, step_index)`: which step of the plan the operator
    signed for this call is. The executor runs a real step only if its argv is
    exactly that registered step, so a real call without it is refused there.
    A dry run needs none (it runs nothing) and the runner gives it none.
    """
    step_id = str(step.get("id") or f"{phase}-{seq}")
    argv = [str(a) for a in step.get("argv", [])]
    cwd = step.get("cwd")
    timeout = int(step.get("timeout_s", 60))

    row_id = await repo.begin_step(db, execution_id, phase=phase, step_id=step_id,
                                   seq=seq, argv=argv, cwd=cwd)
    bound = ({"plan_hash": binding[0], "step_index": binding[1]}
             if binding is not None and not dry_run else {})
    try:
        # socket_timeout_s covers the step's OWN timeout_s (up to 3600s,
        # executor/commands.py op_patch_step_exec) plus margin — the client's
        # default of 30s would otherwise give up on a long-running step while
        # it is still executing as root, and rollback could start concurrently
        # with the step it is rolling back.
        result = await asyncio.to_thread(
            _client.call, "patch_step_exec",
            argv=argv, cwd=cwd, timeout_s=timeout, dry_run=dry_run,
            socket_timeout_s=timeout + TIMEOUT_MARGIN_S, **bound)
    except Exception as exc:  # noqa: BLE001 - executor refused or unreachable
        await repo.end_step(db, row_id, status="failed", stderr=str(exc)[:2000])
        # `ExecutorRejected` is the executor saying no BEFORE it ran anything; an
        # unreachable executor says nothing about whether the step ran.
        return StepOutcome(False, phase, step_id, stderr=str(exc)[:2000],
                           refused=isinstance(exc, ExecutorRejected))

    if dry_run:
        # A dry run runs nothing, so on its own it would say "fine" for a step the
        # real run is going to be refused - the same collapse of "cannot know" into
        # "fine" as a health check that cannot see what it checks. For a package
        # transaction the executor says what it would refuse for; that is a FAILED
        # dry run, with the executor's own words, so the apply is stopped here
        # (guard 4 of `run_plan`) before anything has been touched.
        # Two shapes, one meaning: a package transaction reports under `transaction`, a
        # step that has nowhere to run (policy.sandbox_refusal) at the top level.
        refused = result.get("refused_because") or (result.get("transaction") or {}).get("refused_because")
        if isinstance(refused, list) and refused:
            reason = ("executorul ar refuza acest pas: " + "; ".join(str(r) for r in refused))[:2000]
            await repo.end_step(db, row_id, status="failed", exit_code=1, stderr=reason)
            return StepOutcome(False, phase, step_id, exit_code=1, stderr=reason)
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
    # A transaction the executor could not follow to its end says so; whatever exit
    # code it carries (125: "could not be vouched for") is not an answer.
    open_ = bool((result.get("transaction") or {}).get("still_running_or_unknown"))
    ok = (exit_code in expect) and not timed_out and not open_

    await repo.end_step(db, row_id, status="ok" if ok else "failed",
                        exit_code=exit_code, stdout=stdout, stderr=stderr,
                        timed_out=timed_out)
    return StepOutcome(ok, phase, step_id, exit_code, stdout, stderr, timed_out, open=open_)


async def _run_check(db: Database, execution_id: int, phase: str, seq: int,
                     item: dict[str, Any], *, dry_run: bool, family: str,
                     binding: tuple[str, int] | None = None) -> StepOutcome:
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

    # Only passed when there is one: a check that sends no argv, and every dry run,
    # call `evaluate` exactly as before.
    extra = {"binding": binding} if binding is not None else {}
    outcome = await checks.evaluate(db, check, family=family, **extra)
    blocking = bool(item.get("blocking", True))
    await repo.end_step(db, row_id, status="ok" if outcome.ok else "failed",
                        exit_code=0 if outcome.ok else 1, stdout=outcome.detail)
    return StepOutcome(outcome.ok, phase, step_id,
                       exit_code=0 if outcome.ok else 1, stdout=outcome.detail,
                       tolerated=not outcome.ok and not blocking)


async def _run_phase(db: Database, execution_id: int, plan: dict[str, Any], phase: str,
                     seq_start: int, *, dry_run: bool, family: str = "rhel",
                     binding: approval.Binding | None = None
                     ) -> tuple[list[StepOutcome], int]:
    """Run one phase. Check phases evaluate typed checks; apply and rollback run
    argv steps. A failure is tolerated only when the plan says so — a
    non-blocking check, or `on_failure: continue` on a step.

    `family` only matters for `phase in CHECK_PHASES` (it reaches
    `checks.evaluate` via `_run_check`) — `apply`, `backup` and `rollback`
    are always argv steps (`_exec_step`) and never touch it. Defaulted the
    same way `checks.evaluate` defaults it, so a caller running a phase that
    cannot possibly need it (`_rollback`, below) is not forced to plumb a
    value through for no reason.
    """
    outcomes: list[StepOutcome] = []
    seq = seq_start
    is_checks = phase in CHECK_PHASES

    for position, item in enumerate(plan.get(phase, []) or []):
        # Which registered step this item is, by the same (phase, position) the
        # registration was flattened from. None for an item that sends no argv.
        ref = binding.for_item(phase, position) if binding is not None and not dry_run else None
        if is_checks:
            outcome = await _run_check(db, execution_id, phase, seq, item,
                                       dry_run=dry_run, family=family, binding=ref)
        else:
            outcome = await _exec_step(db, execution_id, phase, seq, item, dry_run=dry_run,
                                       binding=ref)
            outcome.binding = ref
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
    return StepOutcome(True, "backup", "restore_point", 0, stdout=detail, restore_point=rp_id,
                       restore_script=manifest.get("restore_script")), seq + 1


async def _rollback(db: Database, execution_id: int, plan: dict[str, Any],
                    seq_start: int, reason: str,
                    binding: approval.Binding | None = None) -> tuple[bool, list[StepOutcome]]:
    """Run the rollback steps. Always attempted with dry_run=False — a rollback
    that only pretends to work is worse than none, because it reports success.

    No `family` to plumb through: `rollback` is not in `CHECK_PHASES`, so
    `_run_phase` never reaches `checks.evaluate` for it — see `_run_phase`'s
    own docstring.
    """
    log.error("patch rollback starting", extra={"execution_id": execution_id, "reason": reason})
    outcomes, _ = await _run_phase(db, execution_id, plan, "rollback", seq_start, dry_run=False,
                                   binding=binding)
    ok = bool(outcomes) and all(o.ok for o in outcomes)
    if not outcomes:
        # No rollback steps in the plan. The validator only permits that when
        # the plan declares itself irreversible, so this is expected — but it is
        # still a state the operator must be told about explicitly.
        log.error("no rollback steps in plan", extra={"execution_id": execution_id})
    return ok, outcomes


#: How long the runner waits for the executor to say how an open transaction ended, and
#: how it spaces its questions (the schedule below adds up to 60 s; whichever of the
#: two ends first stops the asking). The executor that took over after a restart settles
#: a finished unit within seconds (`transient_unit.recover`); a transaction that is still
#: running is not waited for beyond that - the answer then is "running", and the
#: operator is told.
VERDICT_WAIT_S = 60
VERDICT_POLL_S = (2, 4, 8, 16, 30)


async def _ask_outcome(binding: tuple[str, int]) -> dict[str, Any]:
    """The executor's own record of one approved step's transaction, or a note that it
    could not be read. Never raises: not being able to ask is an answer, and an
    honest one - it is reported as `unavailable`, never as `finished`."""
    try:
        return await asyncio.to_thread(_client.call, "transaction_outcome",
                                       plan_hash=binding[0], step_index=binding[1])
    except Exception as exc:  # noqa: BLE001 - the executor may be mid-restart
        return {"state": "unavailable", "error": str(exc)[:300]}


async def _transaction_verdict(step: StepOutcome) -> dict[str, Any]:
    """Wait, briefly, for the executor to record how an open transaction ended.

    `recorded` ends the wait; so does `running` after the budget is spent, because a
    transaction that is still going is the answer. What comes back always says which
    step it is about (`step_id`)."""
    if step.binding is None:
        return {"state": "unavailable", "step_id": step.step_id,
                "error": "the step carried no plan binding to ask about"}
    waited = 0.0
    answer: dict[str, Any] = {"state": "unavailable"}
    for pause in (*VERDICT_POLL_S, None):
        answer = await _ask_outcome(step.binding)
        if answer.get("state") == "recorded" or pause is None or waited >= VERDICT_WAIT_S:
            break
        await asyncio.sleep(pause)
        waited += pause
    return {**answer, "step_id": step.step_id}


def describe_outcome(verdict: dict[str, Any]) -> str:
    """The executor's verdict about one transaction, in words for the operator. Says
    only what the executor said: 'finished OK' needs the end row's `outcome:
    finished`, exit 0 and `verified`, all three."""
    state = verdict.get("state")
    if state == "recorded":
        end = verdict.get("end") or {}
        if end.get("outcome") == "finished" and end.get("verified") is True and end.get("exit_code") == 0:
            return ("executorul a înregistrat încheierea tranzacției: s-a încheiat CU SUCCES "
                    "(cod 0, verificat de systemd) - pachetul a fost schimbat")
        if end.get("outcome") == "finished" and end.get("verified") is True:
            return (f"executorul a înregistrat încheierea tranzacției: s-a încheiat CU EȘEC "
                    f"(cod {end.get('exit_code')})")
        return (f"executorul a înregistrat tranzacția ca {end.get('outcome')!r} (cod "
                f"{end.get('exit_code')}, verificat: {end.get('verified')}): rezultatul ei nu poate "
                "fi garantat")
    if state == "running":
        return "tranzacția încă rulează sub systemd (sentinel-txn.service)"
    return ("executorul nu poate spune acum cum s-a încheiat tranzacția; rândul `transaction_end` "
            "din lanțul lui de audit (/var/lib/sentinel-executor/audit.jsonl, doar root) o spune")


async def _apply_verdicts(steps: list[StepOutcome]) -> dict[str, dict[str, Any]]:
    """For a failed rollback: what the executor recorded for each apply step that ran.
    One question per step, no waiting - the run is over and this is context."""
    out: dict[str, dict[str, Any]] = {}
    for step in steps:
        if step.phase == "apply" and step.binding is not None and not step.refused:
            out[step.step_id] = await _ask_outcome(step.binding)
    return out


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

    # S1c/Guard 1: `platform_family` has to reach re-validation the same way it
    # already reaches `checks.evaluate` further down — computed once, here,
    # before the first thing that can refuse the plan. Guard 1 used to call
    # `validate_plan(plan)` with no family at all, which skips the
    # cross-platform binary check entirely (see `validate_plan`'s own
    # docstring: `None` means "skip the check", not "assume rhel"), so a
    # `dnf` plan stored for an `rhel` host kept re-validating as fine even
    # after redeployment to a `debian` host changed `cfg.platform.family` out
    # from under it — exactly the class of drift this guard exists to catch.
    # `cfg` is `None` in tests that never reach a family-sensitive check (same
    # reason `checks.evaluate`'s own default exists); a real caller always
    # supplies a real `Config`.
    family = cfg.platform.family if cfg is not None else "rhel"

    # Guard 1: the plan must still validate against today's rules.
    result = validate_plan(plan, platform_family=family)
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

    # Guard 3b: an apply names, for every real command it sends, which step of the
    # plan the operator signed for it is (`plan_hash` + index). The index is derived
    # from the plan here, the same way the request the operator signed was; a plan
    # whose commands cannot be listed is refused before anything runs. Without a
    # matching registration in the executor each of those calls is refused THERE -
    # the approval is the operator's token, and nothing in this process can supply it.
    binding: approval.Binding | None = None
    if mode == "apply":
        try:
            binding = approval.bind(plan, row.plan_hash, family)
        except approval.ApprovalError as exc:
            raise PatchRefused(f"planul nu poate fi legat de o aprobare: {exc}") from None

    # Guard 4 — S3: "dry run first, always" was a claim in this docstring that
    # the code never carried out; `apply` went straight to the real commands.
    # An apply is now actually preceded by a full dry-run pass through the
    # executor, as its own recorded execution, and a failing pass aborts the
    # apply BEFORE an execution row for it is even opened — nothing has been
    # touched yet, so there is nothing to roll back either.
    if mode == "apply":
        pre_check = await run_plan(db, cfg, plan_db_id, mode="dry_run",
                                   triggered_by=f"{triggered_by}:pre-apply-dry-run")
        if pre_check.status != "succeeded":
            raise PatchRefused(
                f"proba uscată dinaintea aplicării nu a reușit (execuția "
                f"#{pre_check.execution_id}, stare {pre_check.status}): "
                f"{pre_check.error or 'vezi pașii execuției'}")

    execution_id = await repo.start_execution(db, plan_db_id, mode=mode,
                                              triggered_by=triggered_by)
    log.warning("patch execution started",
                extra={"execution_id": execution_id, "plan": plan_db_id, "mode": mode,
                       "by": triggered_by})
    if mode == "apply":
        await repo.set_plan_status(db, plan_db_id, "applying")

    dry = mode == "dry_run"
    # S1c: `checks.evaluate` needs the same `family` computed above, for the
    # same reason — `pkg_version` speaks rpm or dpkg-query depending on it,
    # and defaults to `rhel` (see `evaluate`'s own docstring) if never told
    # otherwise.
    all_steps: list[StepOutcome] = []
    seq = 1
    # S3b: a crash is not automatically a reason to roll back. Preflight and
    # backup do not change anything on the target — the existing failure path
    # a few lines down already treats a FAILED step in either of them as
    # "abort, nothing to undo" rather than a rollback. An unhandled exception
    # (a DB write that fails mid-preflight, say) used to skip that distinction
    # entirely and always attempt a rollback whenever `not dry`, which means
    # running the plan's rollback steps against a machine nothing had touched
    # yet. This flag is set the moment the loop actually reaches `apply`, so
    # the crash handler below can tell the two situations apart the same way
    # the normal failure path already does.
    apply_started = False
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

            if phase == "apply":
                apply_started = True
            outcomes, seq = await _run_phase(db, execution_id, plan, phase, seq,
                                             dry_run=dry, family=family, binding=binding)
            all_steps.extend(outcomes)
            failed = next((o for o in outcomes if not o.ok and not o.tolerated), None)
            if failed is None:
                continue

            reason = (f"pasul {failed.step_id} din faza {phase} a eșuat "
                      f"(cod {failed.exit_code}{', timeout' if failed.timed_out else ''})")
            if dry and failed.stderr:
                # A dry run's failure IS the executor's reason ("would refuse: ..."), and
                # the caller - the apply's pre-pass above - shows only this line.
                reason += f": {failed.stderr[:600]}"

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

            # Rule 9: a transaction that is not over is not a failure to undo. Nothing is
            # rolled back - the rollback would race it, and after an executor restart is
            # refused for want of an approval - and the executor is asked how it ended.
            open_step = next((o for o in outcomes if o.open), None)
            if open_step is not None:
                verdict = await _transaction_verdict(open_step)
                reason = (f"pasul {open_step.step_id} din faza apply are un rezultat NECUNOSCUT: "
                          f"executorul nu a putut urmări tranzacția până la capăt (cod "
                          f"{open_step.exit_code}); {describe_outcome(verdict)}. Nu s-a făcut rollback "
                          "și pașii următori ai planului nu au rulat.")
                await repo.finish_execution(db, execution_id, status="failed", error=reason,
                                            result={"phase": phase, "unknown_outcome": verdict})
                await repo.set_plan_status(db, plan_db_id, "failed")
                log.error("patch stopped: the outcome of an apply transaction is unknown",
                          extra={"reason": reason, "verdict": verdict.get("state")})
                return RunResult("failed", execution_id, all_steps, error=reason,
                                 unknown_outcome=verdict)

            # Rule 8: nothing ran, so nothing changed. Only the FIRST apply step can be in
            # this state - an earlier one that ran (and succeeded) is something to undo.
            if phase == "apply" and failed.refused and not any(
                    o is not failed and not o.refused for o in outcomes):
                reason = (f"pasul {failed.step_id} din faza apply a fost REFUZAT de executor înainte "
                          f"să ruleze ({failed.stderr[:600]}); nimic nu a fost schimbat, deci nu s-a "
                          "făcut rollback")
                await repo.finish_execution(db, execution_id, status="aborted", error=reason,
                                            result={"phase": phase, "refused": failed.step_id})
                await repo.set_plan_status(db, plan_db_id, "failed")
                log.error("patch aborted: the executor refused the first apply step",
                          extra={"reason": reason})
                return RunResult("aborted", execution_id, all_steps, error=reason)

            rolled_ok, rb_steps = await _rollback(db, execution_id, plan, seq, reason,
                                                  binding=binding)
            all_steps.extend(rb_steps)
            status = "rolled_back" if rolled_ok else "rollback_failed"
            await repo.finish_execution(db, execution_id, status=status, error=reason,
                                        rollback_reason=reason)
            await repo.set_plan_status(db, plan_db_id,
                                       "rolled_back" if rolled_ok else "failed")
            return RunResult(status, execution_id, all_steps, error=reason,
                             rollback_reason=reason,
                             apply_verdicts={} if rolled_ok else await _apply_verdicts(all_steps))

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
        # S3b: only roll back if `apply` had actually started. A crash during
        # preflight or backup — nothing on the machine changed — must abort
        # the same way a normal failure there does, not run rollback steps
        # against an untouched system.
        if not dry and apply_started:
            rolled_ok, rb_steps = await _rollback(db, execution_id, plan, seq + 100, detail,
                                                  binding=binding)
            all_steps.extend(rb_steps)
            status = "rolled_back" if rolled_ok else "rollback_failed"
        else:
            status = "aborted"
        await repo.finish_execution(db, execution_id, status=status, error=detail,
                                    rollback_reason=detail if (not dry and apply_started) else None)
        await repo.set_plan_status(db, plan_db_id, "failed")
        return RunResult(status, execution_id, all_steps, error=detail)
