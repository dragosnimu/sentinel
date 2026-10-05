"""What the runner does when a step never ran, and when it is not over.

Two reproduced defects, both of which ended in the same message to the operator -
"Patch rollback_failed ... restore by hand: restore.sh" - about a machine that was fine.

1. An apply step the executor REFUSED (a step with nowhere to run, a replayed approval)
   never ran, so there is nothing to undo. The runner rolled back anyway; the rollback
   was refused as well; the execution ended `rollback_failed`.
2. A package transaction the executor could not follow to its end (the executor was
   restarted under it) came back "unknown, do not treat as failure or success" with exit
   125. The runner read 125 as a failure and rolled back; approvals do not survive a
   restart, so the rollback was refused; `rollback_failed` - while `rpm -q` showed the
   package installed and the new executor's own end row said the transaction finished.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from sentinel.errors import ExecutorRejected, ExecutorUnavailable
from sentinel.patch import backup as backup_mod
from sentinel.patch import checks as checks_mod
from sentinel.patch import runner
from tests.unit.test_patch_runner import _check, _FakeDB, _FakeExec, _plan, _step

UPDATE = ["dnf", "-y", "update", "nginx"]
DOWNGRADE = ["dnf", "-y", "downgrade", "nginx-1.20.1-14.el9"]
RESTART = ["systemctl", "restart", "nginx.service"]

FINISHED_OK = {"state": "recorded", "end": {"outcome": "finished", "exit_code": 0, "verified": True,
                                            "result": "success", "recovered": True, "duration_ms": 9}}
FINISHED_FAILED = {"state": "recorded", "end": {"outcome": "finished", "exit_code": 1, "verified": True,
                                                "result": "exit-code", "recovered": True, "duration_ms": 9}}
RUNNING = {"state": "running", "unit": "sentinel-txn.service", "this_step": True}
UNKNOWN = {"state": "unknown"}
OPEN_REPLY = {"exit_code": 125, "stdout": "", "timed_out": False,
              "stderr": "[sentinel-txn] the executor is shutting down; the transaction was NOT stopped",
              "transaction": {"unit_ran": True, "outcome": "detached", "still_running_or_unknown": True,
                              "verified": False}}


class Scripted(_FakeExec):
    """A fake executor that can refuse a real step, answer one with "still running", and
    say what became of a transaction - and records every call."""

    def __init__(self, *, refuse=(), open_for=(), outcomes=(UNKNOWN,), dry_refuse=None):
        super().__init__()
        self.refuse = [list(a) for a in refuse]
        self.open_for = [list(a) for a in open_for]
        self.outcomes = list(outcomes)
        self.dry_refuse = dry_refuse
        self.asked: list[dict[str, Any]] = []

    def real_calls(self) -> list[list[str]]:
        return [c["argv"] for c in self.calls if c["op"] == "patch_step_exec" and not c.get("dry_run")]

    def call(self, op: str, **args: Any) -> dict[str, Any]:
        if op == "transaction_outcome":
            self.asked.append(args)
            answer = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
            if isinstance(answer, Exception):
                raise answer
            return answer
        argv = list(args.get("argv") or [])
        if op == "patch_step_exec":
            if args.get("dry_run") and self.dry_refuse and argv == self.dry_refuse[0]:
                self.calls.append({"op": op, **args})
                return {"dry_run": True, "would_run": argv, "refused_because": [self.dry_refuse[1]]}
            if not args.get("dry_run"):
                if argv in self.refuse:
                    self.calls.append({"op": op, **args})
                    raise ExecutorRejected("refused: no plan is registered for this step")
                if argv in self.open_for:
                    self.calls.append({"op": op, **args})
                    return dict(OPEN_REPLY)
        return super().call(op, **args)


@pytest.fixture
def install(monkeypatch):
    monkeypatch.setattr(runner, "VERDICT_POLL_S", (0, 0, 0))
    monkeypatch.setattr(runner, "VERDICT_WAIT_S", 3600)

    def _install(fake):
        for module in (runner, backup_mod, checks_mod):
            monkeypatch.setattr(module, "_client", fake)
        return fake

    return _install


def run(c):
    return asyncio.run(c)


def _two_step_plan() -> dict:
    plan = _plan()
    plan["apply"].append(_step("ap2", RESTART, timeout_s=60))
    plan["rollback"] = [_step("rb1", DOWNGRADE, on_failure="abort")]
    return plan


# ---------------------------------------------------------------------------
# A step the executor refused never ran: nothing to undo
# ---------------------------------------------------------------------------
def test_when_the_first_apply_step_is_refused_nothing_is_rolled_back(install):
    """The reproduced ghost: `mkdir` refused (or failing with EROFS) as the FIRST apply step
    ended in a rollback against an untouched machine, the rollback itself refused, and a red
    "rollback_failed - restore by hand". A step that never ran changed nothing; the honest
    end is `aborted`, saying so."""
    fake = install(Scripted(refuse=[UPDATE]))
    db = _FakeDB(_plan())
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "aborted"
    assert "REFUZAT" in res.error and "nimic nu a fost schimbat" in res.error and "nu s-a făcut rollback" in res.error
    assert fake.real_calls() == [["test", "-e", "/etc/nginx/nginx.conf"],
                                 ["rpm", "-q", "--qf", "%{EPOCH}:%{VERSION}-%{RELEASE}\\n", "nginx"], UPDATE], (
        "the executor must not have been sent the rollback")
    assert not any(s["phase"] == "rollback" for s in db.steps)
    assert db.plan_statuses[-1] == "failed"
    assert not [e for e in db.executions if e.get("final") in ("rolled_back", "rollback_failed")]


def test_a_failure_that_is_not_a_refusal_still_rolls_back(install):
    """The control, and the reason `refused` is its own fact: an executor that cannot be
    REACHED says nothing about whether the step ran, so it is rolled back from. Only "the
    executor said no" means "it did not run"."""

    class Unreachable(Scripted):
        def call(self, op, **args):
            if op == "patch_step_exec" and not args.get("dry_run") and list(args["argv"]) == UPDATE:
                self.calls.append({"op": op, **args})
                raise ExecutorUnavailable("executor closed the connection without responding")
            return super().call(op, **args)

    fake = install(Unreachable())
    res = run(runner.run_plan(_FakeDB(_plan()), None, 1, mode="apply"))
    assert res.status == "rolled_back"
    assert DOWNGRADE in fake.real_calls()


def test_a_refused_second_apply_step_is_rolled_back_because_the_first_one_ran(install):
    """"Nothing ran" is true only of the FIRST apply step. When an earlier step ran and
    succeeded the machine was changed, and a refusal later is a reason to roll back."""
    fake = install(Scripted(refuse=[RESTART]))
    db = _FakeDB(_two_step_plan())
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "rolled_back"
    assert fake.real_calls()[-3:] == [UPDATE, RESTART, DOWNGRADE]


def test_a_refused_step_after_a_tolerated_failure_that_ran_is_still_rolled_back(install):
    """A step that FAILED but was tolerated did run (`on_failure: continue`) and may have
    changed something: it counts as ran."""
    plan = _two_step_plan()
    plan["apply"][0]["on_failure"] = "continue"

    class FailsThenRefuses(Scripted):
        def call(self, op, **args):
            if op == "patch_step_exec" and not args.get("dry_run") and list(args["argv"]) == UPDATE:
                self.calls.append({"op": op, **args})
                return {"exit_code": 1, "stdout": "", "stderr": "boom", "timed_out": False}
            return super().call(op, **args)

    fake = install(FailsThenRefuses(refuse=[RESTART]))
    res = run(runner.run_plan(_FakeDB(plan), None, 1, mode="apply"))
    assert res.status == "rolled_back", (res.status, res.error)
    assert DOWNGRADE in fake.real_calls()


# ---------------------------------------------------------------------------
# A transaction that is not over is not a failure
# ---------------------------------------------------------------------------
def test_an_open_transaction_is_not_rolled_back_and_the_executors_verdict_is_reported(install):
    """The reproduced restart: the executor shut down under `dnf install`, the reply was
    exit 125 / `still_running_or_unknown`. The runner used to roll back (refused: approvals
    are in the executor's memory) and end `rollback_failed`. Now it asks the executor how the
    transaction ended and reports that, with no rollback."""
    fake = install(Scripted(open_for=[UPDATE], outcomes=[FINISHED_OK]))
    db = _FakeDB(_plan())
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "failed" and res.unknown_outcome["state"] == "recorded"
    assert res.unknown_outcome["step_id"] == "ap1"
    assert "NECUNOSCUT" in res.error and "CU SUCCES" in res.error and "Nu s-a făcut rollback" in res.error
    assert DOWNGRADE not in fake.real_calls()
    assert db.plan_statuses[-1] == "failed"
    finals = [e["final"] for e in db.executions if e.get("final")]
    assert finals[-1] == "failed", finals    # the last one: the first is the pre-apply dry run
    assert fake.asked and fake.asked[0]["step_index"] == approval_index_of_apply(_plan())


def approval_index_of_apply(plan: dict) -> int:
    from sentinel.patch import approval

    return approval.flatten(plan, "rhel").ref("apply", 0)


def test_the_runner_waits_for_the_executor_to_record_the_end_and_then_stops_asking(install):
    """A restarted executor takes a moment to settle the unit; the first answer is
    "running". The runner asks again - and stops at the first `recorded`."""
    fake = install(Scripted(open_for=[UPDATE], outcomes=[RUNNING, RUNNING, FINISHED_OK, RUNNING]))
    res = run(runner.run_plan(_FakeDB(_plan()), None, 1, mode="apply"))
    assert res.unknown_outcome["state"] == "recorded"
    assert len(fake.asked) == 3, "asked until recorded, and not again"


def test_a_transaction_still_running_is_reported_as_running_not_as_failed(install, monkeypatch):
    """When the wait is over and the executor still says "running", that is the answer."""
    monkeypatch.setattr(runner, "VERDICT_WAIT_S", 0)
    fake = install(Scripted(open_for=[UPDATE], outcomes=[RUNNING]))
    res = run(runner.run_plan(_FakeDB(_plan()), None, 1, mode="apply"))
    assert res.unknown_outcome["state"] == "running" and "încă rulează" in res.error
    assert DOWNGRADE not in fake.real_calls()


def test_an_executor_that_cannot_be_asked_is_unavailable_never_finished(install, monkeypatch):
    """"Cannot ask" is not "it finished": the message sends the operator to the audit chain
    and does not claim a result."""
    monkeypatch.setattr(runner, "VERDICT_WAIT_S", 0)
    install(Scripted(open_for=[UPDATE], outcomes=[ExecutorUnavailable("down")]))
    res = run(runner.run_plan(_FakeDB(_plan()), None, 1, mode="apply"))
    assert res.unknown_outcome["state"] == "unavailable"
    assert "CU SUCCES" not in res.error and "nu poate spune" in res.error


def test_a_transaction_that_finished_with_a_failure_is_not_described_as_a_success(install):
    """The control for the success wording: the same path, an end row with exit code 1."""
    install(Scripted(open_for=[UPDATE], outcomes=[FINISHED_FAILED]))
    res = run(runner.run_plan(_FakeDB(_plan()), None, 1, mode="apply"))
    assert "CU EȘEC" in res.error and "CU SUCCES" not in res.error


@pytest.mark.parametrize("end", [
    {"outcome": "lost", "exit_code": 125, "verified": False},
    {"outcome": "finished", "exit_code": 0, "verified": False},
    {"outcome": "stopped", "exit_code": 125, "verified": False},
])
def test_only_a_finished_verified_zero_is_called_a_success(end):
    """Success needs all three: `finished`, exit 0 and verified by PID 1. A transaction
    recorded as lost, or exit 0 that PID 1 did not vouch for, is not one."""
    text = runner.describe_outcome({"state": "recorded", "end": end})
    assert "CU SUCCES" not in text


def test_the_answer_says_which_step_it_is_about(install):
    install(Scripted(open_for=[UPDATE], outcomes=[FINISHED_OK]))
    res = run(runner.run_plan(_FakeDB(_plan()), None, 1, mode="apply"))
    assert res.unknown_outcome["step_id"] == "ap1"


# ---------------------------------------------------------------------------
# A dry run reads both shapes of "would be refused"
# ---------------------------------------------------------------------------
def test_a_dry_run_step_the_executor_says_has_nowhere_to_run_fails_the_dry_run_with_its_reason(install):
    """The top-level `refused_because` (a non-transaction step) is read like the transaction
    one. And the apply's own pre-pass shows the operator the reason, not only "the dry run
    did not succeed"."""
    reason = "`mkdir` writes the filesystem, and the sandbox is read-only"
    install(Scripted(dry_refuse=[RESTART, reason]))
    plan = _plan()
    plan["apply"].append(_step("ap2", RESTART, timeout_s=60))
    with pytest.raises(runner.PatchRefused) as excinfo:
        run(runner.run_plan(_FakeDB(plan), None, 1, mode="apply"))
    assert "proba uscată" in str(excinfo.value) and reason in str(excinfo.value)


def test_a_dry_run_with_nothing_to_refuse_still_succeeds(install):
    install(Scripted())
    assert run(runner.run_plan(_FakeDB(_plan(), status="validated"), None, 1, mode="dry_run")).status == "succeeded"


# ---------------------------------------------------------------------------
# What the operator is shown
# ---------------------------------------------------------------------------
def test_the_restore_point_is_named_in_the_result(install):
    """`restore.sh` "of the restore point" was all the operator was told: which one, and
    where, is the first thing they need."""
    install(Scripted(open_for=[UPDATE], outcomes=[FINISHED_OK]))
    res = run(runner.run_plan(_FakeDB(_plan()), None, 1, mode="apply"))
    assert res.restore_point and res.restore_path == f"/var/backups/sentinel/{res.restore_point}"
    assert res.restore_script == "/var/backups/sentinel/x/restore.sh"


def test_a_failed_rollback_carries_what_the_executor_recorded_for_the_apply_step(install):
    """`rollback_failed` after an apply the executor's own record says FINISHED: the operator
    must see that, or the message sends them to restore a machine that was patched correctly."""

    class ApplyOkThenEverythingElseFails(Scripted):
        def call(self, op, **args):
            if op == "patch_step_exec" and not args.get("dry_run") and list(args["argv"]) in (RESTART, DOWNGRADE):
                self.calls.append({"op": op, **args})
                return {"exit_code": 1, "stdout": "", "stderr": "no plan is registered", "timed_out": False}
            return super().call(op, **args)

    plan = _two_step_plan()
    fake = install(ApplyOkThenEverythingElseFails(outcomes=[FINISHED_OK]))
    res = run(runner.run_plan(_FakeDB(plan), None, 1, mode="apply"))
    assert res.status == "rollback_failed"
    assert res.apply_verdicts["ap1"]["state"] == "recorded"
    assert "ap2" in res.apply_verdicts, "every apply step that ran is asked about"
    assert fake.asked
