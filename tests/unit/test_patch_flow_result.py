"""What the operator reads about a patch - before it, at the first tap, and after it.

The two messages that matter most are the ones about a production machine: the refusal at
the first tap (a plan that cannot be approved is never offered) and the end of an apply.
The end of an apply used to say "ROLLBACK FAILED, restore by hand: restore.sh" and nothing
else - no reason, no restore point, no word about whether the change had actually happened.
On 5 October 2026 that was the message the operator got for a package that had installed
correctly.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.db.repo import approvals  # noqa: E402
from sentinel.patch import runner  # noqa: E402
from sentinel.telegram import patch_flow  # noqa: E402
from tests.unit.test_patch_runner import _check, _plan, _step  # noqa: E402
from tests.unit.test_patch_stage1_reversibility_gate import (  # noqa: E402
    _ctx,
    _plan_row,
    _update_and_edits,
    _wire_common,
)

FINISHED_OK = {"state": "recorded", "step_id": "ap1",
               "end": {"outcome": "finished", "exit_code": 0, "verified": True, "result": "success",
                       "recovered": True, "duration_ms": 9}}


def run(c):
    return asyncio.run(c)


def _result(status, steps=(), **extra) -> runner.RunResult:
    return runner.RunResult(status, 7, list(steps), **extra)


def _rp_step() -> runner.StepOutcome:
    return runner.StepOutcome(True, "backup", "restore_point", exit_code=0,
                              restore_point="20261005-101500-plan9",
                              restore_script="/var/backups/sentinel/20261005-101500-plan9/restore.sh")


# ---------------------------------------------------------------------------
# The end of an apply
# ---------------------------------------------------------------------------
def test_a_failed_rollback_message_carries_the_failing_steps_own_words_and_the_restore_point():
    """Why it failed, which restore point and where: the three things an operator at 3 a.m.
    needs and the old message did not have."""
    text = patch_flow.format_apply_result(_result("rollback_failed", [
        _rp_step(),
        runner.StepOutcome(False, "apply", "ap1", exit_code=125,
                           stderr="[sentinel-txn] the executor is shutting down; the transaction was NOT stopped"),
        runner.StepOutcome(False, "rollback", "rb1", exit_code=None,
                           stderr="refused: no plan is registered for 3f2a"),
    ], error="pasul ap1 din faza apply a eșuat (cod 125)"))
    assert "ROLLBACK-UL A EȘUAT" in text
    assert "the executor is shutting down" in text and "no plan is registered" in text
    assert "<code>apply/ap1</code>" in text and "<code>rollback/rb1</code>" in text
    assert "20261005-101500-plan9" in text
    assert "/var/backups/sentinel/20261005-101500-plan9/restore.sh" in text


def test_a_failed_rollback_does_not_send_the_operator_to_restore_what_the_executor_says_finished():
    """The reproduced message: `rollback_failed` for a package that was installed correctly.
    The executor's end row says the apply step finished with exit 0, verified; the message
    must say so, and must not tell the operator to restore."""
    text = patch_flow.format_apply_result(_result(
        "rollback_failed",
        [_rp_step(), runner.StepOutcome(False, "apply", "ap1", exit_code=125, stderr="x")],
        apply_verdicts={"ap1": FINISHED_OK}))
    assert "ap1" in text and "CU SUCCES" in text and "pachetul a fost schimbat" in text
    assert "Restaurează manual" not in text, "an instruction to restore, for a change that succeeded"
    assert "înainte de orice restaurare" in text


def test_an_unknown_outcome_is_not_called_a_failed_rollback_and_advises_no_restore():
    """The runner stopped without rolling back because the transaction is not over/known.
    The message must not say the rollback failed (none was attempted) and must say how to
    find out, with the executor's verdict."""
    text = patch_flow.format_apply_result(_result(
        "failed", [_rp_step(), runner.StepOutcome(False, "apply", "ap1", exit_code=125, stderr="detached")],
        error="pasul ap1 din faza apply are un rezultat NECUNOSCUT", unknown_outcome=FINISHED_OK))
    assert "ROLLBACK-UL A EȘUAT" not in text
    assert "NU e cunoscut" in text and "Nu s-a făcut rollback" in text
    assert "CU SUCCES" in text and "rpm -q" in text
    assert text.startswith("🟠")


def test_a_clean_success_has_no_restore_noise_and_a_rolled_back_run_names_the_point():
    ok = patch_flow.format_apply_result(_result("succeeded", [_rp_step(), runner.StepOutcome(True, "apply", "ap1", 0)]))
    assert ok.startswith("✅") and "restaurare" not in ok.lower() and "ROLLBACK" not in ok
    back = patch_flow.format_apply_result(_result("rolled_back", [_rp_step()]))
    assert "20261005-101500-plan9" in back


def test_the_failing_steps_output_is_escaped_and_cut_to_its_tail():
    """A package manager's output is untrusted text in an HTML message, and the failure is
    at the END of a long transcript."""
    noisy = "x" * 2000 + "<b>boom</b> Error: the real reason"
    text = patch_flow.format_apply_result(_result("failed", [
        runner.StepOutcome(False, "apply", "ap1", exit_code=1, stderr=noisy)]))
    assert "&lt;b&gt;boom&lt;/b&gt;" in text and "<b>boom</b>" not in text
    assert "the real reason" in text
    assert text.count("x") < 450, "the whole transcript was pasted into a chat message"


def test_a_tolerated_failure_is_not_shown_as_the_reason():
    text = patch_flow.format_apply_result(_result("succeeded", [
        runner.StepOutcome(False, "apply", "ap1", exit_code=1, stderr="harmless", tolerated=True)]))
    assert "harmless" not in text


def test_no_more_than_three_failing_steps_are_printed():
    steps = [runner.StepOutcome(False, "apply", f"ap{i}", exit_code=1, stderr=f"reason{i}") for i in range(6)]
    text = patch_flow.format_apply_result(_result("rollback_failed", steps))
    assert text.count("<i>reason") == 3 and "alți pași eșuați" in text


def test_approve_and_run_sends_exactly_the_formatted_result(monkeypatch):
    """The wiring: the text the operator reads is `format_apply_result`'s, not a second
    summary built beside it."""
    from sentinel.db.repo import patches

    sent: list[str] = []

    async def approve_plan(db, plan_id, *, by, expected_hash):
        return True

    async def revoke(*a, **k):
        return 0

    async def fake_run_plan(*a, **k):
        return _result("rollback_failed", [_rp_step()], error="boom")

    monkeypatch.setattr(patches, "approve_plan", approve_plan)
    monkeypatch.setattr(approvals, "revoke_for_plan", revoke)
    monkeypatch.setattr(runner, "run_plan", fake_run_plan)

    async def edit(text, **kw):
        sent.append(text)

    run(patch_flow._approve_and_run(object(), SimpleNamespace(), edit, plan_id=1, plan_hash="h", by="t"))
    assert sent[-1] == patch_flow.format_apply_result(_result("rollback_failed", [_rp_step()], error="boom"))


# ---------------------------------------------------------------------------
# The first tap: a plan that cannot be approved is never offered
# ---------------------------------------------------------------------------
def _ctx_with_family(family="rhel"):
    ctx = _ctx()
    ctx.bot_data["cfg"] = SimpleNamespace(platform=SimpleNamespace(family=family))
    return ctx


def _first_tap(monkeypatch, plan):
    row = _plan_row(id_=21)
    row.plan = plan
    update, edits = _update_and_edits()
    issued: list[dict] = []
    _wire_common(monkeypatch, plan_row=row, drill_evidence=None, issue_calls=issued)
    run(patch_flow.on_stage1(update, _ctx_with_family(), "tok"))
    return edits, issued


def test_the_control_a_valid_plan_gets_its_second_screen(monkeypatch):
    edits, issued = _first_tap(monkeypatch, _plan())
    assert issued, "a valid plan was refused at the first tap: the refusals below prove nothing"


def test_a_plan_with_a_step_that_cannot_run_is_refused_at_the_first_tap_with_no_token(monkeypatch):
    """The ghost-rollback plan (an apply step that writes the filesystem), stored before the
    rule existed and still `validated`: it must die at the first tap, naming the step, with
    nothing issued - not after the second tap, the PIN and the signature."""
    plan = _plan()
    plan["apply"].insert(0, _step("ap0", ["mkdir", "/var/lib/e2e-probe-dir"], timeout_s=60))
    edits, issued = _first_tap(monkeypatch, plan)
    assert issued == [], "a token was issued for a plan that cannot run"
    assert "nu mai trece validarea" in edits[-1] and "ap0" in edits[-1] and "Read-only" in edits[-1]


def test_a_plan_whose_timeouts_do_not_fit_the_window_is_refused_at_the_first_tap(monkeypatch):
    """n8n plan 1: 2700 s against 2400, refused only at the signing prompt, after two taps and
    the PIN. Now at the first tap, with the numbers."""
    plan = _plan()
    plan["apply"][0]["timeout_s"] = 1500
    plan["rollback"][0]["timeout_s"] = 1500
    edits, issued = _first_tap(monkeypatch, plan)
    assert issued == []
    assert "nu mai trece validarea" in edits[-1] and "run_budget_exceeded" not in edits[-1]
    assert "3150 s" in edits[-1] and "2400 s" in edits[-1], "the operator is told the numbers"


def test_the_refusal_is_html_safe(monkeypatch):
    """The validator's message quotes the plan's own text."""
    plan = _plan()
    plan["apply"].insert(0, _step("ap0", ["mkdir", "/var/lib/<b>x"], timeout_s=60))
    edits, issued = _first_tap(monkeypatch, plan)
    assert issued == [] and "<b>x" not in edits[-1]
