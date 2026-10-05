"""A plan that cannot run, or cannot be approved, is refused at validation - before the
operator is offered it.

Two defects, one place. (1) A plan step that writes the filesystem and is not a package
transaction has nowhere to run: the executor's sandbox is read-only. n8n's real plan 1
had `tar -czf /var/backups/polkit-1.tar.gz -C / etc/polkit-1` as an apply step; the dry
run passed, the apply failed with "Read-only file system" and the runner rolled back a
machine nothing had touched. (2) A plan whose declared timeouts add up to more than the
approval window allows (n8n plan 1 again: 2700 s against 2400) was refused only at the
signing prompt - after two taps and the PIN, with no way to shorten it from there.

The validator is the place both are caught first, and the planner's second attempt is
what reads what it says.
"""

from __future__ import annotations

import copy

import pytest

from sentinel.patch import approval, planner
from sentinel.patch import validator as validator_mod
from sentinel.patch.validator import validate_plan
from tests.unit.test_patch_runner import _check, _plan, _step


def _codes(result):
    return [(e.code, e.path) for e in result.errors]


def _debian_plan() -> dict:
    plan = _plan()
    plan["apply"] = [_step("ap1", ["apt-get", "-y", "install", "nginx=1.24.0-1~deb12u1"], timeout_s=600)]
    plan["rollback"] = [_step("rb1", ["apt-get", "-y", "install", "--allow-downgrades", "nginx=1.18.0-0"],
                              on_failure="abort", timeout_s=600)]
    plan["preflight"] = [c for c in plan["preflight"] if c["id"] != "pf_pkgver"] + [
        _check("pf_pkgver", {"kind": "pkg_version", "name": "nginx", "equals": "1.18.0-0"})]
    return plan


# ---------------------------------------------------------------------------
# Steps that cannot run
# ---------------------------------------------------------------------------
def test_the_control_plan_is_valid_so_the_refusals_below_are_about_the_step():
    assert validate_plan(_plan(), platform_family="rhel").valid
    assert validate_plan(_debian_plan(), platform_family="debian").valid


@pytest.mark.parametrize("argv", [
    ["tar", "-czf", "/var/backups/polkit-1.tar.gz", "-C", "/", "etc/polkit-1"],
    ["mkdir", "/var/lib/e2e-probe-dir"],
    ["cp", "/etc/hostname", "/etc/hostname.bak"],
    ["chmod", "644", "/etc/hostname"],
    # the rollbacks the planner's own history called "schema-valid and restoring nothing":
    # they cannot run either (tests/unit/test_patch_planner_reversibility.py)
    ["dnf", "-y", "clean", "all"],
    ["dnf", "-y", "makecache"],
])
def test_an_apply_step_that_writes_and_is_not_a_transaction_is_refused_and_named(argv):
    """The n8n plan 1 shape. The error names the step (so the operator and the planner's
    retry know which), and says why, and says it is refused here rather than discovered
    after the apply."""
    plan = _plan()
    plan["apply"].insert(0, _step("ap0", argv, timeout_s=60))
    result = validate_plan(plan, platform_family="rhel")
    assert ("step_cannot_run", "$.argv[id=ap0]") in _codes(result), _codes(result)
    message = next(e.message for e in result.errors if e.code == "step_cannot_run")
    assert "Read-only" in message and "roll back a machine that was never changed" in message


def test_a_rollback_step_that_cannot_run_is_refused_too():
    """A rollback that fails with "Read-only file system" is found out at the worst moment."""
    plan = _plan()
    plan["rollback"].append(_step("rb2", ["cp", "/etc/a", "/etc/b"], on_failure="abort"))
    assert ("step_cannot_run", "$.argv[id=rb2]") in _codes(validate_plan(plan, platform_family="rhel"))


@pytest.mark.parametrize("kind_check", [
    {"kind": "command", "argv": ["nginx", "-t"]},
    {"kind": "command", "argv": ["dnf", "check-update"]},
    {"kind": "command", "argv": ["mkdir", "/var/lib/x"]},
])
def test_a_check_that_runs_such_a_command_is_refused(kind_check):
    """A post-verification `nginx -t` is the worst case: the apply has succeeded, the check
    fails with EROFS on a good configuration, and the runner rolls back a patch that worked."""
    plan = _plan()
    plan["post_verification"].append(_check("pv_cmd", kind_check))
    assert ("step_cannot_run", "$.check[id=pv_cmd].argv") in _codes(validate_plan(plan, platform_family="rhel"))


def test_a_backup_restore_command_is_not_judged_by_this_rule():
    """`restore_argv` is the operator's documented manual path (written into restore.sh),
    never sent by the runner; `tar -x` is exactly what it is for. Refusing it would break
    every plan that carries a restore recipe."""
    plan = _plan()
    plan["backup"][0]["restore_argv"] = ["tar", "--zstd", "-xf", "{artifact}", "-C", "/"]
    assert validate_plan(plan, platform_family="rhel").valid


def test_package_transactions_service_restarts_and_reads_are_not_refused():
    plan = _plan()
    plan["apply"].append(_step("ap2", ["systemctl", "restart", "nginx.service"], timeout_s=60))
    plan["post_verification"].append(_check("pv_rpm", {"kind": "command", "argv": ["rpm", "-q", "nginx"]}))
    assert validate_plan(plan, platform_family="rhel").valid


def test_a_policy_that_cannot_say_where_a_step_runs_refuses_the_plan(monkeypatch):
    """A copy of the executor policy from before this rule cannot answer. "Cannot answer"
    is not "runs": the plan is refused, with the reason, instead of being passed on a
    validator that silently stopped asking."""
    real = validator_mod._executor_policy()[0]

    class _Old:
        PolicyRefusal = real.PolicyRefusal
        check_argv = staticmethod(real.check_argv)

    monkeypatch.setattr(validator_mod, "_executor_policy", lambda: (_Old(), None))
    result = validate_plan(_plan(), platform_family="rhel")
    assert "executor_policy_outdated" in [e.code for e in result.errors]


def test_a_policy_that_raises_while_deciding_is_an_error_on_the_plan_not_a_crash(monkeypatch):
    """`patch_flow.py` - and the Telegram bot with it - imports this validator."""
    real = validator_mod._executor_policy()[0]

    class _Broken:
        PolicyRefusal = real.PolicyRefusal
        check_argv = staticmethod(real.check_argv)

        @staticmethod
        def sandbox_refusal(argv):
            raise RuntimeError("boom")

    monkeypatch.setattr(validator_mod, "_executor_policy", lambda: (_Broken(), None))
    result = validate_plan(_plan(), platform_family="rhel")
    assert "executor_check_failed" in [e.code for e in result.errors]


# ---------------------------------------------------------------------------
# The approval window
# ---------------------------------------------------------------------------
def _plan_declaring(seconds_each: int) -> dict:
    plan = _plan()
    plan["apply"][0]["timeout_s"] = seconds_each
    plan["rollback"][0]["timeout_s"] = seconds_each
    return plan


def test_a_plan_whose_timeouts_do_not_fit_the_window_is_refused_by_the_validator():
    """n8n plan 1 declared 2700 s against the 2400 s budget and was refused at the signing
    prompt, after two taps and the PIN, with no way out. Now it is a validation error: the
    plan is never offered, and the planner's retry is told the numbers."""
    plan = _plan_declaring(1500)
    result = validate_plan(plan, platform_family="rhel")
    error = next(e for e in result.errors if e.code == "run_budget_exceeded")
    assert f"{approval.RUN_BUDGET_S} s" in error.message
    assert "apply 1500 s" in error.message and "rollback 1500 s" in error.message
    assert "timeout_s" in error.message


def test_the_budget_boundary_is_exact():
    """Exactly the budget fits; one second more does not - the validator and the
    challenge draw the same line (`approval.RUN_BUDGET_S`), so a plan cannot pass one and
    fail the other."""
    fits = _plan()
    flat = approval.flatten(fits, "rhel")
    slack = approval.RUN_BUDGET_S - flat.budget_s
    fits["apply"][0]["timeout_s"] += slack
    assert approval.flatten(fits, "rhel").budget_s == approval.RUN_BUDGET_S
    assert validate_plan(fits, platform_family="rhel").valid
    over = copy.deepcopy(fits)
    over["apply"][0]["timeout_s"] += 1
    assert "run_budget_exceeded" in [e.code for e in validate_plan(over, platform_family="rhel").errors]


def test_what_the_validator_counts_is_what_the_challenge_counts():
    """One definition of the sum: the validator reads `approval.flatten`, the function the
    challenge uses. A plan the challenge would refuse is exactly a plan the validator refuses."""
    for each in (300, 1000, 1190, 1210, 1500):
        plan = _plan_declaring(each)
        flat = approval.flatten(plan, "rhel")
        refused_by_validator = "run_budget_exceeded" in [e.code for e in validate_plan(plan, platform_family="rhel").errors]
        assert refused_by_validator == (flat.budget_s > approval.RUN_BUDGET_S), (each, flat.budget_s)


def test_the_standalone_validator_with_no_family_still_applies_the_budget():
    """`platform_family=None` skips the family checks, not the window."""
    assert "run_budget_exceeded" in [e.code for e in validate_plan(_plan_declaring(1500)).errors]


def test_a_stored_plan_that_the_challenge_would_refuse_is_refused_at_the_runner_too():
    """Guard 1 of the runner re-validates every plan against today's rules, so a plan stored
    before this rule existed is `rejected_invalid` instead of reaching the signing prompt."""
    import asyncio

    from sentinel.patch import runner
    from tests.unit.test_patch_runner import _FakeDB

    db = _FakeDB(_plan_declaring(1500), status="validated")
    with pytest.raises(runner.PatchRefused, match="nu mai trece validarea"):
        asyncio.run(runner.run_plan(db, None, 1, mode="dry_run"))
    assert db.plan_statuses[-1] == "rejected_invalid"


# ---------------------------------------------------------------------------
# What the planner tells the model
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("family", ["rhel", "debian"])
def test_the_planner_prompt_states_the_budget_the_validator_enforces(family):
    """A model that is not told the number drafts a plan the validator refuses and pays a
    second attempt to find out. The number is read from `approval.RUN_BUDGET_S`, never
    typed: with a copy, the prompt and the check drift apart silently."""
    text = planner._render_system(family)
    assert f"{approval.RUN_BUDGET_S} s" in text
    assert "%%" not in text


def test_the_planner_prompt_names_every_program_the_executor_refuses_to_run_in_a_step():
    """The list in the prompt (`SANDBOX_REFUSED_DOC`) is written by hand and the refusal is
    code: every program `sandbox_refusal` refuses must be named, or the model is taught a
    command the validator then rejects."""
    from tests.security.test_executor_sandbox_refusal import WRITERS

    refused_programs = {argv[0] for argv in WRITERS}
    assert {"tar", "cp", "mv", "mkdir", "install", "chmod", "chown", "nginx", "dnf", "apt-get", "apt"} <= refused_programs
    for program in refused_programs:
        assert f"`{program}" in planner.SANDBOX_REFUSED_DOC, (
            f"`{program}` is refused by the executor for a plan step, but the prompt does not say so")


@pytest.mark.parametrize("family", ["rhel", "debian"])
def test_the_planner_prompt_lists_every_path_the_validator_protects(family):
    """Rule 3 of the prompt is written by hand; `constants.PROTECTED_PATHS` is what the
    validator refuses. A path in the second and not the first is one the model is not told
    about, so it drafts a plan that names it and pays a whole attempt to be refused - which is
    how the executor's own state (`/var/lib/sentinel-executor`) was missing from it."""
    from sentinel import constants

    text = planner._render_system(family)
    missing = [path for path in constants.PROTECTED_PATHS if path not in text]
    assert missing == [], f"the planner prompt does not name: {missing}"


def test_the_planner_prompt_names_the_transactions_of_the_family():
    assert "apt-get" in planner._render_system("debian") and "install/upgrade" in planner._render_system("debian")
    assert "`dnf`" in planner._render_system("rhel")
