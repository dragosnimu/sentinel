"""P9 safety invariants — the tests that matter most in this project.

Everything here asserts that something dangerous is REFUSED. The patch pipeline
runs commands as root on a live machine, so the interesting question is never
"does it work", it is "what does it refuse to do".
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
EXECUTOR = (REPO / "executor" / "commands.py").read_text(encoding="utf-8")
RUNNER = (REPO / "sentinel" / "patch" / "runner.py").read_text(encoding="utf-8")
BACKUP = (REPO / "sentinel" / "patch" / "backup.py").read_text(encoding="utf-8")


# --- the delete door --------------------------------------------------------
def test_rm_is_not_in_the_patch_binary_allowlist():
    """A patch plan must not be able to delete anything. Deletion goes through
    one narrow, path-scoped executor operation instead."""
    from sentinel.constants import PATCH_BINARY_ALLOWLIST
    for dangerous in ("rm", "rmdir", "shred", "mkfs", "dd", "nft", "iptables",
                      "useradd", "usermod", "passwd", "bash", "sh", "python",
                      "python3", "perl", "chroot", "mount", "umount"):
        assert dangerous not in PATCH_BINARY_ALLOWLIST, \
            f"{dangerous!r} must never be runnable from a patch plan"


def test_backup_prune_only_deletes_direct_children_of_the_backup_root():
    body = _func(EXECUTOR, "op_backup_prune")
    # id is stripped of every separator, so traversal is not expressible
    assert 're.sub(r"[^A-Za-z0-9_-]"' in body
    # and the resolved path is re-checked against the root AFTER resolution
    assert "target.parent != root" in body
    assert ".resolve()" in body
    assert "is_symlink()" in body


def test_prune_passes_an_id_not_a_path():
    # If the caller could pass a path, a bug on the unprivileged side would
    # become a root delete anywhere.
    assert "backup_prune" in BACKUP
    assert "restore_point_id=rp_id" in BACKUP
    assert 'argv=["rm"' not in BACKUP


# --- the restore script -----------------------------------------------------
def test_restore_script_is_generated_inside_the_executor():
    """Caller-supplied text must never become a line of a root-owned executable.
    The script is composed from what the executor itself sees on disk."""
    body = _func(EXECUTOR, "op_backup_finalize")
    assert "#!/usr/bin/env bash" in body          # generated here, not received
    assert "0o700" in body
    # The only caller input is the restore-point id, and it is sanitised.
    assert 'restore_point = re.sub(r"[^A-Za-z0-9_-]"' in body
    # The unprivileged side must not build the script at all any more.
    assert "#!/usr/bin/env bash" not in BACKUP


def test_sealing_recomputes_checksums_rather_than_trusting_the_caller():
    body = _func(EXECUTOR, "op_backup_finalize")
    assert "hashlib.sha256()" in body
    assert "handle.read(1 << 20)" in body         # streams, so size is no object


def test_restore_script_verifies_before_touching_anything():
    body = _func(EXECUTOR, "op_backup_finalize")
    # sha256sum -c must run before any tar extraction line is emitted
    verify_at = body.index("sha256sum -c")
    extract_at = body.index("tar --use-compress-program=unzstd")
    assert verify_at < extract_at
    assert "exit 1" in body                       # and it aborts on mismatch


# --- the runner -------------------------------------------------------------
def test_runner_revalidates_at_execution_time():
    """A row in a database is not a promise: constants change and code is
    redeployed between storing a plan and running it."""
    assert "validate_plan(plan)" in RUNNER
    assert "rejected_invalid" in RUNNER


def test_runner_checks_the_hash_matches_the_stored_plan():
    assert "plan_hash(plan)" in RUNNER
    assert "hash-ul planului nu corespunde" in RUNNER


def test_apply_requires_an_approved_plan():
    assert 'if mode == "apply" and row.status != "approved"' in RUNNER


def test_step_row_is_written_before_the_command_runs():
    """A crash mid-command must leave a row saying which command was in flight."""
    body = _func(RUNNER, "_exec_step")
    begin_at = body.index("repo.begin_step")
    call_at = body.index('_client.call, "patch_step_exec"')
    assert begin_at < call_at


def test_failure_during_apply_triggers_rollback():
    assert "_rollback(db, execution_id, plan, seq, reason)" in RUNNER
    assert "rollback_failed" in RUNNER


def test_failure_before_any_change_does_not_roll_back():
    # Rolling back when nothing was applied is a pointless risk of its own.
    assert 'if phase in ("preflight", "backup") or dry:' in RUNNER
    assert '"aborted"' in RUNNER


def test_execution_never_ends_in_running_even_on_a_crash():
    body = _func(RUNNER, "run_plan")
    assert "except Exception" in body
    assert body.count("finish_execution") >= 3    # every exit path closes the row


def test_rollback_is_never_a_dry_run():
    body = _func(RUNNER, "_rollback")
    assert "dry_run=False" in body


def test_approval_is_conditional_inside_the_update():
    """Check-then-act would approve a plan nobody saw if it were regenerated in
    between; the hash condition lives in the UPDATE."""
    repo_src = (REPO / "sentinel" / "db" / "repo" / "patches.py").read_text(encoding="utf-8")
    body = _func(repo_src, "approve_plan")
    assert "AND plan_hash = $3" in body
    assert "AND status = 'validated'" in body


def test_retention_never_deletes_the_last_point_for_an_asset():
    repo_src = (REPO / "sentinel" / "db" / "repo" / "patches.py").read_text(encoding="utf-8")
    body = _func(repo_src, "prunable_restore_points")
    assert "per_asset_rank > 1" in body           # the last one per asset survives
    assert "NOT retention_hold" in body
    assert "verify_error IS NULL" in body         # never prune a good one for a bad one


def _func(source: str, name: str) -> str:
    """The body of one top-level function, up to the next top-level def.
    Handles `async def` as well — most of this pipeline is async."""
    m = re.search(
        rf"^(?:async )?def {re.escape(name)}\(.*?(?=^(?:async )?def |\Z)",
        source, re.S | re.M)
    assert m, f"function {name} not found"
    return m.group(0)


def test_no_plan_is_generated_for_a_protected_asset():
    """The validator refuses every automated plan for a protected asset, so
    generating one is a guaranteed rejection — and an Opus call costs real money.
    Observed live: the model correctly refused to write apply steps, the plan was
    invalid because of it, and $0.13 bought nothing. The gate belongs upstream."""
    planner = (REPO / "sentinel" / "patch" / "planner.py").read_text(encoding="utf-8")
    body = _func(planner, "generate")
    gate_at = body.index('ctx.get("protected")')
    call_at = body.index("call_structured")
    assert gate_at < call_at, "the protected check must precede the model call"
    assert "asset protejat" in body


def test_no_plan_without_a_known_fix():
    planner = (REPO / "sentinel" / "patch" / "planner.py").read_text(encoding="utf-8")
    body = _func(planner, "generate")
    assert 'ctx.get("fixed_version")' in body


def test_generation_retries_once_then_stops():
    """An unbounded retry loop against a model that keeps producing the same
    invalid shape is just a way to spend the daily budget in one minute."""
    planner = (REPO / "sentinel" / "patch" / "planner.py").read_text(encoding="utf-8")
    assert "MAX_ATTEMPTS = 2" in planner
    body = _func(planner, "generate")
    assert "rejected_invalid" in body       # and the failure is kept as evidence


def test_invalid_plans_are_stored_not_discarded():
    planner = (REPO / "sentinel" / "patch" / "planner.py").read_text(encoding="utf-8")
    body = _func(planner, "generate")
    assert "validation_errors=" in body


def test_an_empty_backup_artifact_is_a_failure():
    """A backup that captured nothing is the most dangerous kind of failure: it
    looks like a way back right up until you need it. Found live — `rpm -q` on a
    path instead of a package name wrote an empty file and reported ok=True with
    a valid checksum of nothing, because only `kind == "path"` was exit-checked."""
    body = _func(EXECUTOR, "op_backup_create")
    assert 'if result["exit_code"] != 0:' in body
    assert 'and kind == "path"' not in body      # the old, narrow check is gone
    assert "st_size == 0" in body
    assert "empty artifact" in body
