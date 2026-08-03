"""The patch validator is the gate between "a model wrote a procedure" and
"root runs it on a production server". These tests are the specification.

Each test breaks exactly one thing in an otherwise-valid plan, so a failure
names the rule that stopped working rather than producing a wall of errors.
"""

from __future__ import annotations

from typing import Any

import pytest

from sentinel.patch.validator import plan_hash, validate_plan


def codes(plan: Any) -> set[str]:
    return {e.code for e in validate_plan(plan).errors}


# ---------------------------------------------------------------------------
def test_good_plan_is_valid(good_plan):
    result = validate_plan(good_plan)
    assert result.valid, [e.as_dict() for e in result.errors]
    assert result.plan_hash
    assert result.summary["apply_steps"] == 3
    assert result.summary["rollback_steps"] == 2


def test_non_object_is_rejected():
    assert "not_an_object" in codes(["not", "a", "plan"])
    assert "not_an_object" in codes("still not a plan")


# ---------------------------------------------------------------------------
# argv shape — the rule that stops a shell existing at all
# ---------------------------------------------------------------------------
def test_argv_as_string_is_rejected(broken_plan):
    """The single most likely mistake, and the most dangerous to accept."""
    assert "argv_is_string" in codes(broken_plan("apply.0.argv", "dnf -y update nginx"))


@pytest.mark.parametrize(
    "argv",
    [
        ["bash", "-c", "true"],
        ["sh", "-c", "true"],
        ["env", "FOO=1", "dnf", "update"],
        ["sudo", "dnf", "update"],
        ["python3", "-c", "import os"],
        ["perl", "-e", "1"],
    ],
)
def test_shell_and_interpreter_binaries_are_rejected(broken_plan, argv):
    """These would turn an argv allowlist into no allowlist at all."""
    assert "binary_not_allowed" in codes(broken_plan("apply.0.argv", argv))


@pytest.mark.parametrize(
    "arg",
    ["a|b", "a;b", "a&&b", "$(id)", "`id`", "a>b", "a<b", "a\nb", "a\x00b"],
)
def test_shell_metacharacters_are_rejected(broken_plan, arg):
    assert "shell_metacharacter" in codes(broken_plan("apply.0.argv", ["dnf", arg]))


def test_absolute_path_outside_sentinel_bin_is_rejected(broken_plan):
    assert "absolute_path_not_allowed" in codes(
        broken_plan("apply.0.argv", ["/usr/bin/dnf", "update"])
    )


def test_sentinel_bin_absolute_path_is_allowed(broken_plan):
    plan = broken_plan("apply.0.argv", ["/opt/sentinel/bin/sentinel-restore-mysql", "--db", "x"])
    assert "binary_not_allowed" not in codes(plan)
    assert "absolute_path_not_allowed" not in codes(plan)


# ---------------------------------------------------------------------------
# Protected targets
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "path",
    [
        "/opt/sentinel",
        "/opt/sentinel/venv/bin/python",
        "/etc/sentinel",
        "/etc/sentinel/secrets.env",
        "/var/backups/sentinel",
        "/root/.ssh/authorized_keys",
        "/etc/ssh/sshd_config",
        "/etc/shadow",
        "/etc/sudoers.d/anything",
        "/boot/vmlinuz",
    ],
)
def test_protected_paths_are_rejected(broken_plan, path):
    """Sentinel does not patch itself, and it does not touch the paths whose
    corruption would lock the operator out or escalate privileges."""
    assert "protected_path" in codes(broken_plan("apply.0.argv", ["tar", "-cf", "/tmp/x", path]))


@pytest.mark.parametrize(
    "arg",
    ["mkfs.ext4", "dd if=/dev/zero", "/dev/sda", "nft", "iptables", "--no-preserve-root",
     "usermod", "authorized_keys"],
)
def test_forbidden_operations_are_rejected(broken_plan, arg):
    assert "forbidden_operation" in codes(broken_plan("apply.0.argv", ["dnf", arg]))


def test_protected_asset_gets_no_plan(broken_plan):
    assert "protected_asset" in codes(broken_plan("target.protected", True))


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "argv",
    [
        ["git", "pull"],
        ["npm", "install"],
        ["docker", "pull", "nginx:latest"],
    ],
)
def test_nondeterministic_commands_are_rejected(broken_plan, argv):
    """A plan must do the same thing tomorrow as it does today."""
    assert "nondeterministic" in codes(broken_plan("apply.0.argv", argv))


def test_npm_ci_is_allowed(broken_plan):
    assert "nondeterministic" not in codes(broken_plan("apply.0.argv", ["npm", "ci"]))


# ---------------------------------------------------------------------------
# Structural coupling — the rules that make a plan recoverable
# ---------------------------------------------------------------------------
def test_reversible_plan_requires_rollback(broken_plan):
    assert "rollback_required" in codes(broken_plan("rollback", []))


def test_irreversible_plan_may_omit_rollback(good_plan):
    plan = dict(good_plan)
    plan["risk"] = {**good_plan["risk"], "reversible": False}
    plan["rollback"] = []
    assert "rollback_required" not in codes(plan)


def test_non_idempotent_steps_require_backup(good_plan):
    plan = dict(good_plan)
    plan["apply"] = [{**good_plan["apply"][0], "idempotent": False}]
    plan["backup"] = []
    assert "backup_required" in codes(plan)


def test_backup_requires_disk_free_preflight(good_plan):
    """Backing up into a full filesystem fails halfway and leaves no way back."""
    plan = dict(good_plan)
    plan["preflight"] = [c for c in good_plan["preflight"] if c["check"]["kind"] != "disk_free"]
    assert "no_disk_check" in codes(plan)


def test_database_must_be_backed_up(broken_plan):
    """Files-only backup does not roll back a schema change."""
    plan = broken_plan("target.databases", [{"engine": "mariadb", "name": "blog"}])
    assert "database_not_backed_up" in codes(plan)


def test_at_least_one_blocking_preflight_required(good_plan):
    plan = dict(good_plan)
    plan["preflight"] = [{**c, "blocking": False} for c in good_plan["preflight"]]
    assert "no_blocking_preflight" in codes(plan)


def test_rollback_step_cannot_trigger_rollback(broken_plan):
    assert "recursive_rollback" in codes(broken_plan("rollback.0.on_failure", "rollback"))


def test_duplicate_step_ids_are_rejected(good_plan):
    plan = dict(good_plan)
    plan["apply"] = [good_plan["apply"][0], {**good_plan["apply"][1], "id": "ap1"}]
    assert "duplicate_id" in codes(plan)


# ---------------------------------------------------------------------------
# Reboot flag
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("package", ["kernel", "glibc", "systemd", "openssl"])
def test_reboot_flag_is_mandatory_for_core_packages(good_plan, package):
    """A surprise reboot on a production server is not acceptable."""
    plan = dict(good_plan)
    plan["vulnerabilities"] = [{**good_plan["vulnerabilities"][0], "package": package}]
    plan["risk"] = {**good_plan["risk"], "requires_reboot": False}
    assert "reboot_flag_required" in codes(plan)


# ---------------------------------------------------------------------------
# Required fields
# ---------------------------------------------------------------------------
def test_timeout_is_mandatory(broken_plan):
    assert "bad_range" in codes(broken_plan("apply.0.timeout_s", ...))


def test_restore_instructions_must_be_substantial(broken_plan):
    assert "too_short" in codes(broken_plan("restore_instructions_ro", "vezi backup"))


def test_backup_item_requires_restore_command(broken_plan):
    assert "missing_field" in codes(broken_plan("backup.0.restore_argv", ...))


def test_check_kind_required_fields(broken_plan):
    assert "missing_field" in codes(
        broken_plan("health_check.1.check", {"kind": "http", "timeout_s": 5})
    )


# ---------------------------------------------------------------------------
# `source` means something different per kind
# ---------------------------------------------------------------------------
def test_rpm_state_source_must_be_a_package_not_a_path(broken_plan):
    """The one that reached production. `/var/lib/rpm` reads correctly — it IS
    the RPM database — but the executor's rpm_state records one package's exact
    version, which is what makes `dnf downgrade` in restore_argv possible.
    `rpm -q /var/lib/rpm` exits 1, and the patch aborts at backup, after the
    operator has already confirmed twice."""
    assert "bad_format" in codes(broken_plan("backup.0.source", "/var/lib/rpm"))
    assert "bad_format" in codes(broken_plan("backup.0.source", "/usr/bin/curl"))


def test_rpm_state_accepts_a_real_package_name(good_plan):
    plan = dict(good_plan)
    for name in ("curl", "nginx", "python3.12", "kernel-core", "gcc-c++"):
        plan["backup"] = [{**good_plan["backup"][0], "source": name}]
        assert "bad_format" not in codes(plan), name


def test_path_kinds_must_be_absolute(broken_plan):
    """The mirror image: a `path` backup whose source is a bare name would tar
    up whatever the executor's working directory happens to contain."""
    assert "bad_format" in codes(broken_plan("backup.1.source", "nginx"))
    assert "bad_format" in codes(broken_plan("backup.1.source", "etc/nginx"))


# ---------------------------------------------------------------------------
# The prompt has to agree with the validator, or every plan costs two calls
# ---------------------------------------------------------------------------
def test_prompt_lists_the_required_field_of_every_check_kind():
    """The prompt used to name the check kinds and stop there, so the model
    invented the fields — `disk_free` with no `min_bytes`, `no_open_incident`
    with no `asset_id`. Both attempts rejected for the same omission: real money
    for a guaranteed refusal."""
    from sentinel.patch.planner import PLANNER_SYSTEM
    from sentinel.patch.validator import CHECK_REQUIRED_FIELDS

    for kind, fields in CHECK_REQUIRED_FIELDS.items():
        assert f"· {kind}:" in PLANNER_SYSTEM, f"{kind} is not described to the model"
        for field in fields:
            line = next(l for l in PLANNER_SYSTEM.splitlines() if l.strip().startswith(f"· {kind}:"))
            assert field in line, f"{kind} requires {field}, and the prompt omits it"


def test_the_prompt_placeholder_was_actually_substituted():
    """A silent `.replace` miss would leave `%%CHECK_FIELDS%%` in the system
    prompt — syntactically fine, and the model told nothing."""
    from sentinel.patch.planner import PLANNER_SYSTEM
    assert "%%" not in PLANNER_SYSTEM


def test_the_rejection_says_what_to_write_instead(broken_plan):
    """A validation error is fed back to the model for one retry, so it has to
    be actionable — 'bad format' alone earns a second identical mistake."""
    from sentinel.patch.validator import validate_plan
    plan = broken_plan("backup.0.source", "/var/lib/rpm")
    msg = next(e.message for e in validate_plan(plan).errors if "rpm_state" in e.message)
    assert "NAME" in msg and "curl" in msg


# ---------------------------------------------------------------------------
# Plan hash — the binding between an approval and a specific plan
# ---------------------------------------------------------------------------
def test_hash_is_stable_across_volatile_fields(good_plan):
    a = dict(good_plan, plan_id="uuid-1", created_at="2026-01-01T00:00:00Z")
    b = dict(good_plan, plan_id="uuid-2", created_at="2026-07-29T12:00:00Z")
    assert plan_hash(a) == plan_hash(b)


def test_hash_changes_when_a_command_changes(good_plan, broken_plan):
    """Regenerating a plan must kill every outstanding approval button."""
    changed = broken_plan("apply.0.argv", ["dnf", "-y", "update", "httpd"])
    assert plan_hash(good_plan) != plan_hash(changed)
