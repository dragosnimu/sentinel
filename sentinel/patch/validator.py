"""Deterministic safety validation for patch plans.

This is the gate between "a language model wrote a procedure" and "root runs it
on a production server". It is deliberately paranoid, deliberately boring, and
deliberately not configurable: the rules live in `sentinel.constants` and in
this file, covered by tests, so widening them is a code review rather than a
config change.

Design notes:

* Structural validation is hand-written rather than delegated to a JSON Schema
  library. The schema in `assets/patch_plan.schema.json` documents the shape for
  the model; this module is the enforcement, and it produces error messages the
  model can actually act on ("argv[0]='sh' is not in the binary allowlist"
  rather than "does not match #/$defs/argv").
* Every check appends to a list. Validation never stops at the first error —
  the generator gets one retry, so it needs all of them at once.
* A warning never blocks. If something should block, make it an error.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from sentinel.constants import (
    PATCH_BINARY_ALLOWLIST,
    PATCH_FORBIDDEN_SUBSTRINGS,
    PROTECTED_PATHS,
    REBOOT_REQUIRED_PACKAGES,
    SHELL_METACHARACTERS,
)

SCHEMA_VERSION = 1

RISK_LEVELS = ("low", "medium", "high", "critical")
BLAST_RADII = ("single-service", "multi-service", "host-wide")
ON_FAILURE = ("rollback", "abort", "continue")
BACKUP_KINDS = ("path", "mysql", "postgres", "docker_volume", "rpm_state", "git_ref")
CHECK_KINDS = (
    "http", "tcp", "systemd", "docker", "pkg_version",
    "file_exists", "file_absent", "file_sha256",
    "disk_free", "no_open_incident", "command",
)
CHECK_REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "http": ("url", "expect_status"),
    "tcp": ("host", "port"),
    "systemd": ("unit", "expect_state"),
    "docker": ("container", "expect_status"),
    "pkg_version": ("name",),
    "file_exists": ("path",),
    "file_absent": ("path",),
    "file_sha256": ("path", "sha256"),
    "disk_free": ("path", "min_bytes"),
    "no_open_incident": ("asset_id",),
    "command": ("argv",),
}

_ID_RE = re.compile(r"^[a-z0-9_]{2,16}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
MAX_TIMEOUT_S = 3600


@dataclass(frozen=True)
class Issue:
    path: str
    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"path": self.path, "code": self.code, "message": self.message}


@dataclass
class ValidationResult:
    valid: bool = True
    errors: list[Issue] = field(default_factory=list)
    warnings: list[Issue] = field(default_factory=list)
    plan_hash: str | None = None
    summary: dict[str, Any] = field(default_factory=dict)

    def error(self, path: str, code: str, message: str) -> None:
        self.errors.append(Issue(path, code, message))
        self.valid = False

    def warn(self, path: str, code: str, message: str) -> None:
        self.warnings.append(Issue(path, code, message))


def plan_hash(plan: dict[str, Any]) -> str:
    """Stable hash over the plan's *semantic* content.

    Volatile fields are excluded so that re-serialising an unchanged plan does
    not invalidate an outstanding Telegram approval. Everything that affects
    what will actually run is included.
    """
    material = {k: v for k, v in plan.items() if k not in {"plan_id", "created_at", "generated_by"}}
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def validate_plan(plan: Any) -> ValidationResult:
    """Validate a patch plan. Never raises; returns every problem found."""
    result = ValidationResult()

    if not isinstance(plan, dict):
        result.error("$", "not_an_object", f"plan must be a JSON object, got {type(plan).__name__}")
        return result

    _validate_top_level(plan, result)
    target = plan.get("target") if isinstance(plan.get("target"), dict) else {}
    _validate_target(target, result)
    _validate_vulnerabilities(plan.get("vulnerabilities"), result)
    risk = plan.get("risk") if isinstance(plan.get("risk"), dict) else {}
    _validate_risk(risk, result)

    apply_steps = _validate_step_list(plan.get("apply"), "apply", result, min_items=1)
    rollback_steps = _validate_step_list(plan.get("rollback"), "rollback", result, min_items=0)
    backups = _validate_backups(plan.get("backup"), result)

    preflight = _validate_check_list(plan.get("preflight"), "preflight", result, min_items=1)
    health = _validate_check_list(plan.get("health_check"), "health_check", result, min_items=1)
    postver = _validate_check_list(
        plan.get("post_verification"), "post_verification", result, min_items=1
    )

    _validate_coupling(plan, risk, apply_steps, rollback_steps, backups, preflight, result)
    _validate_reboot_flag(plan, risk, result)
    _validate_restore_instructions(plan, result)
    _check_duplicate_ids(apply_steps + rollback_steps, backups, preflight + health + postver, result)

    if result.valid:
        result.plan_hash = plan_hash(plan)
        result.summary = {
            "asset": target.get("asset_name"),
            "risk_level": risk.get("level"),
            "requires_reboot": bool(risk.get("requires_reboot")),
            "reversible": bool(risk.get("reversible")),
            "estimated_downtime_s": risk.get("estimated_downtime_s"),
            "preflight_checks": len(preflight),
            "backup_items": len(backups),
            "apply_steps": len(apply_steps),
            "rollback_steps": len(rollback_steps),
            "health_checks": len(health),
            "post_verifications": len(postver),
            "estimated_backup_mb": sum(int(b.get("estimated_size_mb") or 0) for b in backups),
        }
    return result


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------
def _validate_top_level(plan: dict[str, Any], r: ValidationResult) -> None:
    required = (
        "schema_version", "target", "vulnerabilities", "risk",
        "preflight", "backup", "apply", "health_check",
        "post_verification", "restore_instructions_ro",
    )
    for key in required:
        if key not in plan:
            r.error(f"$.{key}", "missing_field", f"required field {key!r} is absent")

    version = plan.get("schema_version")
    if version is not None and version != SCHEMA_VERSION:
        r.error(
            "$.schema_version",
            "bad_schema_version",
            f"expected {SCHEMA_VERSION}, got {version!r}",
        )


def _validate_target(target: dict[str, Any], r: ValidationResult) -> None:
    if not target:
        return
    for key in ("asset_id", "asset_name", "stack", "protected"):
        if key not in target:
            r.error(f"$.target.{key}", "missing_field", f"target.{key} is required")

    if target.get("protected") is True:
        r.error(
            "$.target.protected",
            "protected_asset",
            "this asset is marked protected. No automated "
            "patch plan may exist for it. Return the error object with "
            "reason_code=protected_asset instead of a plan.",
        )

    databases = target.get("databases")
    if databases is not None and not isinstance(databases, list):
        r.error("$.target.databases", "bad_type", "databases must be a list")


def _validate_vulnerabilities(vulns: Any, r: ValidationResult) -> None:
    if not isinstance(vulns, list) or not vulns:
        r.error("$.vulnerabilities", "empty", "at least one vulnerability is required")
        return
    for i, v in enumerate(vulns):
        base = f"$.vulnerabilities[{i}]"
        if not isinstance(v, dict):
            r.error(base, "bad_type", "must be an object")
            continue
        if "finding_id" not in v:
            r.error(f"{base}.finding_id", "missing_field", "finding_id is required")
        if not v.get("package"):
            r.error(f"{base}.package", "missing_field", "package is required")
        cve = v.get("cve")
        if cve and not _CVE_RE.match(str(cve)):
            r.error(f"{base}.cve", "bad_format", f"{cve!r} is not a CVE identifier")
        if v.get("fixed_in") in (None, "") and v.get("cve"):
            r.warn(
                f"{base}.fixed_in",
                "no_fixed_version",
                "no fixed version recorded; confirm a fix genuinely exists before patching",
            )


def _validate_risk(risk: dict[str, Any], r: ValidationResult) -> None:
    if not risk:
        return
    if risk.get("level") not in RISK_LEVELS:
        r.error("$.risk.level", "bad_enum", f"must be one of {RISK_LEVELS}")
    if risk.get("blast_radius") not in BLAST_RADII:
        r.error("$.risk.blast_radius", "bad_enum", f"must be one of {BLAST_RADII}")
    for key in ("requires_reboot", "reversible"):
        if not isinstance(risk.get(key), bool):
            r.error(f"$.risk.{key}", "bad_type", "must be a boolean")
    downtime = risk.get("estimated_downtime_s")
    if not isinstance(downtime, int) or downtime < 0:
        r.error("$.risk.estimated_downtime_s", "bad_type", "must be a non-negative integer")
    confidence = risk.get("confidence")
    if not isinstance(confidence, int | float) or not 0 <= float(confidence) <= 1:
        r.error("$.risk.confidence", "bad_range", "must be a number between 0 and 1")
    elif float(confidence) < 0.5:
        r.warn(
            "$.risk.confidence",
            "low_confidence",
            "confidence below 0.5 — the operator will be warned that this plan is a guess",
        )


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
def _validate_step_list(
    steps: Any, section: str, r: ValidationResult, *, min_items: int
) -> list[dict[str, Any]]:
    if steps is None and min_items == 0:
        return []
    if not isinstance(steps, list):
        r.error(f"$.{section}", "bad_type", "must be a list")
        return []
    if len(steps) < min_items:
        r.error(f"$.{section}", "too_few", f"at least {min_items} step(s) required")

    valid: list[dict[str, Any]] = []
    for i, step in enumerate(steps):
        base = f"$.{section}[{i}]"
        if not isinstance(step, dict):
            r.error(base, "bad_type", "must be an object")
            continue
        _validate_step(step, base, r)
        valid.append(step)
    return valid


def _validate_step(step: dict[str, Any], base: str, r: ValidationResult) -> None:
    step_id = step.get("id")
    if not isinstance(step_id, str) or not _ID_RE.match(step_id):
        r.error(f"{base}.id", "bad_format", "id must match ^[a-z0-9_]{2,16}$")

    desc = step.get("desc_ro")
    if not isinstance(desc, str) or len(desc.strip()) < 5:
        r.error(f"{base}.desc_ro", "missing_field", "a Romanian description of ≥5 chars is required")

    _validate_argv(step.get("argv"), f"{base}.argv", r)

    timeout = step.get("timeout_s")
    if not isinstance(timeout, int) or not 1 <= timeout <= MAX_TIMEOUT_S:
        r.error(
            f"{base}.timeout_s",
            "bad_range",
            f"timeout_s is mandatory and must be between 1 and {MAX_TIMEOUT_S}",
        )

    on_failure = step.get("on_failure")
    if on_failure not in ON_FAILURE:
        r.error(f"{base}.on_failure", "bad_enum", f"must be one of {ON_FAILURE}")
    elif on_failure == "continue":
        r.warn(
            f"{base}.on_failure",
            "continue_on_failure",
            "'continue' is only appropriate for cleanup steps; a failure here will "
            "not stop the patch",
        )

    expect = step.get("expect_exit", [0])
    if not isinstance(expect, list) or not all(isinstance(x, int) for x in expect):
        r.error(f"{base}.expect_exit", "bad_type", "must be a list of integers")
    elif len(expect) > 1:
        r.warn(
            f"{base}.expect_exit",
            "multiple_exit_codes",
            f"accepting {expect} hides failures; prefer understanding why a non-zero "
            "exit occurs",
        )

    for key in ("cwd", "run_as"):
        value = step.get(key)
        if value is not None and not isinstance(value, str):
            r.error(f"{base}.{key}", "bad_type", "must be a string")

    _check_protected_paths(step.get("cwd"), f"{base}.cwd", r)


def _validate_argv(argv: Any, path: str, r: ValidationResult) -> None:
    if isinstance(argv, str):
        r.error(
            path,
            "argv_is_string",
            "argv must be a list of strings. There is no shell: a string command "
            "cannot be executed. Split it into arguments.",
        )
        return
    if not isinstance(argv, list) or not argv:
        r.error(path, "bad_type", "argv must be a non-empty list of strings")
        return

    for i, part in enumerate(argv):
        if not isinstance(part, str):
            r.error(f"{path}[{i}]", "bad_type", f"expected str, got {type(part).__name__}")
            return

    program = argv[0]
    basename = program.rsplit("/", 1)[-1]
    allowed_absolute = program.startswith("/opt/sentinel/bin/")
    if not allowed_absolute and basename not in PATCH_BINARY_ALLOWLIST:
        r.error(
            f"{path}[0]",
            "binary_not_allowed",
            f"{program!r} is not in the binary allowlist. Allowed: "
            f"{', '.join(sorted(PATCH_BINARY_ALLOWLIST))}, or an absolute path under "
            "/opt/sentinel/bin/. Note that sh, bash, env, sudo and python are "
            "excluded deliberately — they would make the allowlist meaningless.",
        )
    if program.startswith("/") and not allowed_absolute:
        r.error(
            f"{path}[0]",
            "absolute_path_not_allowed",
            f"{program!r}: use the bare binary name, or an absolute path under "
            "/opt/sentinel/bin/",
        )

    for i, part in enumerate(argv):
        for meta in SHELL_METACHARACTERS:
            if meta in part:
                r.error(
                    f"{path}[{i}]",
                    "shell_metacharacter",
                    f"contains {meta!r}. Commands are executed directly, not through "
                    "a shell, so pipes, redirects and command substitution do not "
                    "work. Use one step per stage.",
                )
                break

        lowered = part.lower()
        for forbidden in PATCH_FORBIDDEN_SUBSTRINGS:
            if forbidden in lowered:
                r.error(
                    f"{path}[{i}]",
                    "forbidden_operation",
                    f"contains {forbidden!r}, which is never permitted in a patch plan",
                )
                break

        _check_protected_paths(part, f"{path}[{i}]", r)

    _check_nondeterministic(argv, path, r)


def _check_protected_paths(value: Any, path: str, r: ValidationResult) -> None:
    if not isinstance(value, str):
        return
    for protected in PROTECTED_PATHS:
        if value == protected or value.startswith(protected + "/"):
            r.error(
                path,
                "protected_path",
                f"{value!r} is under {protected}, which no automated change may touch. "
                "If the fix genuinely requires it, return the error object with "
                "reason_code=protected_asset and describe the manual procedure.",
            )
            return


def _check_nondeterministic(argv: list[str], path: str, r: ValidationResult) -> None:
    """Flag commands whose result depends on when they run."""
    program = argv[0].rsplit("/", 1)[-1]
    joined = " ".join(argv)

    if program == "git" and "pull" in argv:
        r.error(
            path,
            "nondeterministic",
            "`git pull` fetches whatever HEAD happens to be. Use "
            "`git checkout <sha-or-tag>` so the plan does the same thing tomorrow.",
        )
    if program == "npm" and "install" in argv and "ci" not in argv:
        r.error(
            path,
            "nondeterministic",
            "`npm install` may resolve differently from the lockfile. Use `npm ci`.",
        )
    if ":latest" in joined:
        r.error(
            path,
            "nondeterministic",
            "`:latest` is not a rollback target. Pin the image by digest "
            "(image@sha256:...).",
        )
    if program == "dnf" and "update" in argv and len(argv) <= 3:
        r.warn(
            path,
            "broad_update",
            "`dnf update` without a package name updates everything on the host. "
            "Name the package.",
        )


# ---------------------------------------------------------------------------
# Backups and checks
# ---------------------------------------------------------------------------
def _validate_backups(backups: Any, r: ValidationResult) -> list[dict[str, Any]]:
    if backups is None:
        return []
    if not isinstance(backups, list):
        r.error("$.backup", "bad_type", "must be a list")
        return []

    valid: list[dict[str, Any]] = []
    for i, item in enumerate(backups):
        base = f"$.backup[{i}]"
        if not isinstance(item, dict):
            r.error(base, "bad_type", "must be an object")
            continue
        if not _ID_RE.match(str(item.get("id", ""))):
            r.error(f"{base}.id", "bad_format", "id must match ^[a-z0-9_]{2,16}$")
        if item.get("kind") not in BACKUP_KINDS:
            r.error(f"{base}.kind", "bad_enum", f"must be one of {BACKUP_KINDS}")
        source = item.get("source")
        if not isinstance(source, str) or not source:
            r.error(f"{base}.source", "missing_field", "source is required")
        else:
            _check_protected_paths(source, f"{base}.source", r)

        restore = item.get("restore_argv")
        if restore is None:
            r.error(
                f"{base}.restore_argv",
                "missing_field",
                "restore_argv is required. The runner can create the backup from "
                "kind+source, but the way back needs your judgement.",
            )
        else:
            _validate_argv(restore, f"{base}.restore_argv", r)

        size = item.get("estimated_size_mb")
        if size is None:
            r.warn(
                f"{base}.estimated_size_mb",
                "no_size_estimate",
                "without an estimate the free-space preflight cannot be sized; "
                "run `du -sm` on the source",
            )
        valid.append(item)
    return valid


def _validate_check_list(
    checks: Any, section: str, r: ValidationResult, *, min_items: int
) -> list[dict[str, Any]]:
    if not isinstance(checks, list):
        r.error(f"$.{section}", "bad_type", "must be a list")
        return []
    if len(checks) < min_items:
        r.error(f"$.{section}", "too_few", f"at least {min_items} check(s) required")

    valid: list[dict[str, Any]] = []
    for i, item in enumerate(checks):
        base = f"$.{section}[{i}]"
        if not isinstance(item, dict):
            r.error(base, "bad_type", "must be an object")
            continue
        if not _ID_RE.match(str(item.get("id", ""))):
            r.error(f"{base}.id", "bad_format", "id must match ^[a-z0-9_]{2,16}$")
        if not isinstance(item.get("desc_ro"), str) or len(str(item.get("desc_ro"))) < 5:
            r.error(f"{base}.desc_ro", "missing_field", "a Romanian description is required")
        if not isinstance(item.get("blocking"), bool):
            r.error(f"{base}.blocking", "bad_type", "blocking must be a boolean")

        check = item.get("check")
        if not isinstance(check, dict):
            r.error(f"{base}.check", "bad_type", "check must be an object")
            valid.append(item)
            continue

        kind = check.get("kind")
        if kind not in CHECK_KINDS:
            r.error(f"{base}.check.kind", "bad_enum", f"must be one of {CHECK_KINDS}")
        else:
            for required in CHECK_REQUIRED_FIELDS[kind]:
                if required not in check:
                    r.error(
                        f"{base}.check.{required}",
                        "missing_field",
                        f"check kind {kind!r} requires {required!r}",
                    )
            if kind == "pkg_version" and not (check.get("equals") or check.get("at_least")):
                r.error(
                    f"{base}.check",
                    "missing_field",
                    "pkg_version requires either 'equals' or 'at_least'",
                )
            if kind == "command":
                _validate_argv(check.get("argv"), f"{base}.check.argv", r)
        valid.append(item)
    return valid


# ---------------------------------------------------------------------------
# Cross-section coupling — the rules that actually make a plan safe
# ---------------------------------------------------------------------------
def _validate_coupling(
    plan: dict[str, Any],
    risk: dict[str, Any],
    apply_steps: list[dict[str, Any]],
    rollback_steps: list[dict[str, Any]],
    backups: list[dict[str, Any]],
    preflight: list[dict[str, Any]],
    r: ValidationResult,
) -> None:
    non_idempotent = [s for s in apply_steps if not s.get("idempotent", False)]
    if non_idempotent and not backups:
        ids = ", ".join(str(s.get("id")) for s in non_idempotent[:5])
        r.error(
            "$.backup",
            "backup_required",
            f"steps [{ids}] are not idempotent, so at least one backup item is "
            "required. If they really are idempotent, mark them idempotent:true.",
        )

    if risk.get("reversible") is True and not rollback_steps:
        r.error(
            "$.rollback",
            "rollback_required",
            "risk.reversible is true, so a non-empty rollback section is required. "
            "If you cannot write one, set reversible:false — the plan is then "
            "flagged high_risk and needs extra approval. Do not fake a rollback.",
        )

    if risk.get("reversible") is False and rollback_steps:
        r.warn(
            "$.rollback",
            "rollback_on_irreversible",
            "reversible is false but rollback steps are present; confirm they really "
            "restore the prior state",
        )

    if not any(c.get("blocking") for c in preflight):
        r.error(
            "$.preflight",
            "no_blocking_preflight",
            "at least one preflight check must be blocking, otherwise nothing "
            "prevents the patch from running against an unexpected state",
        )

    # A patch that never confirms what is installed is patching something it did
    # not verify. This is the single most common real-world mistake.
    kinds = {
        c.get("check", {}).get("kind") for c in preflight if isinstance(c.get("check"), dict)
    }
    if "pkg_version" not in kinds and "command" not in kinds and "file_sha256" not in kinds:
        r.warn(
            "$.preflight",
            "no_version_check",
            "no preflight confirms the installed version matches the finding; a stale "
            "finding would cause a pointless or harmful change",
        )
    if backups and "disk_free" not in kinds:
        r.error(
            "$.preflight",
            "no_disk_check",
            "a backup is planned but no disk_free preflight exists. Backing up into a "
            "full filesystem fails halfway and leaves no way back.",
        )

    # Rollback steps must not themselves trigger a rollback.
    for i, step in enumerate(rollback_steps):
        if step.get("on_failure") == "rollback":
            r.error(
                f"$.rollback[{i}].on_failure",
                "recursive_rollback",
                "a rollback step cannot itself trigger a rollback; use 'abort'",
            )

    databases = plan.get("target", {}).get("databases") or []
    if databases:
        backup_kinds = {b.get("kind") for b in backups}
        if not backup_kinds & {"mysql", "postgres"}:
            r.error(
                "$.backup",
                "database_not_backed_up",
                f"the target has {len(databases)} database(s) but no database backup "
                "item. File-only backups do not roll back schema or data changes.",
            )


def _validate_reboot_flag(
    plan: dict[str, Any], risk: dict[str, Any], r: ValidationResult
) -> None:
    packages = {
        str(v.get("package", "")).lower()
        for v in (plan.get("vulnerabilities") or [])
        if isinstance(v, dict)
    }
    touched = " ".join(
        " ".join(s.get("argv", [])) if isinstance(s.get("argv"), list) else ""
        for s in (plan.get("apply") or [])
        if isinstance(s, dict)
    ).lower()

    for pkg in REBOOT_REQUIRED_PACKAGES:
        if any(p.startswith(pkg) for p in packages) or f" {pkg}" in f" {touched}":
            if not risk.get("requires_reboot"):
                r.error(
                    "$.risk.requires_reboot",
                    "reboot_flag_required",
                    f"this plan touches {pkg!r}, which requires a reboot to take "
                    "effect. Set requires_reboot:true — it triggers a separate "
                    "approval so the operator is not surprised by a restart.",
                )
            return


def _validate_restore_instructions(plan: dict[str, Any], r: ValidationResult) -> None:
    text = plan.get("restore_instructions_ro")
    if not isinstance(text, str) or len(text.strip()) < 20:
        r.error(
            "$.restore_instructions_ro",
            "too_short",
            "write the manual restore procedure the operator would follow with "
            "Sentinel stopped and the database unreachable — that is the situation "
            "in which they will read it",
        )


def _check_duplicate_ids(
    steps: list[dict[str, Any]],
    backups: list[dict[str, Any]],
    checks: list[dict[str, Any]],
    r: ValidationResult,
) -> None:
    for label, items in (("step", steps), ("backup", backups), ("check", checks)):
        seen: set[str] = set()
        for item in items:
            item_id = item.get("id")
            if not isinstance(item_id, str):
                continue
            if item_id in seen:
                r.error(
                    f"$.{label}[id={item_id}]",
                    "duplicate_id",
                    f"{label} id {item_id!r} appears more than once; ids identify rows "
                    "in the audit trail and must be unique",
                )
            seen.add(item_id)
