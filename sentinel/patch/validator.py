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
    PLATFORM_FAMILIES,
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

# Package-manager binaries that only make sense on ONE platform family. A `dnf`
# step in a plan meant for a `debian` host — or `apt-get` on `rhel` — is not a
# procedure mistake the model can be asked to fix on retry: it is proof the
# plan was drafted for the wrong operating system, because the planner prompt
# used to say "AlmaLinux 9" unconditionally regardless of what
# `platform.family` actually held. Keyed the same as
# `sentinel.constants.PLATFORM_FAMILIES`, deliberately not imported from there:
# this is about which BINARY belongs to which family, a validator-local
# judgement, not the family list itself.
PLATFORM_PACKAGE_BINARIES: dict[str, frozenset[str]] = {
    "rhel": frozenset({"dnf", "rpm"}),
    "debian": frozenset({"apt-get", "apt", "dpkg", "dpkg-query"}),
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
def validate_plan(
    plan: Any,
    *,
    platform_family: str | None = None,
    finding: dict[str, Any] | None = None,
) -> ValidationResult:
    """Validate a patch plan. Never raises; returns every problem found.

    Two keyword-only arguments make this check TRUTH, not just FORM, for the
    two ways a plan has fabricated facts in production:

    * `platform_family` — the host's `cfg.platform.family` ("rhel" or
      "debian"). When given, an `argv[0]` that is a package-manager binary of
      the OTHER family is rejected: a plan is not "correct" merely because it
      is schema-valid, and `dnf` on a Debian host is proof of exactly that gap.
      `None` (the default) skips the check — callers that genuinely do not
      know the host's family, like the standalone skill CLI, get the same
      behaviour as before this argument existed, not a guess.
    * `finding` — the deterministic facts (`finding_id`, `cve`, `package`) the
      plan was generated FOR, read from the database, never from the model.
      When given, `plan["vulnerabilities"]` is checked against it: a different
      `finding_id`, a CVE the finding does not have, or a different package are
      all rejected. This is what makes fabrication — `finding_id: 0`,
      `CVE-0000-00000` — impossible to validate rather than merely unlikely to
      be asked for. `None` skips the check for callers with no finding in hand
      (e.g. `runner.run_plan`'s execution-time re-validation, which validates
      whatever plan was already approved, not a fresh generation request).
    """
    result = ValidationResult()

    if not isinstance(plan, dict):
        result.error("$", "not_an_object", f"plan must be a JSON object, got {type(plan).__name__}")
        return result

    _validate_top_level(plan, result)
    target = plan.get("target") if isinstance(plan.get("target"), dict) else {}
    _validate_target(target, result)
    _validate_vulnerabilities(plan.get("vulnerabilities"), result, finding=finding)
    risk = plan.get("risk") if isinstance(plan.get("risk"), dict) else {}
    _validate_risk(risk, result)

    apply_steps = _validate_step_list(plan.get("apply"), "apply", result, min_items=1)
    rollback_steps = _validate_step_list(plan.get("rollback"), "rollback", result, min_items=0)
    backups = _validate_backups(plan.get("backup"), result, platform_family=platform_family)

    preflight = _validate_check_list(plan.get("preflight"), "preflight", result, min_items=1)
    health = _validate_check_list(plan.get("health_check"), "health_check", result, min_items=1)
    postver = _validate_check_list(
        plan.get("post_verification"), "post_verification", result, min_items=1
    )

    _validate_platform_binaries(
        platform_family, apply_steps, rollback_steps, backups, preflight, health, postver, result
    )
    _validate_executor_grammar(
        platform_family, apply_steps, rollback_steps, backups,
        preflight, health, postver, result
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


def _validate_vulnerabilities(
    vulns: Any, r: ValidationResult, *, finding: dict[str, Any] | None = None
) -> None:
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

        if finding is None:
            continue

        # The finding this plan was actually generated for, read from the
        # database by the caller — never from the model's own output. A plan
        # is not "about" whatever finding_id it happens to write down; it is
        # about the finding it was asked to fix, and a mismatch here is not a
        # formatting slip, it is the model inventing an identifier it was
        # never given (measured: `finding_id: 0`, `CVE-0000-00000` — both
        # schema-valid, both fabricated).
        expected_id = finding.get("finding_id")
        if expected_id is not None and "finding_id" in v and v.get("finding_id") != expected_id:
            r.error(
                f"{base}.finding_id",
                "finding_id_mismatch",
                f"finding_id {v.get('finding_id')!r} does not match the finding this "
                f"plan was generated for ({expected_id!r}) — a plan may not claim to "
                "fix a finding other than the one it was asked about",
            )

        expected_cve = finding.get("cve")
        if cve:
            if not expected_cve or str(cve).upper() != str(expected_cve).upper():
                have = expected_cve or "no CVE at all"
                r.error(
                    f"{base}.cve",
                    "cve_mismatch",
                    f"{cve!r} is not the CVE of the requested finding (it has {have!r}) "
                    "— do not attribute a CVE the finding does not carry; if it has "
                    "none, leave cve empty",
                )

        expected_package = finding.get("package")
        pkg = v.get("package")
        if (
            expected_package
            and pkg
            and str(pkg).strip().lower() != str(expected_package).strip().lower()
        ):
            r.error(
                f"{base}.package",
                "package_mismatch",
                f"{pkg!r} does not match the requested finding's package "
                f"{expected_package!r}",
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
# `source` means a different thing per kind, and getting it wrong is not caught
# by anything downstream until the executor runs — at which point the operator
# has already approved twice and is watching a patch abort.
#
# The specific failure this exists for: a plan asked to back up `rpm_state` with
# source `/var/lib/rpm`. That reads correctly — it IS the RPM database — but the
# executor's `rpm_state` records the installed `name-version-release.arch` of one
# package, which is what makes the `dnf downgrade` in restore_argv meaningful.
# `rpm -q /var/lib/rpm` exits 1, so the backup fails and the patch aborts.
#
# The prompt already stated the contract. Stating it was not enough: the model is
# the drafting tool and the validator is the authority, so the authority has to
# know the rule too.
_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")

_PATH_KINDS = ("path", "git_ref")
_NAME_KINDS = ("rpm_state", "mysql", "postgres", "docker_volume")


def _check_source_shape(kind: str, source: str, path: str, r: ValidationResult) -> None:
    if kind in _NAME_KINDS:
        if source.startswith("/"):
            r.error(
                path, "bad_format",
                f"{kind} takes a NAME, not a filesystem path — got {source!r}. "
                f"For rpm_state that is the package (e.g. \"curl\"); the executor "
                f"records its exact version so restore_argv can pin it.",
            )
        elif not _PKG_NAME_RE.match(source):
            r.error(path, "bad_format",
                    f"{kind} source {source!r} is not a valid name")
    elif kind in _PATH_KINDS and not source.startswith("/"):
        r.error(path, "bad_format",
                f"{kind} takes an absolute path — got {source!r}")


# `BACKUP_KINDS` has no Debian package-state equivalent to `rpm_state` — the
# executor's `rpm_state` op runs `rpm -q`, a binary that does not exist on a
# Debian host, so a plan that picks it there aborts at the FIRST apply step,
# before anything changes. Adding a `dpkg_state` kind would mean touching the
# executor, a separate batch; `path` (the package's own files or config) is
# already an available, sufficient backup for a Debian package update, so the
# rule here is a refusal, not a substitution: pick something that exists on
# this host.
BACKUP_KIND_UNAVAILABLE_ON: dict[str, frozenset[str]] = {
    "rpm_state": frozenset({"debian"}),
}


def _validate_backups(
    backups: Any, r: ValidationResult, *, platform_family: str | None = None
) -> list[dict[str, Any]]:
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
        kind = item.get("kind")
        if kind not in BACKUP_KINDS:
            r.error(f"{base}.kind", "bad_enum", f"must be one of {BACKUP_KINDS}")
        elif platform_family and platform_family in BACKUP_KIND_UNAVAILABLE_ON.get(kind, ()):
            r.error(
                f"{base}.kind", "backup_kind_wrong_platform",
                f"{kind!r} does not exist on platform.family={platform_family!r} "
                f"(it runs a binary that host does not have). Use 'path' to back "
                f"up the package's own files or configuration instead.",
            )
        source = item.get("source")
        if not isinstance(source, str) or not source:
            r.error(f"{base}.source", "missing_field", "source is required")
        else:
            _check_protected_paths(source, f"{base}.source", r)
            _check_source_shape(str(item.get("kind", "")), source, f"{base}.source", r)

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
# Platform coupling — the argv that runs must belong on the host it runs on
# ---------------------------------------------------------------------------
def _iter_plan_argvs(
    apply_steps: list[dict[str, Any]],
    rollback_steps: list[dict[str, Any]],
    backups: list[dict[str, Any]],
    *check_lists: list[dict[str, Any]],
    builder: Any = None,
    family: str | None = None,
):
    """Every argv the runner could actually execute, with a path for errors.

    Three shapes carry a command LITERALLY — an apply/rollback step's `argv`
    and a backup's `restore_argv` — and the checks carry them by
    construction: `sentinel/patch/checks.py` BUILDS an argv for six of the
    eleven check kinds (`command`, `systemd`, `file_exists`, `file_absent`,
    `file_sha256`, `pkg_version`) and sends each down the same
    `patch_step_exec` path the apply steps use.

    This function used to look only at `kind == "command"`, because
    `checks.py`'s own module docstring said that was the only kind reaching
    the executor. It was not, and the cost was measured: a `systemd` health
    check naming `dbus.service` (an `UNCONTROLLABLE_UNITS` entry) or a
    `file_exists` on `/etc/shadow` validated clean, and the refusal arrived
    at run time — for a health check, that is AFTER the apply step has
    already changed the machine, so the plan rolls back a patch that
    succeeded.

    The fix is not five more `if kind ==` branches here; that is a second
    list that goes stale the next time a kind is added. `builder` is
    `checks.argv_for`, the same function `_dispatch` uses to execute, so the
    set of commands inspected here is derived from the code that produces
    them. Without a `builder` (a caller that could not import `checks`) this
    degrades to the literal argvs only — and `_validate_executor_grammar`
    has already refused the plan in that case, so the narrower walk cannot
    let anything through.
    """
    for step in (*apply_steps, *rollback_steps):
        argv = step.get("argv")
        if isinstance(argv, list) and argv:
            yield f"argv[id={step.get('id')}]", argv
    for b in backups:
        argv = b.get("restore_argv")
        if isinstance(argv, list) and argv:
            yield f"backup[id={b.get('id')}].restore_argv", argv
    for checks in check_lists:
        for item in checks:
            check = item.get("check")
            if not isinstance(check, dict):
                continue
            if builder is None:
                argv = check.get("argv") if check.get("kind") == "command" else None
            else:
                try:
                    argv = builder(check, family or "")
                except Exception:
                    # A check missing a required field: `_validate_check_list`
                    # has already recorded that as an error, and guessing what
                    # the author meant is not this function's job.
                    argv = None
            if isinstance(argv, list) and argv:
                yield f"check[id={item.get('id')}].argv", argv


def _validate_platform_binaries(
    platform_family: str | None,
    apply_steps: list[dict[str, Any]],
    rollback_steps: list[dict[str, Any]],
    backups: list[dict[str, Any]],
    preflight: list[dict[str, Any]],
    health: list[dict[str, Any]],
    postver: list[dict[str, Any]],
    r: ValidationResult,
) -> None:
    """Reject a package-manager binary that belongs to a DIFFERENT platform
    family than the one this plan will run on.

    `None` (family unknown to the caller) skips this rather than guessing —
    the same "unknown is not fine" rule `unplannable_reason` already applies
    upstream of generation. This is the check that keeps that rule true after
    the fact: a prompt edit that reintroduces "AlmaLinux 9" as a literal would,
    without this, again produce a `dnf` plan on a Debian host that validates
    clean — exactly today's defect, silently reopened.
    """
    if not platform_family:
        return
    forbidden: set[str] = set()
    for family, binaries in PLATFORM_PACKAGE_BINARIES.items():
        if family != platform_family:
            forbidden |= binaries
    if not forbidden:
        return
    builder, _ = _check_argv_builder()
    for path, argv in _iter_plan_argvs(
            apply_steps, rollback_steps, backups, preflight, health, postver,
            builder=builder, family=platform_family):
        program = str(argv[0]).rsplit("/", 1)[-1]
        if program in forbidden:
            r.error(
                f"$.{path}[0]",
                "binary_wrong_platform",
                f"{program!r} is a package-manager binary for a different platform "
                f"family than this host (platform.family={platform_family!r}). The "
                "plan was drafted for the wrong operating system.",
            )


# ---------------------------------------------------------------------------
# The executor's grammar is the authority — this module does not keep a second
# opinion about it
# ---------------------------------------------------------------------------
# `executor/policy.py` is the thing that actually decides, as root, whether a
# command runs: `patch_step_exec` and `backup_restore` in `executor/commands.py`
# both call its `check_argv` before executing anything. This module used to
# carry its own, independent idea of what an argv may look like, and the two
# drifted exactly as far as nobody was comparing them. Measured on 18 September
# 2026: the validator blessed `apt-get -y install --only-upgrade polkitd`,
# which `check_argv` refuses outright, so every Debian plan that reached the
# operator on Telegram was guaranteed to die at apply step 1 — and the fixture
# plan's own `["systemctl", "reload", "nginx"]` is refused for the same reason
# (the executor requires a full unit name), which is the rhel half of the same
# defect.
#
# So the question is asked of the module that answers it for real, instead of
# being answered a second time here. Two properties of HOW it is asked matter:
#
# * The import is lazy, and its failure is an error ON THE PLAN, never an
#   exception at import time. `sentinel/telegram/patch_flow.py` imports this
#   module, so a module-level `from executor import policy` would turn a
#   missing file into a crash-looping Telegram bot — the one failure this
#   repository has already paid a full day for.
# * A validator that cannot reach the grammar does not know whether the plan
#   is safe. It says so and refuses; "unknown" and "fine" are different states.
#
# Deployment: `deploy/install.sh` step 24 installs the same `policy.py` twice —
# `/opt/sentinel/libexec/policy.py` is what the root process runs, and
# `/opt/sentinel/lib/executor/policy.py` is the read-only copy on the sentinel
# package's own `PYTHONPATH`. Both root-owned, neither writable by `sentinel`,
# so the untrusted side can read the rules without being able to change them.
def _executor_policy() -> tuple[Any, str | None]:
    """The executor's policy module, or the reason it could not be loaded.

    Returns `(module, None)` or `(None, reason)`. Never raises: the caller
    turns a failure into a validation error, because every caller of
    `validate_plan` is a long-running service that must not die over this.
    """
    try:
        from executor import policy as executor_policy
    except Exception as exc:
        # Every import failure means the same thing here — the grammar is not
        # readable — so they are caught as one rather than enumerated.
        return None, f"{type(exc).__name__}: {exc}"
    return executor_policy, None


def _check_argv_builder() -> tuple[Any, str | None]:
    """`checks.argv_for`, or the reason it could not be loaded.

    Lazy for the same reason `_executor_policy` is: this module is imported
    by `sentinel/telegram/patch_flow.py`, and `sentinel/patch/checks.py`
    pulls in the database engine and the executor client. A validator that
    could not be imported without them would put the alerting channel behind
    a socket library.
    """
    try:
        from sentinel.patch.checks import argv_for
    except Exception as exc:
        # As above: every failure means the same thing — the commands the
        # checks will run cannot be known from here.
        return None, f"{type(exc).__name__}: {exc}"
    return argv_for, None


def _validate_executor_grammar(
    platform_family: str | None,
    apply_steps: list[dict[str, Any]],
    rollback_steps: list[dict[str, Any]],
    backups: list[dict[str, Any]],
    preflight: list[dict[str, Any]],
    health: list[dict[str, Any]],
    postver: list[dict[str, Any]],
    r: ValidationResult,
) -> None:
    """Refuse any argv the root executor would refuse, using its own code.

    Covers every argv `_iter_plan_argvs` can produce: the literal ones in
    apply/rollback steps and backup restores, and the ones
    `sentinel/patch/checks.py` builds from a structured check. All of them
    reach `check_argv` at run time, and a plan is only "valid" if every one
    of them can actually execute.

    `platform_family=None` (the standalone skill CLI) is not a reason to skip
    the check kinds: only `pkg_version`'s argv depends on the family, so the
    plan is examined once per known family and a command refused on any of
    them is reported. That is exact rather than a guess about which host the
    plan is for — and today the two families differ only in which
    (allowlisted) query binary they name, so it costs nothing.
    """
    policy, reason = _executor_policy()
    builder, builder_reason = _check_argv_builder()
    if builder is None:
        r.error(
            "$", "check_builder_unreadable",
            f"`sentinel.patch.checks.argv_for` could not be loaded ({builder_reason}), "
            "so the commands this plan's preflight, health and verification "
            "checks would run as root cannot be known. Refused rather than "
            "assumed safe.",
        )
        return
    if policy is None:
        r.error(
            "$", "executor_policy_unreadable",
            "the executor's own command policy could not be loaded "
            f"({reason}), so it is impossible to tell whether the commands in "
            "this plan would be permitted to run as root. Refused rather than "
            "assumed safe. On the host this means /opt/sentinel/lib/executor/"
            "policy.py is missing — redeploy; it is installed by install.sh "
            "step 24 alongside /opt/sentinel/libexec/policy.py.",
        )
        return
    # A dict, not a list: the same literal apply-step argv is produced once
    # per candidate family below, and reporting it twice would tell the
    # operator there are two problems where there is one.
    candidates: dict[tuple[str, tuple[str, ...]], tuple[str, list[str]]] = {}
    for fam in ((platform_family,) if platform_family else PLATFORM_FAMILIES):
        for path, argv in _iter_plan_argvs(
                apply_steps, rollback_steps, backups, preflight, health, postver,
                builder=builder, family=fam):
            candidates.setdefault((path, tuple(str(a) for a in argv)), (path, argv))

    for path, argv in candidates.values():
        try:
            policy.check_argv(list(argv))
        except policy.PolicyRefusal as refusal:
            r.error(
                f"$.{path}", "executor_would_refuse",
                f"the root executor refuses this command, so it can never run: "
                f"{refusal}",
            )
        except Exception as exc:
            # Anything other than a refusal is a bug in the policy module.
            # Reported as a plan error all the same: a validator that crashes
            # here takes `patch_flow.py` — and the Telegram bot — with it.
            r.error(
                f"$.{path}", "executor_check_failed",
                f"the executor's policy raised {type(exc).__name__}: {exc} while "
                "checking this command. That is a bug, not an approval.",
            )


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

    _validate_rollback_pin(rollback_steps, preflight, r)


def _validate_rollback_pin(
    rollback_steps: list[dict[str, Any]],
    preflight: list[dict[str, Any]],
    r: ValidationResult,
) -> None:
    """An apt rollback may only pin a version the preflight actually checked.

    The executor permits `--allow-downgrades` for exactly one purpose —
    putting a package back on the version that was installed before the patch
    — and it can only enforce the SHAPE of that: a pin is present. Whether the
    pinned version is the one the plan verified was installed is a question
    only the whole plan can answer, so it is answered here.

    Without this, `rollback: apt-get -y install --allow-downgrades
    openssl=1.0.2` validates clean in a plan whose preflight checked
    `polkitd`: a "rollback" that downgrades an unrelated package to a version
    nobody looked at, authorised by a button the operator pressed to undo
    something else. The preflight `equals` is what makes the pin meaningful;
    a pin without one is a version taken on the model's word.

    Compared as literal strings, deliberately: both values are supposed to be
    the same `installed_version` fact the planner injected into the prompt, so
    any difference at all — an added epoch, a guessed revision — means one of
    them did not come from the database.
    """
    verified: dict[str, str] = {}
    for item in preflight:
        check = item.get("check")
        if not isinstance(check, dict) or check.get("kind") != "pkg_version":
            continue
        equals = check.get("equals")
        if isinstance(equals, str) and equals:
            verified[str(check.get("name"))] = equals

    for i, step in enumerate(rollback_steps):
        argv = step.get("argv")
        if not isinstance(argv, list) or not argv:
            continue
        if str(argv[0]).rsplit("/", 1)[-1] not in ("apt", "apt-get"):
            continue
        skip_next = False
        # `part`, not `token`: with the obvious name, ruff reads `part == "-o"`
        # as a hardcoded credential (S105) and the file stops being clean.
        for part in argv[1:]:
            if skip_next:
                # The VALUE of `-o`, e.g. `Dpkg::Options::=--force-confold`.
                # It is not a flag (no leading dash) and it does contain an
                # `=`, so a loop that only looked at those two things read it
                # as a pin of a package called `Dpkg` — a refusal on a plan
                # the executor is perfectly happy with. Measured before this
                # line existed.
                skip_next = False
                continue
            if not isinstance(part, str):
                continue
            if part == "-o":
                skip_next = True
                continue
            if part.startswith("-") or "=" not in part:
                continue
            name, _, version = part.partition("=")
            name = name.split(":", 1)[0]
            if name not in verified:
                r.error(
                    f"$.rollback[{i}].argv",
                    "rollback_pin_unverified",
                    f"this step pins {name!r} to {version!r}, but no preflight check "
                    f"confirms which version of {name!r} is installed. A rollback to "
                    "a version nothing verified can install something the host never "
                    "had — add a pkg_version preflight with `equals`.",
                )
            elif verified[name] != version:
                r.error(
                    f"$.rollback[{i}].argv",
                    "rollback_pin_mismatch",
                    f"this step rolls {name!r} back to {version!r}, but the preflight "
                    f"verifies the installed version is {verified[name]!r}. One of the "
                    "two is not the version this host actually has, and the rollback "
                    "is the half that runs when something has already gone wrong.",
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
