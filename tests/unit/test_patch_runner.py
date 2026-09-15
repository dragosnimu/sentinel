"""Runner behaviour, driven against a fake executor.

Nothing here touches a real machine: the point is to prove the state machine is
correct — that a failure rolls back, that a rollback failure is reported as its
own (worse) state, and that no path leaves an execution stuck in 'running'.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from sentinel.patch import runner
from sentinel.patch.validator import plan_hash


def _step(sid: str, argv: list[str], **extra: Any) -> dict[str, Any]:
    return {"id": sid, "desc_ro": f"pas de test {sid}", "argv": argv,
            "timeout_s": 60, "on_failure": "rollback", "expect_exit": [0], **extra}


def _check(cid: str, check: dict[str, Any], blocking: bool = True) -> dict[str, Any]:
    return {"id": cid, "desc_ro": f"verificare {cid}", "blocking": blocking,
            "check": check}


def _plan(*, with_rollback: bool = True) -> dict[str, Any]:
    """A plan that actually passes the real validator — otherwise these tests
    would only ever exercise the "invalid plan" branch.

    Note three constraints the validator enforces and this fixture honours: a
    backup requires a disk_free preflight; a rollback step may not itself
    trigger a rollback; and nothing may reference /var/backups/sentinel, which
    is why restore_argv points at the extracted target rather than the archive.
    """
    return {
        "schema_version": 1,
        "target": {"asset_id": 93, "asset_name": "nginx", "protected": False,
                   "stack": "rpm", "unit": "nginx.service"},
        "vulnerabilities": [{"finding_id": 1, "cve": "CVE-2026-12345",
                             "package": "nginx", "severity": "high"}],
        "risk": {"level": "medium", "blast_radius": "single-service",
                 "reversible": True, "requires_reboot": False,
                 "estimated_downtime_s": 5, "confidence": 0.9},
        "preflight": [
            _check("pf_disk", {"kind": "disk_free", "path": "/var",
                               "min_bytes": 524288000}),
            _check("pf_conf", {"kind": "file_exists", "path": "/etc/nginx/nginx.conf"}),
        ],
        "backup": [{"id": "bk1", "desc_ro": "salvez configurația nginx",
                    "kind": "path", "source": "/etc/nginx",
                    "restore_argv": ["systemctl", "reload", "nginx"],
                    "estimated_size_mb": 5}],
        "apply": [_step("ap1", ["dnf", "-y", "update", "nginx"], expect_exit=[0, 100])],
        "health_check": [
            _check("hc_unit", {"kind": "systemd", "unit": "nginx.service",
                               "expect_state": "active"}),
        ],
        "rollback": ([_step("rb1", ["dnf", "-y", "downgrade", "nginx"],
                            on_failure="abort")] if with_rollback else []),
        "post_verification": [
            _check("pv_conf", {"kind": "command", "argv": ["nginx", "-t"],
                               "expect_exit": [0]}),
        ],
        "restore_instructions_ro":
            "Rulează ca root: bash restore.sh din directorul punctului de restaurare.",
    }


class _FakeExec:
    """Stands in for the root executor across every module that talks to it.

    `fail_on` names argv[0] values that come back non-zero; `raise_on` makes the
    socket call itself blow up, which is the "executor unreachable" case.
    """

    def __init__(self, fail_on: set[str] | None = None, raise_on: set[str] | None = None):
        self.fail_on = fail_on or set()
        self.raise_on = raise_on or set()
        self.calls: list[dict[str, Any]] = []

    def call(self, op: str, **args: Any) -> dict[str, Any]:
        self.calls.append({"op": op, **args})

        if op == "disk_free":
            return {"ok": True, "free": 50 * 1_048_576_000, "total": 1, "used_pct": 10}
        if op == "backup_create":
            return {"ok": True, "artifact": f"/var/backups/sentinel/x/{args.get('source')}.tar.zst",
                    "sha256": "a" * 64, "size_bytes": 1024}
        if op == "backup_finalize":
            if "backup" in self.fail_on:
                return {"ok": False, "error": "sigilare esuata"}
            return {"ok": True, "items": [{"artifact": "etc_nginx.tar.zst",
                                           "sha256": "a" * 64, "size_bytes": 1024,
                                           "is_archive": True}],
                    "manifest_path": "/var/backups/sentinel/x/manifest.json",
                    "restore_script": "/var/backups/sentinel/x/restore.sh",
                    "total_bytes": 1024}

        argv = args.get("argv") or []
        head = argv[0] if argv else ""
        if head in self.raise_on:
            raise RuntimeError("executor unreachable")
        if args.get("dry_run"):
            return {"dry_run": True, "would_run": argv}
        code = 1 if head in self.fail_on else 0
        # `systemctl is-active` is read via stdout by the systemd check, so it
        # has to answer plausibly, not just with an exit code.
        stdout = ""
        if argv[:2] == ["systemctl", "is-active"]:
            stdout = "failed" if "systemctl" in self.fail_on else "active"
        return {"exit_code": code, "stdout": stdout, "stderr": "boom" if code else "",
                "timed_out": False}


class _FakeDB:
    """Just enough of the repo surface: remembers the plan and every write."""

    def __init__(self, plan: dict[str, Any], status="approved", stored_hash=None):
        self.plan = plan
        self.status = status
        self.stored_hash = stored_hash or plan_hash(plan)
        self.plan_statuses: list[str] = []
        self.executions: list[dict[str, Any]] = []
        self.steps: list[dict[str, Any]] = []
        self._next_id = 1

    async def fetchrow(self, sql, *a):
        if "FROM patch_plans" in sql:
            return {
                "id": 1, "plan_id": "00000000-0000-0000-0000-000000000001",
                "plan_hash": self.stored_hash, "plan": json.dumps(self.plan),
                "status": self.status, "risk_level": "medium", "requires_reboot": False,
                "reversible": True, "estimated_downtime_s": 5, "asset_id": None,
                "created_at": None, "approved_by": "test", "approved_at": None,
                "validation_errors": None,
            }
        return None

    async def fetchval(self, sql, *a):
        self._next_id += 1
        if "INSERT INTO patch_executions" in sql:
            self.executions.append({"id": self._next_id, "mode": a[1]})
        if "INSERT INTO patch_steps" in sql:
            self.steps.append({"id": self._next_id, "execution_id": a[0], "phase": a[1],
                               "step_id": a[2], "argv": a[4], "status": "running"})
        return self._next_id

    async def execute(self, sql, *a):
        if "UPDATE patch_plans SET status" in sql:
            self.plan_statuses.append(a[1])
        if "UPDATE patch_executions SET status" in sql:
            self.executions.append({"final": a[1], "error": a[3]})
        if "UPDATE patch_steps SET status" in sql:
            for s in self.steps:
                if s["id"] == a[0]:
                    s["status"] = a[1]
        return "OK"

    async def fetch(self, sql, *a):
        return []


@pytest.fixture(autouse=True)
def _fake_executor(monkeypatch):
    """Every module that reaches the executor gets the same fake, so a test that
    forgets one cannot accidentally hit a real socket."""
    from sentinel.patch import backup as backup_mod
    from sentinel.patch import checks as checks_mod

    fake = _FakeExec()
    for module in (runner, backup_mod, checks_mod):
        monkeypatch.setattr(module, "_client", fake)
    return fake


def run(c):
    return asyncio.run(c)


def _final(db: _FakeDB) -> str | None:
    for e in reversed(db.executions):
        if "final" in e:
            return e["final"]
    return None


def _steps_for(db: _FakeDB, execution_id: int) -> list[dict[str, Any]]:
    """Steps belonging to one execution — needed once `apply` is always
    preceded by its own dry-run execution (S3): `db.steps` otherwise mixes
    the pre-check's steps in with the real run's."""
    return [s for s in db.steps if s["execution_id"] == execution_id]


# --- refusals before anything runs ------------------------------------------
def test_missing_plan_is_refused_without_creating_an_execution():
    class Empty(_FakeDB):
        async def fetchrow(self, sql, *a):
            return None
    db = Empty(_plan())
    with pytest.raises(runner.PatchRefused, match="inexistent"):
        run(runner.run_plan(db, None, 1))
    assert db.executions == []


def test_tampered_plan_is_refused_and_marked_invalid():
    db = _FakeDB(_plan(), stored_hash="deadbeef")
    with pytest.raises(runner.PatchRefused, match="hash-ul planului"):
        run(runner.run_plan(db, None, 1))
    assert "rejected_invalid" in db.plan_statuses
    assert db.executions == []          # nothing was started


def test_unapproved_plan_cannot_be_applied():
    db = _FakeDB(_plan(), status="validated")
    with pytest.raises(runner.PatchRefused, match="nu este aprobat"):
        run(runner.run_plan(db, None, 1, mode="apply"))
    assert db.executions == []


def test_unapproved_plan_may_still_be_dry_run():
    # Seeing what WOULD happen must not require approval; that is the point of
    # a dry run.
    db = _FakeDB(_plan(), status="validated")
    res = run(runner.run_plan(db, None, 1, mode="dry_run"))
    assert res.status == "succeeded"


# --- the happy path ---------------------------------------------------------
def test_apply_runs_every_forward_phase_in_order(_fake_executor):
    db = _FakeDB(_plan())
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "succeeded"
    # de-duplicated, since a phase may contain several checks. Filtered to the
    # real apply's own execution: S3 means a full dry-run pass now precedes it
    # as a SEPARATE recorded execution, which would otherwise double every
    # phase in db.steps (a global log across every execution the fake ever saw).
    seen: list[str] = []
    for st in _steps_for(db, res.execution_id):
        if not seen or seen[-1] != st["phase"]:
            seen.append(st["phase"])
    assert seen == ["preflight", "backup", "apply", "health_check", "post_verification"]
    assert "applied" in db.plan_statuses


def test_every_call_site_asks_for_a_socket_timeout_beyond_the_ops_own(_fake_executor):
    """Every `patch_step_exec`/`backup_create` call this codebase makes must
    pass `socket_timeout_s` strictly greater than the op's own declared
    duration on the executor side (`timeout_s` for a step/check,
    `_BACKUP_CREATE_TAR_TIMEOUT_S` for a backup).

    Prevents: a call site that forgets `+ TIMEOUT_MARGIN_S` (or keeps using
    the client's short fixed default) reporting a still-running root command
    as failed, which can start a rollback concurrently with the very step it
    is rolling back. Exercises all three call sites at once — runner.py's own
    apply step, checks.py's "command"-kind post_verification (also
    patch_step_exec), and backup.py's backup_create — because `_plan()`
    contains one of each."""
    from sentinel.patch import backup as backup_mod
    from sentinel.respond.executor_client import TIMEOUT_MARGIN_S

    db = _FakeDB(_plan())
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "succeeded"

    seen_patch_step_exec = seen_backup_create = False
    for c in _fake_executor.calls:
        if c["op"] == "patch_step_exec":
            seen_patch_step_exec = True
            declared = c["timeout_s"]
            assert c["socket_timeout_s"] == declared + TIMEOUT_MARGIN_S
        elif c["op"] == "backup_create":
            seen_backup_create = True
            assert c["socket_timeout_s"] == (
                backup_mod._BACKUP_CREATE_TAR_TIMEOUT_S + TIMEOUT_MARGIN_S)

    assert seen_patch_step_exec and seen_backup_create, (
        "the fixture plan must exercise both call kinds, or this test proves nothing"
    )


def test_dry_run_never_executes_for_real(_fake_executor):
    db = _FakeDB(_plan())
    run(runner.run_plan(db, None, 1, mode="dry_run"))
    assert all(c.get("dry_run") for c in _fake_executor.calls if c["op"] == "patch_step_exec")


# --- failure handling -------------------------------------------------------
def test_apply_failure_rolls_back(_fake_executor):
    # The rollback uses a different binary from the one that failed, so it can
    # actually succeed — that is the "clean rollback" path.
    plan = _plan()
    plan["rollback"] = [_step("rb1", ["systemctl", "restart", "nginx"], on_failure="abort")]
    _fake_executor.fail_on = {"dnf"}
    db = _FakeDB(plan)
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "rolled_back"
    assert "rolled_back" in db.plan_statuses
    assert any(s["phase"] == "rollback" for s in db.steps)


def test_failed_rollback_is_its_own_louder_state(_fake_executor):
    # dnf fails in apply AND in rollback (the plan's rollback is also dnf): the
    # machine is now in an unknown state, which must not look like a tidy
    # "rolled_back".
    _fake_executor.fail_on = {"dnf"}
    db = _FakeDB(_plan())
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "rollback_failed"
    assert "failed" in db.plan_statuses


def test_preflight_failure_aborts_without_rolling_back(_fake_executor):
    _fake_executor.fail_on = {"test"}
    db = _FakeDB(_plan())
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "aborted"
    # Nothing was applied, so rolling back would be a pointless risk.
    assert not any(s["phase"] == "rollback" for s in db.steps)


def test_health_check_failure_rolls_back(_fake_executor):
    _fake_executor.fail_on = {"systemctl"}
    db = _FakeDB(_plan())
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status in ("rolled_back", "rollback_failed")


def test_unreachable_executor_still_closes_the_execution(_fake_executor):
    _fake_executor.raise_on = {"test"}
    db = _FakeDB(_plan())
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "aborted"
    assert _final(db) is not None       # never left 'running'


def test_a_phase_stops_at_its_first_failure(_fake_executor):
    plan = _plan()
    plan["apply"] = [
        _step("a1", ["dnf", "-y", "update", "nginx"]),
        _step("a2", ["systemctl", "restart", "nginx"]),
    ]
    _fake_executor.fail_on = {"dnf"}
    db = _FakeDB(plan)
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    applied = [s["step_id"] for s in _steps_for(db, res.execution_id) if s["phase"] == "apply"]
    assert applied == ["a1"]            # a2 never ran


# --- S3: an apply is actually preceded by a dry-run pass, not just claimed --
def test_apply_creates_a_dry_run_execution_before_the_real_one(_fake_executor):
    """The module docstring has always said 'dry run first, always'; before
    this fix `mode='apply'` went straight to the real commands and nothing
    ever exercised the dry-run path first. A real pre-check must leave its
    own execution row, distinct from the applied one."""
    db = _FakeDB(_plan())
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "succeeded"
    modes = [e["mode"] for e in db.executions if "mode" in e]
    assert modes == ["dry_run", "apply"]


def test_apply_is_refused_before_touching_anything_if_the_dry_run_fails(_fake_executor):
    """A crash in the executor is exactly the case the dry-run pass exists to
    catch before real commands run. Without an actual pre-apply dry-run pass,
    `run_plan` went straight into applying and only discovered the executor
    could not run `dnf` after the real apply had already started (and then
    had to roll back a real `dnf downgrade`, itself liable to fail the same
    way). With the pass wired in, the failure surfaces before any 'applying'
    execution is even created."""
    _fake_executor.raise_on = {"dnf"}
    db = _FakeDB(_plan())
    with pytest.raises(runner.PatchRefused, match="proba uscată"):
        run(runner.run_plan(db, None, 1, mode="apply"))
    assert "applying" not in db.plan_statuses
    # Only the failed dry-run pre-check execution exists — never the apply.
    modes = [e["mode"] for e in db.executions if "mode" in e]
    assert modes == ["dry_run"]


# --- S3b: a crash before `apply` starts must not trigger a rollback --------
class _CrashOnRealApplyStepInsertDB(_FakeDB):
    """Raises the moment `begin_step` is called for a given phase, but ONLY
    for the step belonging to the execution created with mode='apply' — the
    dry-run pre-check (S3) runs the very same phases first and must not be
    the one that trips the injected crash, or the test would never reach the
    real apply at all."""

    def __init__(self, *a, crash_phase: str, **kw):
        super().__init__(*a, **kw)
        self.crash_phase = crash_phase
        self._apply_execution_id: int | None = None

    async def fetchval(self, sql, *a):
        if "INSERT INTO patch_executions" in sql and a[1] == "apply":
            eid = await super().fetchval(sql, *a)
            self._apply_execution_id = eid
            return eid
        if ("INSERT INTO patch_steps" in sql and a[1] == self.crash_phase
                and a[0] == self._apply_execution_id):
            raise RuntimeError("baza a picat chiar acum")
        return await super().fetchval(sql, *a)


def test_crash_before_apply_starts_does_not_roll_back(_fake_executor):
    """A crash while still validating preflight — nothing on the machine has
    changed — must not run the plan's rollback steps against an untouched
    system. Before this fix, ANY unhandled exception inside run_plan(mode=
    'apply') triggered a rollback attempt regardless of how far the run had
    actually gotten."""
    db = _CrashOnRealApplyStepInsertDB(_plan(), crash_phase="preflight")
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "aborted"
    assert not any(s["phase"] == "rollback" for s in db.steps)


def test_crash_after_apply_starts_still_rolls_back(_fake_executor):
    """The flip side of the test above: apply_started must not be so
    conservative that a REAL crash after changes were made goes unrolled."""
    plan = _plan()
    plan["rollback"] = [_step("rb1", ["systemctl", "restart", "nginx"], on_failure="abort")]
    db = _CrashOnRealApplyStepInsertDB(plan, crash_phase="health_check")
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status in ("rolled_back", "rollback_failed")
    assert any(s["phase"] == "rollback" for s in db.steps)


# --- S1c: cfg.platform.family must reach checks.evaluate --------------------
def test_platform_family_from_cfg_reaches_checks_evaluate(_fake_executor, monkeypatch):
    """`checks.evaluate` needs `platform.family` to know which package
    manager `pkg_version` speaks (rpm vs dpkg-query). Before this fix,
    `runner.py:_run_check` called `checks.evaluate(db, check)` with no
    `family` at all — which silently defaults to `rhel` regardless of what
    `cfg.platform.family` actually says, so a debian host's `pkg_version`
    checks ran through the rpm path (a binary that host does not have)
    instead of the debian-specific query, or the debian-specific "cannot
    evaluate" refusal.

    Driven with a spy on `checks.evaluate` rather than asserting on the
    outcome, so this fails for the right reason (the value was never
    threaded through) rather than an incidental side effect of what the fake
    executor happens to answer for `dpkg-query`.
    """
    from types import SimpleNamespace

    from sentinel.patch import checks as checks_mod

    seen_family: list[str] = []
    real_evaluate = checks_mod.evaluate

    async def spy(db_arg, check, *, family="rhel"):
        seen_family.append(family)
        return await real_evaluate(db_arg, check, family=family)

    monkeypatch.setattr(checks_mod, "evaluate", spy)

    plan = _plan()
    plan["preflight"].append(
        _check("pf_pkg", {"kind": "pkg_version", "name": "nginx", "at_least": "1.0"},
              blocking=False))
    db = _FakeDB(plan)
    cfg = SimpleNamespace(platform=SimpleNamespace(family="debian"))

    run(runner.run_plan(db, cfg, 1, mode="apply"))

    assert seen_family, "checks.evaluate was never called"
    assert "debian" in seen_family, (
        f"cfg.platform.family='debian' never reached checks.evaluate — saw {seen_family}")
