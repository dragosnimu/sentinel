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
            self.steps.append({"id": self._next_id, "phase": a[1], "step_id": a[2],
                               "argv": a[4], "status": "running"})
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
    # de-duplicated, since a phase may contain several checks
    seen: list[str] = []
    for st in db.steps:
        if not seen or seen[-1] != st["phase"]:
            seen.append(st["phase"])
    assert seen == ["preflight", "backup", "apply", "health_check", "post_verification"]
    assert "applied" in db.plan_statuses


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
    run(runner.run_plan(db, None, 1, mode="apply"))
    applied = [s["step_id"] for s in db.steps if s["phase"] == "apply"]
    assert applied == ["a1"]            # a2 never ran
