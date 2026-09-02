"""`check_patch_window` — de ce n-a propus fereastra nimic, sau de ce n-a
rulat deloc.

Un mecanism care tace când nu face nimic e indistinct de unul stricat.
Fiecare test aici pică pe scenariul în care verificarea ar confunda două
stări care nu au voie să arate la fel: „n-a rulat niciodată" cu „a rulat și
n-a găsit nimic", sau „nimic eligibil încă" cu „ceva dovedit NEreversibil".
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sentinel.db.repo import patches as patch_repo
from sentinel.selfcheck import checks

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def run(c):
    return asyncio.run(c)


def _plan(id_=1, reversible=True, backup_kind="path"):
    return SimpleNamespace(
        id=id_,
        plan={"risk": {"reversible": reversible},
              "backup": [{"kind": backup_kind, "source": "/etc/nginx"}]})


def _wire(monkeypatch, *, last_run=None, halt=None, outstanding=None,
         candidates=None, evidence=None):
    async def _last_run(db):
        return last_run

    async def _halt(db):
        return halt

    async def _outstanding(db):
        return outstanding

    async def _candidates(db, *, limit):
        return candidates or []

    async def _evidence(db):
        return evidence

    monkeypatch.setattr(patch_repo, "last_window_run", _last_run)
    monkeypatch.setattr(patch_repo, "window_halt", _halt)
    monkeypatch.setattr(patch_repo, "outstanding_window_plan", _outstanding)
    monkeypatch.setattr(patch_repo, "window_candidate_plans", _candidates)
    monkeypatch.setattr(patch_repo, "latest_archive_drill_summary", _evidence)


class _DB:
    pass


def test_never_run_is_unknown_not_ok(monkeypatch):
    """«Există planuri de patch» și «fereastra le-a luat în considerare» nu
    sunt același fapt — exact tiparul cerut din `check_restore_drill`."""
    _wire(monkeypatch, last_run=None)
    out = run(checks.check_patch_window(_DB()))
    assert len(out) == 1
    assert out[0].status == "unknown"
    assert out[0].facts.get("ran") is False


def test_a_stale_timer_is_degraded(monkeypatch):
    _wire(monkeypatch, last_run={"ran_at": NOW - timedelta(days=20), "id": 1})
    out = run(checks.check_patch_window(_DB()))
    assert out[0].status == "degraded"
    assert "învechit" in out[0].title.lower()


def test_a_recent_run_is_not_flagged_stale(monkeypatch):
    _wire(monkeypatch, last_run={"ran_at": NOW - timedelta(days=1), "id": 1},
         halt=None, outstanding=None, candidates=[])
    out = run(checks.check_patch_window(_DB()))
    assert all(r.status != "degraded" or "învechit" not in r.title.lower() for r in out)


def test_a_halted_window_is_reported_loudly(monkeypatch):
    """Oprirea la primul eșec e o proprietate de siguranță care lucrează —
    tăcerea aici ar ascunde-o. `degraded`, nu `ok`."""
    _wire(monkeypatch, last_run={"ran_at": NOW - timedelta(days=1), "id": 1},
         halt={"plan_id": 3, "execution_id": 9, "status": "failed"})
    out = run(checks.check_patch_window(_DB()))
    assert len(out) == 1
    assert out[0].status == "degraded"
    assert out[0].facts.get("halted") is True
    assert out[0].facts.get("execution_id") == 9


def test_an_outstanding_release_is_informational_not_a_problem(monkeypatch):
    _wire(monkeypatch, last_run={"ran_at": NOW - timedelta(days=1), "id": 1},
         halt=None, outstanding={"id": 4})
    out = run(checks.check_patch_window(_DB()))
    assert out[0].status == "ok"
    assert out[0].facts.get("outstanding_plan_id") == 4


def test_no_candidates_is_ok_not_a_problem(monkeypatch):
    _wire(monkeypatch, last_run={"ran_at": NOW - timedelta(days=1), "id": 1},
         halt=None, outstanding=None, candidates=[])
    out = run(checks.check_patch_window(_DB()))
    assert out[0].status == "ok"
    assert out[0].facts.get("candidates") == 0


def test_a_provably_unreversible_candidate_is_degraded(monkeypatch):
    """E defectul pe care exercițiul de restaurare există să-l prindă, nu o
    lipsă de informație — nu are voie să iasă `ok`."""
    _wire(monkeypatch, last_run={"ran_at": NOW - timedelta(days=1), "id": 1},
         halt=None, outstanding=None, candidates=[_plan(id_=9, reversible=False)])
    out = run(checks.check_patch_window(_DB()))
    assert len(out) == 1
    assert out[0].status == "degraded"
    assert out[0].facts["plan_id"] == 9
    assert out[0].facts["state"] == "not_reversible"


def test_an_unproven_candidate_is_ok_not_a_malfunction(monkeypatch):
    """Nedovedit nu e stricat — stare normală pe o gazdă fără arhive
    dovedite încă (măsurată pe gazda reală la 1 septembrie 2026)."""
    _wire(monkeypatch, last_run={"ran_at": NOW - timedelta(days=1), "id": 1},
         halt=None, outstanding=None,
         candidates=[_plan(id_=2, backup_kind="rpm_state")])
    out = run(checks.check_patch_window(_DB()))
    assert out[0].status == "ok"
    assert out[0].facts["state"] == "unproven"


def test_mixed_candidates_report_each_one_separately(monkeypatch):
    candidates = [_plan(id_=1, reversible=False), _plan(id_=2, backup_kind="rpm_state")]
    _wire(monkeypatch, last_run={"ran_at": NOW - timedelta(days=1), "id": 1},
         halt=None, outstanding=None, candidates=candidates)
    out = run(checks.check_patch_window(_DB()))
    assert len(out) == 2
    by_id = {r.facts["plan_id"]: r.status for r in out}
    assert by_id == {1: "degraded", 2: "ok"}
