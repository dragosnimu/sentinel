"""`sentinel/patch/restore_drill.py` — driven against a fake executor and a
fake database, the way `test_patch_runner.py` drives the patch runner.

The property under test throughout: `succeeded` on the recorded drill must
mean "at least one archive was proven to restore, and nothing else failed" —
never "nothing happened to fail", and never "the point looked fine because it
had nothing to check".
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any

import pytest

from sentinel.patch import restore_drill


def run(c):
    return asyncio.run(c)


class _FakeExec:
    def __init__(self, response: dict[str, Any] | None = None,
                raise_exc: Exception | None = None):
        self.response = response
        self.raise_exc = raise_exc
        self.calls: list[dict[str, Any]] = []

    def call(self, op: str, **args: Any) -> dict[str, Any]:
        self.calls.append({"op": op, **args})
        if self.raise_exc:
            raise self.raise_exc
        return self.response


class _FakeConn:
    def __init__(self):
        self.fetchval_calls: list[tuple] = []
        self.execute_calls: list[tuple] = []
        self._next_id = 500

    async def fetchval(self, sql, *a):
        self.fetchval_calls.append((sql, a))
        self._next_id += 1
        return self._next_id

    async def execute(self, sql, *a):
        self.execute_calls.append((sql, a))
        return "INSERT 0 1"


class _FakeDB:
    def __init__(self, *, point: dict[str, Any] | None = None, any_live: bool = False):
        self._point = point
        self._any_live = any_live
        self.conn = _FakeConn()
        self.fetchrow_sql: str | None = None
        self.fetchval_sql: str | None = None

    async def fetchrow(self, sql, *a):
        self.fetchrow_sql = sql
        return self._point

    async def fetchval(self, sql, *a):
        self.fetchval_sql = sql
        return self._any_live

    @contextlib.asynccontextmanager
    async def transaction(self):
        yield self.conn


def _point(id_=1, path="/var/backups/sentinel/20260901-x", sources=None, asset_id=None):
    return {"id": id_, "path": path, "asset_id": asset_id,
           "created_at": None, "last_drill_at": None,
           "manifest": {"sources": sources or ["/etc/nginx"]}}


def _restorable_response(**overrides):
    resp = {"ok": True, "restore_point_id": "20260901-x", "items": [
        {"artifact": "etc_nginx.tar.zst", "is_archive": True, "sha256_ok": True,
         "verdict": "restorable_verified", "matched_sources": ["/etc/nginx"],
         "detail": ""},
    ]}
    resp.update(overrides)
    return resp


@pytest.fixture(autouse=True)
def _fake_client(monkeypatch):
    fake = _FakeExec(response=_restorable_response())
    monkeypatch.setattr(restore_drill, "_client", fake)
    return fake


def _head_row(conn: _FakeConn) -> tuple[str, tuple]:
    """The single INSERT INTO restore_drills call — the head row."""
    heads = [c for c in conn.fetchval_calls if "INSERT INTO restore_drills" in c[0]]
    assert len(heads) == 1, conn.fetchval_calls
    return heads[0]


# ---------------------------------------------------------------------------
# Nothing to do — distinguished from "ran and found a problem"
# ---------------------------------------------------------------------------
def test_no_live_restore_points_writes_nothing_and_says_so(monkeypatch, _fake_client):
    db = _FakeDB(point=None, any_live=False)
    outcome = run(restore_drill.run(db, None))
    assert outcome.ran is False
    assert "nimic de testat" in outcome.detail
    assert db.conn.fetchval_calls == [], "a drill row was written for nothing to test"
    assert _fake_client.calls == [], "the executor was called with no point to check"


def test_a_selection_query_bug_is_distinguished_from_an_empty_host(_fake_client):
    """Live points exist, but the picker returned none — a bug in the query,
    not a fresh install. The two must not read the same in the log."""
    db = _FakeDB(point=None, any_live=True)
    outcome = run(restore_drill.run(db, None))
    assert outcome.ran is False
    assert "pick_restore_point_for_drill" in outcome.detail


# ---------------------------------------------------------------------------
# The executor cannot be reached / refuses
# ---------------------------------------------------------------------------
def test_executor_unreachable_is_recorded_not_raised(monkeypatch):
    fake = _FakeExec(raise_exc=RuntimeError("socket timeout"))
    monkeypatch.setattr(restore_drill, "_client", fake)
    db = _FakeDB(point=_point())

    outcome = run(restore_drill.run(db, None))

    assert outcome.ran is True
    assert outcome.succeeded is False
    sql, args = _head_row(db.conn)
    # (restore_point_id, automated, performed_by, succeeded, duration_ms, notes, result)
    assert args[1] is True   # automated
    assert args[3] is False  # succeeded
    assert "executorul nu a răspuns" in args[5]


def test_executor_refusal_is_recorded_not_raised(monkeypatch):
    fake = _FakeExec(response={"ok": False, "error": "restore point does not exist on disk"})
    monkeypatch.setattr(restore_drill, "_client", fake)
    db = _FakeDB(point=_point())

    outcome = run(restore_drill.run(db, None))

    assert outcome.succeeded is False
    sql, args = _head_row(db.conn)
    assert args[3] is False
    assert "refuzat" in args[5] or "does not exist" in args[5]


# ---------------------------------------------------------------------------
# The central rule: informational-only is never success
# ---------------------------------------------------------------------------
def test_a_purely_informational_point_never_succeeds(monkeypatch):
    """Falsified: change `_OK_VERDICTS` to include nothing extra, or change
    `any_restored` to `True` unconditionally, and this starts passing on a
    point that proved nothing."""
    fake = _FakeExec(response={"ok": True, "items": [
        {"artifact": "rpm-nginx.txt", "is_archive": False, "sha256_ok": True,
         "verdict": "informational_only", "matched_sources": [], "detail": ""},
    ]})
    monkeypatch.setattr(restore_drill, "_client", fake)
    db = _FakeDB(point=_point())

    outcome = run(restore_drill.run(db, None))

    assert outcome.succeeded is False
    assert "informativ" in outcome.detail
    sql, args = _head_row(db.conn)
    assert args[3] is False


def test_a_fully_verified_archive_succeeds(monkeypatch):
    db = _FakeDB(point=_point())
    outcome = run(restore_drill.run(db, None))
    assert outcome.succeeded is True
    sql, args = _head_row(db.conn)
    assert args[3] is True


def test_one_bad_artifact_fails_the_whole_point_even_if_others_are_fine(monkeypatch):
    """A mixed restore point where one archive is fine and another is not must
    not report overall success — that would hide the real problem behind the
    artifact that happened to work."""
    fake = _FakeExec(response={"ok": True, "items": [
        {"artifact": "etc_nginx.tar.zst", "is_archive": True, "sha256_ok": True,
         "verdict": "restorable_verified", "matched_sources": ["/etc/nginx"], "detail": ""},
        {"artifact": "var_www.tar.zst", "is_archive": True, "sha256_ok": True,
         "verdict": "structure_mismatch", "matched_sources": [],
         "detail": "arhiva s-a extras curat, dar nicio sursă declarată nu apare"},
    ]})
    monkeypatch.setattr(restore_drill, "_client", fake)
    db = _FakeDB(point=_point())

    outcome = run(restore_drill.run(db, None))

    assert outcome.succeeded is False
    assert "var_www.tar.zst" in outcome.detail


def test_an_empty_manifest_from_the_executor_is_not_a_success(monkeypatch):
    fake = _FakeExec(response={"ok": True, "items": []})
    monkeypatch.setattr(restore_drill, "_client", fake)
    db = _FakeDB(point=_point())
    outcome = run(restore_drill.run(db, None))
    assert outcome.succeeded is False


# ---------------------------------------------------------------------------
# Wiring: the right point, the right sources, one item row per artifact
# ---------------------------------------------------------------------------
def test_the_executor_is_called_with_the_id_derived_from_the_path_and_the_db_sources(
        _fake_client):
    db = _FakeDB(point=_point(path="/var/backups/sentinel/20260901-plan7",
                              sources=["/etc/nginx", "/etc/hostname"]))
    run(restore_drill.run(db, None))
    (call,) = _fake_client.calls
    assert call["op"] == "restore_drill_verify"
    assert call["restore_point_id"] == "20260901-plan7"
    assert call["sources"] == ["/etc/nginx", "/etc/hostname"]


def test_every_returned_item_becomes_its_own_drill_item_row(monkeypatch):
    fake = _FakeExec(response={"ok": True, "items": [
        {"artifact": "a.tar.zst", "is_archive": True, "sha256_ok": True,
         "verdict": "restorable_verified", "matched_sources": ["/etc/nginx"], "detail": ""},
        {"artifact": "b.txt", "is_archive": False, "sha256_ok": True,
         "verdict": "informational_only", "matched_sources": [], "detail": ""},
    ]})
    monkeypatch.setattr(restore_drill, "_client", fake)
    db = _FakeDB(point=_point())

    run(restore_drill.run(db, None))

    item_inserts = [c for c in db.conn.execute_calls
                    if "INSERT INTO restore_drill_items" in c[0]]
    assert len(item_inserts) == 2
    artifacts = {c[1][1] for c in item_inserts}  # (drill_id, artifact, ...)
    assert artifacts == {"a.tar.zst", "b.txt"}


def test_the_recorded_drill_is_marked_automated(monkeypatch):
    db = _FakeDB(point=_point())
    run(restore_drill.run(db, None))
    sql, args = _head_row(db.conn)
    assert args[1] is True, "the scheduled job's rows must be distinguishable from a manual drill"
