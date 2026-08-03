"""The patch pipeline speaking first.

Everything about patching used to be pull-based: the plan generator, the
validator, the approval flow and the runner were all complete, and the only way
to see a plan was to type `/patch <id>`. So the whole pipeline ran and nobody
was ever told. These tests pin the three connections that close that gap, and —
more importantly — the conditions under which each one stays quiet.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from sentinel.db.repo import patches as repo


def run(c):
    return asyncio.run(c)


class _StubDB:
    def __init__(self, rows: list | None = None):
        self.sql: list[str] = []
        self.args: list[tuple] = []
        self._rows = rows or []

    async def fetch(self, sql, *a):
        self.sql.append(sql); self.args.append(a); return self._rows

    async def execute(self, sql, *a):
        self.sql.append(sql); self.args.append(a); return "UPDATE 1"


# --- the push queues --------------------------------------------------------
def test_only_validated_plans_are_ever_offered():
    """An invalid plan must never carry an approve button, so it must never
    reach the queue that attaches one."""
    db = _StubDB()
    run(repo.unnotified_plans(db))
    assert "status = 'validated'" in db.sql[0]
    assert "notified_at IS NULL" in db.sql[0]


def test_stale_plans_are_not_offered():
    """A plan older than the TTL was written against package versions that have
    since moved. Offering it invites approving a patch for a machine that no
    longer exists."""
    db = _StubDB()
    run(repo.unnotified_plans(db))
    assert "make_interval(hours =>" in db.sql[0]
    assert repo.PLAN_TTL_HOURS in db.args[0]


def test_plan_push_is_capped():
    db = _StubDB()
    run(repo.unnotified_plans(db))
    assert db.args[0][-1] == 3          # not "every plan we found at 3 a.m."


def test_telegram_triggered_executions_are_not_announced_twice():
    """`on_dry_run` edits its own message with the result. A second message
    saying the same thing teaches the operator that these can be ignored."""
    db = _StubDB()
    run(repo.unnotified_executions(db))
    assert "triggered_by NOT LIKE 'telegram:%'" in db.sql[0]


def test_unfinished_executions_are_not_announced():
    db = _StubDB()
    run(repo.unnotified_executions(db))
    assert "finished_at IS NOT NULL" in db.sql[0]


# --- drafting ---------------------------------------------------------------
def _cfg(auto: bool = True):
    return SimpleNamespace(
        scan=SimpleNamespace(enabled=True, os_packages=False),
        patch=SimpleNamespace(auto_generate_for_kev=auto),
    )


def test_drafting_is_off_when_the_flag_is_off(monkeypatch):
    from sentinel.scan import orchestrator
    called = False

    def _boom(*a, **k):
        nonlocal called
        called = True
        raise AssertionError("should not have been reached")

    monkeypatch.setattr("sentinel.config.get_secrets", _boom)
    out = run(orchestrator._draft_plans(_StubDB(), _cfg(auto=False)))
    assert out == {"status": "disabled"}
    assert not called          # not even the secrets file is opened


def test_no_api_key_skips_drafting_without_failing_the_scan(monkeypatch):
    from sentinel.scan import orchestrator
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: SimpleNamespace(get=lambda k: None))
    out = run(orchestrator._draft_plans(_StubDB(), _cfg()))
    assert out["status"] == "skipped"


def test_a_crash_in_drafting_never_fails_the_scan(monkeypatch):
    """Scanning is deterministic and free; drafting is a paid model call. The
    cheap, reliable half must not be taken down by the expensive one."""
    from sentinel.scan import orchestrator
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: SimpleNamespace(get=lambda k: "sk-ant-test"))

    async def _explode(*a, **k):
        raise RuntimeError("api down")

    monkeypatch.setattr("sentinel.patch.planner.generate_for_kev", _explode)
    out = run(orchestrator._draft_plans(_StubDB(), _cfg()))
    assert out["status"] == "failed"       # recorded, not raised


def test_drafting_reports_only_the_plans_that_validated(monkeypatch):
    from sentinel.scan import orchestrator
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: SimpleNamespace(get=lambda k: "sk-ant-test"))

    async def _results(*a, **k):
        return [(7, "validated"), (8, "rejected_invalid"), (None, "buget: depășit")]

    monkeypatch.setattr("sentinel.patch.planner.generate_for_kev", _results)
    out = run(orchestrator._draft_plans(_StubDB(), _cfg()))
    assert out["attempted"] == 3 and out["validated"] == 1
    assert out["plan_ids"] == [7]


def test_drafting_is_capped_per_pass(monkeypatch):
    from sentinel.scan import orchestrator
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: SimpleNamespace(get=lambda k: "sk-ant-test"))
    seen: dict[str, Any] = {}

    async def _capture(db, cfg, key, limit):
        seen["limit"] = limit
        return []

    monkeypatch.setattr("sentinel.patch.planner.generate_for_kev", _capture)
    run(orchestrator._draft_plans(_StubDB(), _cfg()))
    assert seen["limit"] == orchestrator.MAX_PLANS_PER_PASS <= 3


def test_generation_is_not_application():
    """The safety property that makes automatic drafting acceptable at all:
    nothing generated here can reach the machine without two taps."""
    src = (__import__("pathlib").Path(__file__).resolve().parents[2]
           / "sentinel" / "scan" / "orchestrator.py").read_text(encoding="utf-8")
    assert "run_plan" not in src and "apply" not in src.split("_draft_plans")[1]


# --- the message ------------------------------------------------------------
@dataclass
class _Exec(dict):
    pass


def _row(**kw):
    base = {"id": 4, "plan_id": 3, "mode": "dry_run", "status": "succeeded",
            "duration_ms": 74, "error": None, "triggered_by": "web:operator",
            "rollback_reason": None}
    base.update(kw)
    return base


def test_dry_run_message_says_nothing_changed():
    pytest.importorskip("telegram")
    from sentinel.telegram import bot
    text = bot._format_execution(_row())
    assert "Dry-run" in text and "Nimic nu a fost modificat" in text
    assert "web:operator" in text


def test_apply_message_does_not_claim_nothing_changed():
    pytest.importorskip("telegram")
    from sentinel.telegram import bot
    text = bot._format_execution(_row(mode="apply", status="succeeded"))
    assert "Nimic nu a fost modificat" not in text


def test_rollback_reason_is_carried():
    """The reason is the entire point of the message when a patch rolls back."""
    pytest.importorskip("telegram")
    from sentinel.telegram import bot
    text = bot._format_execution(
        _row(mode="apply", status="rolled_back",
             rollback_reason="health check nginx a eșuat după 30s"))
    assert "health check nginx" in text


def test_message_escapes_html():
    """`triggered_by` contains a username, and the message is parse_mode=HTML."""
    pytest.importorskip("telegram")
    from sentinel.telegram import bot
    text = bot._format_execution(_row(triggered_by="web:<b>x</b>"))
    assert "<b>x</b>" not in text.replace("<b>Dry-run", "")


# --- the dry-run must not destroy the way to apply --------------------------
def test_dry_run_never_edits_the_plan_message():
    """`edit_message_text` replaces the inline keyboard as well as the text, so
    editing the plan message to report a dry-run DELETED the approve button.
    The one action meant to build confidence before applying became the thing
    that made applying impossible."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import patch_flow
    src = inspect.getsource(patch_flow.on_dry_run)
    assert "query.edit_message_text" not in src, \
        "on_dry_run edits the plan message — the approve button dies with it"
    assert "reply_text" in src          # the result goes underneath it instead


def test_dry_run_reports_progress_without_touching_the_plan():
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import patch_flow
    src = inspect.getsource(patch_flow.on_dry_run)
    # Progress and result land on the same NEW message, edited in place.
    assert "progress = await query.message.reply_text" in src
    assert src.count("progress.edit_text") >= 2      # refused, and finished


def test_reject_still_edits_because_the_plan_is_dead():
    """The counter-case, so the rule above is not applied blindly: rejecting a
    plan SHOULD replace the message — leaving live-looking approve buttons on a
    rejected plan is worse than losing them."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import patch_flow
    assert "edit_message_text" in inspect.getsource(patch_flow.on_reject)


def test_an_unexpected_error_does_not_wipe_the_plan_message():
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot.on_patch_callback)
    handler = src.split("except Exception", 1)[1]
    assert "reply_text" in handler and "edit_message_text" not in handler


def test_an_unauthorised_tap_is_an_alert_not_an_edit():
    """One viewer tapping a button must not delete the plan for everyone else
    in the chat."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot.on_patch_callback)
    guard = src.split("_can_act", 1)[1].split("from sentinel.telegram", 1)[0]
    assert "show_alert=True" in guard
    assert "edit_message_text" not in guard


# --- isolation --------------------------------------------------------------
def test_each_push_source_is_isolated():
    """One failing query must not stop the others. A broken plan push used to be
    enough to silence incident alerts, which are the ones that matter most."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot._push_loop)
    assert "for name, fn in sources" in src
    assert src.count("try:") == 1 and "await fn(" in src


def test_a_plan_that_reached_nobody_is_retried():
    """An unsent incident is still in the dashboard. An unsent plan is a decision
    nobody was asked to make."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot._push_plans)
    assert "if sent:" in src
    assert "mark_plan_notified" in src.split("if sent:")[1].split("else:")[0]
