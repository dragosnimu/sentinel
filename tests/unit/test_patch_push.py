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


def test_ai_drafted_plans_wait_for_the_window(monkeypatch):
    """Funcționalitatea 08: un plan `generated_by='ai'` nu are voie să treacă
    prin canalul rapid decât după ce `sentinel-patch-window` l-a marcat
    eliberat. Fără clauza asta, poarta de eligibilitate a ferestrei ar fi
    decorativă — planul ar ajunge oricum pe Telegram în 15 secunde, înainte
    ca fereastra să apuce vreodată să-l evalueze."""
    db = _StubDB()
    run(repo.unnotified_plans(db))
    sql = db.sql[0]
    assert "generated_by <> 'ai'" in sql
    assert "OR proposed_by_window" in sql
    # Trebuie să fie ÎN INTERIORUL clauzei principale, altfel un plan AI ar
    # trece indiferent de restul filtrelor.
    assert "AND (generated_by <> 'ai' OR proposed_by_window)" in sql


def test_a_window_released_plan_bypasses_the_recency_filter(monkeypatch):
    """`PLAN_TTL_HOURS` e 72; fereastra rulează săptămânal. Fără excepția
    asta, un plan pe care fereastra tocmai l-a eliberat ar cădea în afara
    propriei ferestre de propunere exact în clipa în care devine eligibil."""
    db = _StubDB()
    run(repo.unnotified_plans(db))
    sql = db.sql[0]
    assert "make_interval(hours => $1) OR proposed_by_window)" in sql


def test_the_predicate_actually_excludes_ai_plans_when_executed():
    """Interogarea asta decide ce ajunge pe telefon — nu e destul s-o citești.

    Găsit la revizuire: o aserțiune pe SUBȘIRUL clauzei trece chiar dacă
    cineva adaugă ` OR TRUE` la coada ei — precedența SQL face din
    `A AND B OR TRUE` un `(A AND B) OR TRUE`, adică „orice rând", și
    `3743 passed` n-a observat nimic. Testul ăsta EXECUTĂ clauza (peste
    SQLite; `now() - make_interval(...)` legat la un literal, `$n` la `?`,
    singurele substituții — decizia de filtrare rămâne verbatim) peste rânduri
    concrete, ca o asemenea mutație să producă un rezultat greșit observabil.
    """
    import sqlite3

    db = _StubDB()
    run(repo.unnotified_plans(db))
    where = db.sql[0].split("WHERE", 1)[1].split("ORDER BY", 1)[0]
    cutoff = "2026-08-01T00:00:00+00:00"
    where_sqlite = where.replace("now() - make_interval(hours => $1)", "?")

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE patch_plans (id INTEGER, notified_at TEXT, status TEXT, "
                 "created_at TEXT, generated_by TEXT, proposed_by_window INTEGER)")
    fresh = "2026-08-15T00:00:00+00:00"
    stale = "2026-01-01T00:00:00+00:00"
    conn.executemany("INSERT INTO patch_plans VALUES (?,?,?,?,?,?)", [
        (1, None, "validated", fresh, "ai", 0),      # AI, not released -> EXCLUDED
        (2, None, "validated", fresh, "ai", 1),      # AI, released -> included
        (3, None, "validated", stale, "ai", 0),      # AI, stale, not released -> EXCLUDED
        (4, None, "validated", stale, "ai", 1),      # AI, stale, released -> included
        (5, None, "validated", fresh, "manual", 0),  # not AI -> included
        (6, None, "rejected", fresh, "manual", 0),   # wrong status -> EXCLUDED
        (7, "x", "validated", fresh, "manual", 0),   # already notified -> EXCLUDED
    ])
    sql = f"SELECT id FROM patch_plans WHERE {where_sqlite}"
    matched = {r[0] for r in conn.execute(sql, (cutoff,))}
    assert matched == {2, 4, 5}, matched


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
    # The call to each source sits inside the per-source try, so one failing
    # source cannot take the others down. (Counting `try:` blocks would be
    # wrong — the quiet-hours lookup has its own, for its own reason.)
    body = src.split("for name, fn in sources", 1)[1]
    assert body.index("try:") < body.index("await fn(")
    assert "except Exception" in body


def test_a_plan_that_reached_nobody_is_retried():
    """An unsent incident is still in the dashboard. An unsent plan is a decision
    nobody was asked to make."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot._push_plans)
    assert "if sent:" in src
    assert "mark_plan_notified" in src.split("if sent:")[1].split("else:")[0]


# --- the informational notice (Funcționalitatea 08, runda 2) ----------------
# «Nu poate fi aplicat automat» și «nu trebuie să afli că există» sunt fapte
# diferite. `unnotified_plans` corect ține un plan AI în afara canalului
# rapid de aprobare pana e eliberat de fereastra; testele de aici verifică
# separat că EXISTENȚA lui ajunge oricum la operator, fără niciun buton.
def _notice_plan(id_=7, asset_name="nginx"):
    return SimpleNamespace(
        id=id_,
        plan={"target": {"asset_name": asset_name},
              "vulnerabilities": [{"cve": "CVE-2026-1", "finding_id": 1,
                                   "package": "nginx", "severity": "high"}]})


def test_the_notice_names_the_plan_and_the_reason_but_offers_no_button():
    pytest.importorskip("telegram")
    from sentinel.telegram import patch_flow

    text = patch_flow.format_window_notice(
        _notice_plan(), "niciun exercitiu de restaurare n-a atins o arhiva")
    assert "#7" in text
    assert "nginx" in text
    assert "niciun exercitiu de restaurare" in text
    assert "/patch 7" in text
    # Textul e trimis prin `_broadcast`, care nu primește niciun `kb` de la
    # `format_window_notice` — funcția întoarce doar text, nu markup.
    assert not isinstance(text, tuple)


def test_the_notice_path_never_touches_approval_or_execution():
    """Aserțiune structurală, ca `test_generation_is_not_application`: nimic
    din calea asta n-are voie să apeleze fluxul de aprobare sau executorul."""
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot._push_window_gated_notices)
    # Doar CORPUL, după docstring: docstring-ul chiar NUMEȘTE
    # `send_plan_for_approval` ca să spună că nu-l cheamă, iar o aserțiune pe
    # tot fișierul ar pica pe propria ei explicație.
    body = src.split('"""', 2)[-1]
    for forbidden in ("send_plan_for_approval", "approve_plan", "run_plan"):
        assert forbidden not in body, f"{forbidden} apare în corpul anunțului informativ"


def test_a_delivered_notice_is_marked_sent(monkeypatch):
    """Executat, nu doar citit: livrarea reușită trebuie să oprească
    retrimiterea, iar una eșuată trebuie să lase planul netrimis pentru
    reîncercare — la fel ca la butonul de aprobare."""
    pytest.importorskip("telegram")
    from sentinel.db.repo import patches as patch_repo
    from sentinel.telegram import bot

    plan = _notice_plan(id_=11)
    marked: list[int] = []

    async def _rows(db):
        return [plan]

    async def _evidence(db):
        return None

    async def _mark(db, plan_id):
        marked.append(plan_id)

    monkeypatch.setattr(patch_repo, "unnotified_window_gated_plans", _rows)
    monkeypatch.setattr(patch_repo, "latest_archive_drill_summary", _evidence)
    monkeypatch.setattr(patch_repo, "mark_window_notice_sent", _mark)

    sent_to: list[int] = []

    async def send_message(chat_id, text, **kw):
        sent_to.append(chat_id)

    app = SimpleNamespace(bot=SimpleNamespace(send_message=send_message))
    cfg = SimpleNamespace(telegram=SimpleNamespace(allowed_chat_ids=[111]))

    run(bot._push_window_gated_notices(app, cfg, object(), set()))

    assert sent_to == [111]
    assert marked == [11]


def test_a_notice_that_reached_nobody_is_not_marked_sent(monkeypatch):
    pytest.importorskip("telegram")
    from sentinel.db.repo import patches as patch_repo
    from sentinel.telegram import bot

    plan = _notice_plan(id_=12)
    marked: list[int] = []

    async def _rows(db):
        return [plan]

    async def _evidence(db):
        return None

    async def _mark(db, plan_id):
        marked.append(plan_id)

    monkeypatch.setattr(patch_repo, "unnotified_window_gated_plans", _rows)
    monkeypatch.setattr(patch_repo, "latest_archive_drill_summary", _evidence)
    monkeypatch.setattr(patch_repo, "mark_window_notice_sent", _mark)

    async def send_message(chat_id, text, **kw):
        raise RuntimeError("chat not found")

    app = SimpleNamespace(bot=SimpleNamespace(send_message=send_message))
    cfg = SimpleNamespace(telegram=SimpleNamespace(allowed_chat_ids=[111]))

    run(bot._push_window_gated_notices(app, cfg, object(), set()))

    assert marked == []


def test_the_notice_source_is_registered_in_the_push_loop():
    pytest.importorskip("telegram")
    import inspect

    from sentinel.telegram import bot
    src = inspect.getsource(bot._push_loop)
    assert '"plan_notices"' in src
    assert "_push_window_gated_notices" in src
