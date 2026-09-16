"""Poarta întoarcerii, verificată prin execuția reală a `on_stage1` — nu prin
citirea sursei.

Runda 2 (16 sep 2026) a dovedit prin execuție că poarta ținută doar la
propunere (`_verdict_de_intoarcere` + `allow_apply` în `bot.py`) era ocolibilă:
`/patch <id>` cheamă `send_plan_for_approval` fără niciun verdict, deci ORICE
plan `validated` — inclusiv unul `NOT_REVERSIBLE` — primea tastatura întreagă
și un token stage-1 proaspăt. Operatorul a decis: poarta stă în `on_stage1`,
unde ajunge orice token stage-1, indiferent pe ce cale a plecut butonul.

Testele de aici pică dacă poarta e scoasă din `on_stage1`, e ocolită de o cale
de intrare care nu trece prin el, sau devine strictă pe `UNPROVEN` — măsurat pe
ambele gazde pe 16 sep 2026, `latest_archive_drill_summary` nu are niciun rând,
deci ORICE plan e azi `UNPROVEN`; o poartă strictă pe starea asta ar opri toată
aprobarea, pe ambele gazde, chiar acum.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.db.repo import approvals, patches as patch_repo  # noqa: E402
from sentinel.patch import window  # noqa: E402
from sentinel.telegram import patch_flow  # noqa: E402


def run(c):
    return asyncio.run(c)


def _async(fn):
    async def wrapper(*a, **k):
        return fn(*a, **k)
    return wrapper


def _plan_row(id_=1, *, reversible_declared=True, backup_path=True):
    plan = {
        "target": {"asset_name": "web-1", "stack": "rpm"},
        "risk": {"reversible": reversible_declared, "blast_radius": "single host"},
        "backup": ([{"kind": "path", "path": "/etc/nginx"}] if backup_path else
                  [{"kind": "rpm_state", "package": "nginx"}]),
        "apply": [], "rollback": [],
    }
    return SimpleNamespace(id=id_, plan_hash="h", plan=plan, status="validated",
                           reversible=reversible_declared, estimated_downtime_s=5,
                           requires_reboot=False, risk_level="high")


def _update_and_edits(chat_id: int = 42):
    edits: list[str] = []

    async def edit_message_text(text, **kw):
        edits.append(text)

    query = SimpleNamespace(edit_message_text=edit_message_text)
    update = SimpleNamespace(callback_query=query,
                             effective_chat=SimpleNamespace(id=chat_id))
    return update, edits


def _ctx():
    return SimpleNamespace(bot_data={"db": object()})


def _wire_common(monkeypatch, *, plan_row, drill_evidence, issue_calls,
                 drill_raises=False):
    token_row = SimpleNamespace(stage=1, plan_id=plan_row.id, plan_hash=plan_row.plan_hash)
    monkeypatch.setattr(approvals, "consume", _async(lambda *a, **k: token_row))
    monkeypatch.setattr(patch_repo, "get_plan", _async(lambda *a, **k: plan_row))

    if drill_raises:
        async def _summary(db):
            raise RuntimeError("conexiune pierdută")
        monkeypatch.setattr(patch_repo, "latest_archive_drill_summary", _summary)
    else:
        monkeypatch.setattr(patch_repo, "latest_archive_drill_summary",
                            _async(lambda db: drill_evidence))

    async def _issue(db, **kw):
        issue_calls.append(kw)
        return "stage2-tok"
    monkeypatch.setattr(approvals, "issue", _issue)


# --- the property that matters -----------------------------------------------
def test_unproven_still_passes_the_gate_or_both_hosts_stop_approving_today(monkeypatch):
    """Măsurat pe producție ȘI pe n8n pe 16 sep 2026: `restore_drill_items` nu
    are niciun artefact-arhivă, deci `latest_archive_drill_summary` întoarce
    `None` și `window.evaluate` iese `UNPROVEN` pentru orice plan. Dacă poarta
    ar bloca pe `UNPROVEN`, /patch nu ar mai aproba NIMIC pe niciuna dintre
    gazde până la exercițiul din 1 oct — asta trebuie să rămână roșu dacă
    cineva înăsprește poarta."""
    update, edits = _update_and_edits()
    emise: list[dict] = []
    row = _plan_row(id_=10, reversible_declared=True, backup_path=True)
    _wire_common(monkeypatch, plan_row=row, drill_evidence=None, issue_calls=emise)

    run(patch_flow.on_stage1(update, _ctx(), "tok"))

    assert emise, ("niciun token stage-2 emis pentru un plan UNPROVEN — poarta "
                   "a devenit strictă pe stare nedovedită, nu doar pe NOT_REVERSIBLE")
    assert not any("Fără cale de întoarcere" in e for e in edits), edits


def test_a_self_declared_irreversible_plan_is_refused_at_stage1(monkeypatch):
    """`risk.reversible: false` e o dovadă POZITIVĂ, nu o lipsă de informație —
    exact ce `window.evaluate` numește NOT_REVERSIBLE. Niciun token stage-2 nu
    are voie să plece, indiferent pe ce cale a ajuns butonul aici."""
    update, edits = _update_and_edits()
    emise: list[dict] = []
    row = _plan_row(id_=11, reversible_declared=False, backup_path=True)
    _wire_common(monkeypatch, plan_row=row, drill_evidence=None, issue_calls=emise)

    run(patch_flow.on_stage1(update, _ctx(), "tok"))

    assert emise == [], "token stage-2 emis pentru un plan declarat irevocabil"
    assert any("Fără cale de întoarcere" in e for e in edits), edits


def test_a_drill_that_found_a_corrupt_archive_is_refused_at_stage1(monkeypatch):
    """Cealaltă sursă de NOT_REVERSIBLE: nu planul se declară irevocabil, ci
    exercițiul de restaurare a găsit deja o arhivă care nu se reface. Poarta
    trebuie să citească dovada proaspăt, nu doar declarația planului."""
    update, edits = _update_and_edits()
    emise: list[dict] = []
    row = _plan_row(id_=12, reversible_declared=True, backup_path=True)
    dovada = {"age_days": 3.0, "any_bad": True, "all_good": False}
    _wire_common(monkeypatch, plan_row=row, drill_evidence=dovada, issue_calls=emise)

    run(patch_flow.on_stage1(update, _ctx(), "tok"))

    assert emise == [], "token stage-2 emis deși ultimul exercițiu a găsit o arhivă coruptă"
    assert any("Fără cale de întoarcere" in e for e in edits), edits


def test_an_unreadable_drill_does_not_block_the_gate(monkeypatch):
    """O pană la citirea dovezii nu e un verdict NOT_REVERSIBLE — e o pană.
    Blocarea aici ar face o scurtă cădere a bazei să pară un plan irevocabil."""
    update, edits = _update_and_edits()
    emise: list[dict] = []
    row = _plan_row(id_=13, reversible_declared=True, backup_path=True)
    _wire_common(monkeypatch, plan_row=row, drill_evidence=None, issue_calls=emise,
                drill_raises=True)

    run(patch_flow.on_stage1(update, _ctx(), "tok"))

    assert emise, "poarta a blocat aprobarea din cauza unei pene la citirea dovezii"
    assert not any("Fără cale de întoarcere" in e for e in edits), edits


def test_the_gate_is_reached_even_when_the_button_never_computed_a_verdict(monkeypatch):
    """Reproduce exact calea `/patch <id>`: butonul pleacă din
    `send_plan_for_approval` fără `gate_note`/`allow_apply` — niciun verdict
    calculat la propunere — pentru un plan `NOT_REVERSIBLE`. Dacă poarta ar
    trăi doar la propunere, tokenul emis aici ar fi valid și ar deschide stage
    2 cu tastatura completă, exact regresia din runda 2."""
    emitted: list[dict] = []

    async def _fake_issue(db, **kw):
        emitted.append(kw)
        return "pap1-token"

    monkeypatch.setattr(approvals, "issue", _fake_issue)
    row = _plan_row(id_=14, reversible_declared=False, backup_path=True)

    class _Bot:
        sent: list = []

        async def send_message(self, chat_id, text, **kw):
            self.sent.append((text, kw))

    bot_obj = _Bot()
    run(patch_flow.send_plan_for_approval(bot_obj, object(), 42, row))
    assert emitted, "send_plan_for_approval nu a emis niciun token stage-1 de testat"
    assert emitted[0]["stage"] == 1 and emitted[0]["plan_id"] == row.id
    token = "pap1-token"

    update, edits = _update_and_edits()
    stage2_emise: list[dict] = []
    _wire_common(monkeypatch, plan_row=row, drill_evidence=None, issue_calls=stage2_emise)

    run(patch_flow.on_stage1(update, _ctx(), token))

    assert stage2_emise == [], (
        "un token stage-1 emis de o cale care n-a calculat niciun verdict a "
        "trecut oricum de poarta din on_stage1 — regresia din runda 2")
    assert any("Fără cale de întoarcere" in e for e in edits), edits
