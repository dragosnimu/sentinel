"""Oprirea la primul eșec (Funcționalitatea 08), verificată prin execuția reală
a `on_stage2` — nu prin citirea sursei.

Fereastra propune, iar omul atinge butoanele mai târziu, poate peste ore sau
zile. Dacă „oprire la primul eșec" ar fi impusă doar la propunere, un al
doilea plan deja eliberat înainte de primul eșec ar rămâne cu butonul activ
pe Telegram — și l-ar aplica oricum. Testele de aici pică exact pe scenariul
ăsta dacă poarta din `on_stage2` e scoasă sau ocolită.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.db.repo import approvals, patches as patch_repo
from sentinel.telegram import patch_flow


def run(c):
    return asyncio.run(c)


def _async(fn):
    async def wrapper(*a, **k):
        return fn(*a, **k)
    return wrapper


def _plan_row(id_=2, proposed_by_window=True):
    return SimpleNamespace(id=id_, proposed_by_window=proposed_by_window)


def _update_and_edits(chat_id: int = 42):
    edits: list[str] = []

    async def edit_message_text(text, **kw):
        edits.append(text)

    query = SimpleNamespace(edit_message_text=edit_message_text)
    update = SimpleNamespace(callback_query=query,
                             effective_chat=SimpleNamespace(id=chat_id))
    return update, edits


def _ctx():
    return SimpleNamespace(bot_data={"db": object(), "cfg": SimpleNamespace()})


def _wire_common(monkeypatch, *, plan_row, halt, approved=True, run_plan_calls):
    token_row = SimpleNamespace(stage=2, plan_id=plan_row.id, plan_hash="h")
    monkeypatch.setattr(approvals, "consume", _async(lambda *a, **k: token_row))
    monkeypatch.setattr(patch_repo, "get_plan", _async(lambda *a, **k: plan_row))
    monkeypatch.setattr(patch_repo, "window_halt", _async(lambda db: halt))
    monkeypatch.setattr(approvals, "revoke_for_plan", _async(lambda *a, **k: 0))

    async def _approve(*a, **k):
        run_plan_calls["approve"] = True
        return approved
    monkeypatch.setattr(patch_repo, "approve_plan", _approve)

    from sentinel.patch import runner

    async def _run_plan(*a, **k):
        run_plan_calls["run"] = True
        return SimpleNamespace(status="succeeded", execution_id=1, error=None, steps=[])
    monkeypatch.setattr(runner, "run_plan", _run_plan)


# --- the property that matters -----------------------------------------------
def test_a_window_plan_is_not_applied_after_the_window_has_a_recorded_failure(monkeypatch):
    """La momentul aplicării — nu la propunere — un plan eliberat de fereastră
    nu trece dacă un ALT plan al ferestrei a eșuat deja. Nici aprobarea, nici
    execuția nu au voie să fie atinse."""
    update, edits = _update_and_edits()
    calls: dict[str, bool] = {}
    _wire_common(monkeypatch,
                plan_row=_plan_row(id_=2, proposed_by_window=True),
                halt={"plan_id": 1, "execution_id": 9, "status": "failed"},
                run_plan_calls=calls)

    run(patch_flow.on_stage2(update, _ctx(), "tok"))

    assert calls == {}, "aprobarea sau execuția au fost atinse deși fereastra e oprită"
    assert any("oprit" in e.lower() or "fereastr" in e.lower() for e in edits), edits


def test_a_non_window_plan_is_unaffected_by_a_window_failure(monkeypatch):
    """Oprirea e o proprietate a FERESTREI, nu o înghețare globală a
    patching-ului: un plan care nu vine din fereastră trebuie să continue
    normal chiar dacă un plan de fereastră a eșuat în altă parte."""
    update, edits = _update_and_edits()
    calls: dict[str, bool] = {}
    _wire_common(monkeypatch,
                plan_row=_plan_row(id_=3, proposed_by_window=False),
                halt={"plan_id": 1, "execution_id": 9, "status": "failed"},
                run_plan_calls=calls)

    run(patch_flow.on_stage2(update, _ctx(), "tok"))

    assert calls.get("approve") is True
    assert calls.get("run") is True


def test_a_window_plan_applies_normally_with_no_prior_failure(monkeypatch):
    """Reversul, ca poarta să nu blocheze orbește tot ce vine din fereastră:
    fără niciun eșec anterior, planul trebuie aprobat și rulat ca înainte."""
    update, edits = _update_and_edits()
    calls: dict[str, bool] = {}
    _wire_common(monkeypatch,
                plan_row=_plan_row(id_=4, proposed_by_window=True),
                halt=None,
                run_plan_calls=calls)

    run(patch_flow.on_stage2(update, _ctx(), "tok"))

    assert calls.get("approve") is True
    assert calls.get("run") is True
