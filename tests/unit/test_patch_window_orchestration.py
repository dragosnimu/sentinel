"""`sentinel/patch/window.py:run` — orchestrarea ferestrei săptămânale.

Proprietatea urmărită în tot fișierul: fereastra scrie ÎNTOTDEAUNA un rând în
`patch_window_runs`, indiferent de rezultat (altfel „n-a rulat niciodată" și
„a rulat și n-a găsit nimic" arată identic — zero rânduri), eliberează CEL
MULT un plan pe rulare, nu eliberează nimic nou cât timp fereastra e
oprită sau mai are deja un plan eliberat, nerezolvat — și expiră explicit
candidații prea vechi, ÎNAINTE de orice altceva, ca îmbătrânirea peste plafon
să fie productivă (planul devine vizibil ca `expired` și deblochează un plan
proaspăt), nu o dispariție tăcută din `window_candidate_plans`.

Repo-ul e monkeypatch-uit funcție cu funcție, nu simulat prin SQL: decizia
testată e a lui `window.run`, nu forma interogărilor din `patches.py` — acelea
au propriile teste, cu propriul `_StubDB`.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from sentinel.db.repo import patches as repo
from sentinel.patch import window


def run(c):
    return asyncio.run(c)


def _plan(id_=1, reversible=True, backup_kind="path"):
    return SimpleNamespace(
        id=id_,
        plan={"risk": {"reversible": reversible},
              "backup": [{"kind": backup_kind, "source": "/etc/nginx"}]})


_GOOD_EVIDENCE = {"age_days": 1.0, "any_bad": False, "all_good": True}


def _wire(monkeypatch, *, halt=None, outstanding=None, candidates=None,
         evidence=None, expired=None):
    released: list[int] = []
    recorded: list[dict[str, Any]] = []

    async def _expire(db):
        return expired or []

    async def _halt(db):
        return halt

    async def _outstanding(db):
        return outstanding

    async def _candidates(db, *, limit):
        return candidates or []

    async def _evidence(db):
        return evidence

    async def _mark(db, plan_id):
        released.append(plan_id)

    async def _record(db, *, candidates, proposed_plan_id, halted, detail, skipped):
        recorded.append({"candidates": candidates, "proposed_plan_id": proposed_plan_id,
                         "halted": halted, "detail": detail, "skipped": skipped})
        return 1

    monkeypatch.setattr(repo, "expire_stale_window_candidates", _expire)
    monkeypatch.setattr(repo, "window_halt", _halt)
    monkeypatch.setattr(repo, "outstanding_window_plan", _outstanding)
    monkeypatch.setattr(repo, "window_candidate_plans", _candidates)
    monkeypatch.setattr(repo, "latest_archive_drill_summary", _evidence)
    monkeypatch.setattr(repo, "mark_proposed_by_window", _mark)
    monkeypatch.setattr(repo, "record_window_run", _record)
    return released, recorded


# --- halted ------------------------------------------------------------------
def test_a_halted_window_proposes_nothing_and_says_so(monkeypatch):
    released, recorded = _wire(
        monkeypatch, halt={"plan_id": 3, "execution_id": 9, "status": "failed"},
        candidates=[_plan(id_=5)], evidence=_GOOD_EVIDENCE)

    outcome = run(window.run(None, None))

    assert outcome.halted is True
    assert outcome.proposed_plan_id is None
    assert released == [], "a plan was released while the window was halted"
    assert recorded == [{"candidates": 0, "proposed_plan_id": None,
                        "halted": True, "detail": outcome.detail, "skipped": []}]


# --- outstanding -------------------------------------------------------------
def test_an_outstanding_release_blocks_a_new_one(monkeypatch):
    released, recorded = _wire(
        monkeypatch, outstanding={"id": 7}, candidates=[_plan(id_=8)],
        evidence=_GOOD_EVIDENCE)

    outcome = run(window.run(None, None))

    assert outcome.proposed_plan_id is None
    assert released == []
    assert "7" in outcome.detail


# --- no candidates -----------------------------------------------------------
def test_no_candidates_is_reported_as_nothing_pending(monkeypatch):
    _wire(monkeypatch, candidates=[])

    outcome = run(window.run(None, None))

    assert outcome.proposed_plan_id is None
    assert outcome.candidates == 0


# --- the eligible one gets released, and only one -----------------------------
def test_the_first_eligible_candidate_is_released_and_no_more_than_one(monkeypatch):
    """Falsificat: dacă bucla n-ar opri la primul eligibil, ambele planuri
    reversibile din listă ar fi eliberate simultan — exact configurația pe
    care oprirea la primul eșec trebuie s-o evite."""
    candidates = [_plan(id_=1, reversible=True, backup_kind="path"),
                  _plan(id_=2, reversible=True, backup_kind="path")]
    released, recorded = _wire(monkeypatch, candidates=candidates, evidence=_GOOD_EVIDENCE)

    outcome = run(window.run(None, None))

    assert outcome.proposed_plan_id == 1
    assert released == [1]
    assert recorded[0]["proposed_plan_id"] == 1


def test_an_ineligible_candidate_is_skipped_in_favour_of_the_next_one(monkeypatch):
    candidates = [_plan(id_=1, reversible=False),                      # blocked
                  _plan(id_=2, reversible=True, backup_kind="path")]   # eligible
    released, _ = _wire(monkeypatch, candidates=candidates, evidence=_GOOD_EVIDENCE)

    outcome = run(window.run(None, None))

    assert outcome.proposed_plan_id == 2
    assert released == [2]
    assert outcome.skipped and outcome.skipped[0]["plan_id"] == 1


def test_no_eligible_candidate_releases_nothing(monkeypatch):
    candidates = [_plan(id_=1, reversible=False), _plan(id_=2, backup_kind="rpm_state")]
    released, recorded = _wire(monkeypatch, candidates=candidates, evidence=_GOOD_EVIDENCE)

    outcome = run(window.run(None, None))

    assert outcome.proposed_plan_id is None
    assert released == []
    assert len(outcome.skipped) == 2
    assert recorded[0]["skipped"] == outcome.skipped


# --- always writes a row, whatever happened -----------------------------------
def test_every_outcome_writes_exactly_one_run_row(monkeypatch):
    """«N-a rulat niciodată» trebuie să rămână distinct de «a rulat și n-a
    găsit nimic» — imposibil dacă rularea nu scrie un rând."""
    scenarios = [
        dict(halt={"plan_id": 1, "execution_id": 1, "status": "failed"}),
        dict(outstanding={"id": 1}, candidates=[_plan()]),
        dict(candidates=[]),
        dict(candidates=[_plan(reversible=True, backup_kind="path")],
            evidence=_GOOD_EVIDENCE),
    ]
    for kwargs in scenarios:
        _, recorded = _wire(monkeypatch, **kwargs)
        run(window.run(None, None))
        assert len(recorded) == 1, (kwargs, recorded)


# --- aging out must be productive, never a silent disappearance --------------
def test_expiring_a_stale_candidate_is_reported_in_the_outcome(monkeypatch):
    """Runda 3: un plan care depășește plafonul de candidatură dispărea
    tăcut din `window_candidate_plans`, fără nicio urmă — și rămânea
    permanent fără plan proaspăt, fiindcă `generate_for_kev` refuză să
    redacteze cât timp unul `validated` există. Expirarea trebuie raportată
    în rezultatul rulării, nu doar făcută în bază fără ecou."""
    _, recorded = _wire(monkeypatch, expired=[42], candidates=[])

    outcome = run(window.run(None, None))

    assert outcome.expired == [42]
    assert "42" in outcome.detail
    assert "expirat" in outcome.detail.lower()
    assert "42" in recorded[0]["detail"]


def test_expiration_runs_even_when_the_window_is_halted(monkeypatch):
    """Expirarea e întreținere independentă de zăvor: un plan expirat n-a
    fost eliberat niciodată, deci n-are nicio legătură cu execuția care a
    declanșat oprirea. Dacă expirarea ar rula DOAR când fereastra nu e
    oprită, un plan ar putea îmbătrâni o săptămână în plus de fiecare dată
    când fereastra e oprită."""
    _, recorded = _wire(
        monkeypatch, expired=[7],
        halt={"plan_id": 3, "execution_id": 9, "status": "failed"})

    outcome = run(window.run(None, None))

    assert outcome.halted is True
    assert outcome.expired == [7]
    assert "7" in outcome.detail


def test_no_expiration_leaves_the_detail_unchanged(monkeypatch):
    """Reversul: fără niciun candidat expirat, mesajul nu trebuie să
    pomenească expirarea deloc."""
    _wire(monkeypatch, candidates=[], expired=[])

    outcome = run(window.run(None, None))

    assert outcome.expired == []
    assert "expirat" not in outcome.detail.lower()


def test_expiring_mention_survives_every_branch(monkeypatch):
    """Testele de mai sus pinează mențiunea expirării doar pe ramurile
    «zăvorât» și «fără candidați» — cele două fără niciun plan viu de
    evaluat. Pe «în așteptare» (`outstanding`), «eliberat» (un candidat
    reversibil) și «niciunul eligibil», adică exact săptămânile în care
    EXISTĂ planuri și se întâmplă ceva, `_with_expired` putea fi omis din
    `detail` (uitat pe o singură ramură, la o schimbare viitoare) fără niciun
    roșu: operatorul ar vedea planul propus sau blocat, dar n-ar mai afla
    niciodată că altul, alături, tocmai a fost expirat. Verifică toate cele
    cinci ramuri, nu doar pe cele două deja acoperite."""
    scenarios = {
        "halted": dict(halt={"plan_id": 3, "execution_id": 9, "status": "failed"}),
        "outstanding": dict(outstanding={"id": 7}, candidates=[_plan(id_=8)]),
        "no_candidates": dict(candidates=[]),
        "released": dict(candidates=[_plan(id_=1, reversible=True, backup_kind="path")],
                         evidence=_GOOD_EVIDENCE),
        "none_eligible": dict(candidates=[_plan(id_=1, reversible=False)],
                              evidence=_GOOD_EVIDENCE),
    }
    for name, kwargs in scenarios.items():
        _, recorded = _wire(monkeypatch, expired=[42], **kwargs)
        outcome = run(window.run(None, None))
        assert "42" in outcome.detail, (name, outcome.detail)
        # Și în RÂNDUL scris, nu doar în valoarea întoarsă. Fără asta, mutarea
        # lui `_with_expired` DUPĂ `record_window_run` lasă rândul de audit
        # fără mențiune și testul verde — dovedit pe ramura `outstanding`,
        # unde `detail` se construiește în doi pași, nu într-o expresie.
        assert "42" in recorded[0]["detail"], (name, recorded[0]["detail"])
        assert "expirat" in outcome.detail.lower(), (name, outcome.detail)
