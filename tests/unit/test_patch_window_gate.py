"""`sentinel/patch/window.py:evaluate` — poarta de eligibilitate pentru
Funcționalitatea 08, cu cele trei stări cerute.

Falsul care se previne aici nu e "poarta refuză" sau "poarta acceptă" —
e poarta care confundă „nedovedit" cu „dovedit reversibil", exact greșeala
care ar aplica automat o reparație a cărei întoarcere n-a fost verificată
niciodată. Testele folosesc `good_plan` din `tests/fixtures/good_plan.json`,
care amestecă un backup `rpm_state` cu unul `path` — planul realist, nu unul
inventat pentru fixture.
"""
from __future__ import annotations

import copy

import pytest

from sentinel.patch import window


def _fresh_good_evidence(age_days: float = 5.0) -> dict:
    return {"age_days": age_days, "any_bad": False, "all_good": True}


# --- REVERSIBLE ---------------------------------------------------------
def test_a_plan_with_a_fresh_verified_archive_is_reversible(good_plan):
    """Categoria cea mai frecventă de reparație — un backup mixt rpm_state +
    path — trebuie să poată trece poarta. Falsificat: dacă `evaluate` ar cere
    ca TOATE elementele de backup să fie `path`, planul ăsta n-ar trece
    niciodată, exact poarta naivă respinsă explicit de proiectare."""
    gate = window.evaluate(good_plan, _fresh_good_evidence())
    assert gate.state == window.REVERSIBLE


# --- NOT_REVERSIBLE -------------------------------------------------------
def test_a_plan_declared_irreversible_is_blocked(good_plan):
    plan = copy.deepcopy(good_plan)
    plan["risk"]["reversible"] = False
    gate = window.evaluate(plan, _fresh_good_evidence())
    assert gate.state == window.NOT_REVERSIBLE


def test_a_recently_broken_archive_blocks_every_plan_with_a_path_backup(good_plan):
    """Dovada cea mai recentă contează: dacă ultimul exercițiu a găsit o
    arhivă coruptă sau nereconstituită, mecanismul e sub îndoială chiar acum
    — indiferent ce plan anume e evaluat."""
    evidence = {"age_days": 1.0, "any_bad": True, "all_good": False}
    gate = window.evaluate(good_plan, evidence)
    assert gate.state == window.NOT_REVERSIBLE


# --- UNPROVEN --------------------------------------------------------------
def test_no_evidence_at_all_is_unproven_not_reversible(good_plan):
    """„Are un backup" și „se poate restaura" nu sunt același fapt — o
    absență de dovadă nu are voie să se citească drept succes."""
    gate = window.evaluate(good_plan, None)
    assert gate.state == window.UNPROVEN


def test_a_pure_bookkeeping_backup_is_unproven(good_plan):
    """Un plan fără NICIUN element `path` (doar rpm_state/git_ref) nu poate
    fi dovedit prin exercițiul actual, indiferent cât de bună e dovada
    globală despre arhive — nu există nimic al LUI de extras."""
    plan = copy.deepcopy(good_plan)
    plan["backup"] = [i for i in plan["backup"] if i["kind"] != "path"]
    assert plan["backup"], "fixture-ul nu mai are un element rpm_state de testat"
    gate = window.evaluate(plan, _fresh_good_evidence())
    assert gate.state == window.UNPROVEN


def test_stale_evidence_is_unproven_even_if_it_was_once_good(good_plan):
    """Falsificat: dacă pragul de vechime n-ar fi verificat, o dovadă de acum
    un an ar rămâne eligibilă pentru totdeauna."""
    evidence = {"age_days": window.RESTORE_DRILL_STALE_DAYS + 1, "any_bad": False,
               "all_good": True}
    gate = window.evaluate(good_plan, evidence)
    assert gate.state == window.UNPROVEN


def test_evidence_at_the_threshold_still_counts(good_plan):
    """Limita e inclusivă: exact la prag, dovada tot contează — altfel
    exercițiul lunar/săptămânal ar rata mereu cu o zi."""
    evidence = {"age_days": float(window.RESTORE_DRILL_STALE_DAYS), "any_bad": False,
               "all_good": True}
    gate = window.evaluate(good_plan, evidence)
    assert gate.state == window.REVERSIBLE


def test_inconclusive_evidence_is_unproven(good_plan):
    """Nici `any_bad`, nici `all_good` — cazul `skipped_low_disk`: verificat,
    dar neextras. Nici dovedit, nici respins."""
    evidence = {"age_days": 1.0, "any_bad": False, "all_good": False}
    gate = window.evaluate(good_plan, evidence)
    assert gate.state == window.UNPROVEN


def test_an_empty_backup_list_is_unproven(good_plan):
    plan = copy.deepcopy(good_plan)
    plan["backup"] = []
    gate = window.evaluate(plan, _fresh_good_evidence())
    assert gate.state == window.UNPROVEN
