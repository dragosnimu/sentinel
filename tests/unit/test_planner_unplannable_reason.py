"""`sentinel/patch/planner.py:unplannable_reason` — refuzul care ține
`/planifica` departe de un apel Opus garantat inutil.

Docstring-ul funcției e explicit: „O familie necunoscută NU e tratată ca
«probabil rpm» — «nu știu» și «e bine» sunt stări diferite, iar direcția
sigură aici e refuzul." Testele de aici pică dacă `OS_PACKAGE_ECOSYSTEM.get`
capătă vreodată un implicit — o familie `platform.family` neconfigurată (o
gazdă nouă, sau o greșeală de scriere în config) ar deveni tăcut „probabil
rpm" și ar lăsa un plan `dnf` plauzibil să fie cerut pentru un pachet care nu
e deloc al gazdei.
"""
from __future__ import annotations

from sentinel.patch import planner


def test_a_recognised_family_with_the_matching_ecosystem_is_plannable():
    assert planner.unplannable_reason("rpm", "rhel") is None
    assert planner.unplannable_reason("deb", "debian") is None


def test_an_unrecognised_family_refuses_instead_of_guessing_rpm():
    """Cauza reală pe care fișierul o previne: `platform.family` necunoscut
    NU are voie să se comporte ca `rhel`. O gazdă `alpine` sau o valoare goală
    de config ar trece tăcut planuri `dnf` pentru findinguri care nu sunt ale
    ei."""
    motiv = planner.unplannable_reason("rpm", "alpine")
    assert motiv is not None, (
        "o familie necunoscută (`alpine`) a fost tratată ca planificabilă — "
        "exact «probabil rpm» pe care docstring-ul îl refuză")
    assert "nu se știe ce pachete" in motiv


def test_a_mismatched_ecosystem_is_refused_on_a_known_family():
    motiv = planner.unplannable_reason("npm", "rhel")
    assert motiv is not None
    assert "npm" in motiv and "rpm" in motiv


def test_a_missing_ecosystem_is_refused_not_guessed():
    motiv = planner.unplannable_reason(None, "rhel")
    assert motiv is not None
    assert "nu spune din ce ecosistem" in motiv


def test_family_matching_is_case_and_whitespace_insensitive():
    assert planner.unplannable_reason("rpm", " RHEL \n") is None
