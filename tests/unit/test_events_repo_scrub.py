"""Plasa de sub colectoare: niciun octet NUL nu ajunge în bază.

Eșecul, întâmplat de trei ori în două zile — de fiecare dată cu același simptom
și cu altă cauză: **ingestia oprită pentru TOATE sursele**, nu doar pentru cea
vinovată. `executemany` respinge lotul întreg, iar ce se vede în panou e o gazdă
care a devenit brusc liniștită.

A treia oară, cauza a fost un octet NUL: `argv` e NUL-separat în nucleu, auditd
codifică octeții bruți, iar PostgreSQL refuză `\u0000` în `text` și în `jsonb`.

Reparația adevărată e la sursă, în colector, și e făcută acolo. Asta e plasa:
`raw_events` primește text din cinci colectoare, iar al șaselea care va produce
un octet nepotrivit nu are voie să oprească din nou totul.
"""

from __future__ import annotations

from sentinel.db.repo.events import _scrub


def test_a_nul_in_a_plain_string_is_replaced() -> None:
    assert _scrub("a\x00b") == "a b"


def test_a_nul_nested_in_raw_is_replaced() -> None:
    """`raw` e `jsonb`, iar `json.dumps` scrie NUL ca `\u0000` — pe care
    PostgreSQL îl refuză la fel de tare ca pe octetul brut."""
    assert _scrub({"argv": "x\x00y", "paths": ["p\x00q"]}) == {
        "argv": "x y", "paths": ["p q"]}


def test_the_separator_becomes_a_SPACE_not_nothing() -> None:
    """Șters, două argumente s-ar lipi într-un cuvânt care nu s-a rulat."""
    assert _scrub("systemctl\x00restart") == "systemctl restart"


def test_values_that_are_not_text_pass_through_untouched() -> None:
    """Numerele, `None`, momentele — plasa nu are voie să le atingă."""
    for v in (None, 42, 3.5, True):
        assert _scrub(v) is v


def test_ordinary_text_is_returned_unchanged() -> None:
    """Garda celuilalt sens: fără ea, testele de mai sus ar trece și pentru o
    funcție care rescrie orice."""
    assert _scrub("systemctl restart nginx") == "systemctl restart nginx"
