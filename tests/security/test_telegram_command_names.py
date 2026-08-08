"""Numele comenzilor Telegram, validate înainte să ajungă pe server.

Un alias cu diacritic — `știu` — a oprit tot canalul de alertare. Telegram
acceptă doar `[a-z0-9_]` într-un nume de comandă, iar `python-telegram-bot`
ridică `ValueError` la ÎNREGISTRARE, nu la folosire. Botul murea în
`build_application`, înainte de a porni, și systemd îl repornea la nesfârșit:
contorul ajunsese la 1113 când a fost observat.

Costul nu e proporțional cu greșeala. Comanda nouă n-ar fi mers — asta ar fi
fost în regulă. În schimb a murit canalul prin care un agent de securitate îți
spune orice, timp de aproape o zi, în tăcere.

Verificarea e statică: numele sunt literale în tabelele de înregistrare, deci se
pot citi fără să pornim nimic și fără biblioteca de Telegram instalată.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

BOT = Path(__file__).resolve().parents[2] / "sentinel" / "telegram" / "bot.py"

# Regula lui Telegram, nu a noastră: litere mici ASCII, cifre, underscore, 1-32.
VALID = re.compile(r"^[a-z0-9_]{1,32}$")


def _command_names() -> list[tuple[str, int]]:
    """Numele din tabelele `(("nume", "alias"), handler)`, cu linia lor.

    Citite din AST, nu cu o expresie regulată peste text: un nume construit
    dintr-o variabilă sau o concatenare ar scăpa unei potriviri textuale, iar
    testul ar trece exact pentru cazul pe care nu-l poate vedea.
    """
    tree = ast.parse(BOT.read_text(encoding="utf-8"), filename=str(BOT))
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        # Forma din cod: o listă de tupluri (tuplu_de_nume, handler).
        if not isinstance(node, ast.Tuple) or len(node.elts) != 2:
            continue
        names, _handler = node.elts
        if not isinstance(names, ast.Tuple):
            continue
        for elt in names.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                found.append((elt.value, elt.lineno))
    return found


def test_the_registration_tables_are_actually_found() -> None:
    """Fără asta, o schimbare de formă ar face testul să nu vadă nimic și să
    treacă — verde, gol, inutil."""
    names = _command_names()
    assert len(names) >= 20, f"am găsit doar {len(names)} nume; formatul s-a schimbat?"
    assert any(n == "status" for n, _ in names)


def test_every_command_name_is_valid_for_telegram() -> None:
    offenders = [f"{name!r} (linia {line})"
                 for name, line in _command_names() if not VALID.match(name)]
    assert not offenders, (
        "nume de comandă respinse de Telegram: " + ", ".join(offenders)
        + "\n  Doar [a-z0-9_], maxim 32. python-telegram-bot ridică ValueError la "
          "înregistrare, deci botul nu pornește deloc — nu doar comanda aceea."
    )


def test_no_command_name_is_registered_twice() -> None:
    """Al doilea `add_handler` pentru același nume nu crapă; pur și simplu nu se
    execută niciodată. O comandă care tace e mai greu de observat decât una care
    dă eroare."""
    from collections import Counter

    dupes = [n for n, c in Counter(n for n, _ in _command_names()).items() if c > 1]
    assert not dupes, f"nume înregistrate de mai multe ori: {dupes}"
