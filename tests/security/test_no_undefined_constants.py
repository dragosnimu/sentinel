"""Constante folosite și nedefinite nicăieri.

`_MUTE_HELP` a fost referit de două ori în botul de Telegram și nu a fost
definit niciodată. Modulul se importa curat — Python caută numele abia la
apelare — deci `sentinel telegram` pornea, comenzile mergeau, și doar `/mute`
fără argumente ridica `NameError`. Adică exact comanda pe care o dai când vrei
să verifici dacă ești în liniște.

Un linter ar fi prins-o. Niciunul nu e instalat pe mașina de dezvoltare, iar o
verificare care depinde de o unealtă absentă nu e o verificare. Asta rulează în
suita normală, cu `ast` din biblioteca standard.

## De ce doar constantele

Regula se limitează la nume în MAJUSCULE, cu sau fără underscore inițial.
Detecția generală a numelor nedefinite înseamnă reimplementarea analizei de
domenii a lui pyflakes, cu toate cazurile ei — comprehensiuni, `global`,
`nonlocal`, walrus, closure-uri. Constantele acoperă clasa de greșeală care
chiar s-a întâmplat, cu aproape zero fals-pozitive, iar un test cu fals-pozitive
e un test pe care cineva îl dezactivează.
"""

from __future__ import annotations

import ast
import builtins
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
PACKAGES = ("sentinel", "executor")

CONSTANT = "^_?[A-Z][A-Z0-9_]*$"


def _python_files() -> list[Path]:
    files: list[Path] = []
    for pkg in PACKAGES:
        files += [p for p in (REPO / pkg).rglob("*.py")
                  if "__pycache__" not in p.parts]
    return sorted(files)


def _bound_names(tree: ast.AST) -> set[str]:
    """Tot ce leagă un nume, oriunde în fișier.

    Deliberat generos — atribuiri la orice nivel, importuri, definiții, `global`,
    parametri, `for`, `with`, `except ... as`. Un test care caută constante
    nedefinite trebuie să greșească înspre tăcere: un fals-pozitiv l-ar face
    ignorat, iar atunci n-ar mai prinde nici cazul real.
    """
    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.Global):
            bound.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            bound.update(node.names)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*":
                    # `from x import *` poate aduce orice. Nu putem ști ce, deci
                    # nu putem afirma nimic despre fișierul ăsta.
                    bound.add("*")
                    continue
                bound.add(alias.asname or alias.name.split(".")[0])
    return bound


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: str(p.relative_to(REPO)))
def test_no_constant_is_used_without_being_defined(path: Path) -> None:
    import re

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    bound = _bound_names(tree)
    if "*" in bound:
        pytest.skip("`import *` face analiza imposibilă")

    rx = re.compile(CONSTANT)
    missing = sorted({
        node.id for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        and rx.match(node.id)
        and node.id not in bound
        and not hasattr(builtins, node.id)
    })
    assert not missing, (
        f"{path.relative_to(REPO)} folosește constante nedefinite: {missing}\n"
        "  Modulul se importă curat — Python caută numele abia la apelare — deci "
        "greșeala apare doar pe ramura care chiar rulează."
    )
