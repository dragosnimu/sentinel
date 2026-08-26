"""Niciun apel de logare nu are voie să arunce în bucla care îl conține.

## Eșecul, întâmplat pe 25 august 2026

`log.info("login sessions projected", **proiectat)` — argumente cu nume, pasate
direct la logger. `Logger._log()` nu le acceptă și ridică `TypeError`.

Apelul era **în bucla de ingestie**, iar excepția a oprit colectarea pentru toate
cele cinci surse. Și numai atunci când chiar se deschidea o sesiune de login —
deci a arătat intermitent, ceea ce e mai greu de legat de cauză decât o pană
constantă.

E o formă a tiparului din `CLAUDE.md` pe care merită s-o numim separat: **codul
scris ca să RAPORTEZE ce s-a întâmplat a devenit motivul pentru care nu s-a
întâmplat.** O linie de jurnal nu are voie să fie mai fragilă decât munca pe care
o descrie.

## Ce se caută

Apeluri de logare cu `**` sau cu argumente cu nume care nu sunt cele acceptate de
`logging`. Găsit prin AST, nu prin regex: un apel scris pe trei linii sau cu un
comentariu între argumente ar scăpa unui tipar pe linie, iar aici tocmai
apelurile lungi sunt cele cu multe câmpuri.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

#: Ce acceptă `logging.Logger.info()` și rudele lui, pe lângă mesaj.
#:
#: Orice altceva ajunge la `Logger._log()` și ridică `TypeError`. Câmpurile
#: proprii se trec prin `extra={...}` — cum face tot restul proiectului.
ALLOWED_KWARGS = frozenset({"extra", "exc_info", "stack_info", "stacklevel"})

LOG_METHODS = frozenset({"debug", "info", "warning", "warn", "error",
                         "exception", "critical"})

SEARCHED = ("sentinel", "executor")


def _python_files() -> list[Path]:
    out: list[Path] = []
    for top in SEARCHED:
        out.extend(p for p in (ROOT / top).rglob("*.py")
                   if "__pycache__" not in p.parts)
    return out


def _bad_calls(tree: ast.AST) -> list[tuple[int, str]]:
    """Apelurile de logare cu argumente pe care `logging` nu le acceptă."""
    bad: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in LOG_METHODS:
            continue
        # `log.info(...)`, `logger.error(...)`, `self.log.warning(...)` — se cere
        # ca receptorul să se numească a logger, ca să nu se prindă un
        # `results.error(...)` oarecare.
        receptor = func.value
        nume = getattr(receptor, "id", None) or getattr(receptor, "attr", None)
        if nume is None or "log" not in str(nume).lower():
            continue

        for kw in node.keywords:
            if kw.arg is None:
                bad.append((node.lineno, "**kwargs despachetat direct în logger"))
            elif kw.arg not in ALLOWED_KWARGS:
                bad.append((node.lineno, f"argument cu nume `{kw.arg}=`"))
    return bad


def test_no_logging_call_passes_unsupported_keywords() -> None:
    """Forma care a oprit ingestia.

    `logging` acceptă doar `extra`, `exc_info`, `stack_info` și `stacklevel`.
    Orice altceva ridică `TypeError` DIN apelul de logare — adică din locul care
    trebuia doar să povestească ce s-a întâmplat.
    """
    gasite: list[str] = []
    for path in _python_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:  # pragma: no cover - un fișier stricat e altă problemă
            gasite.append(f"{path.relative_to(ROOT).as_posix()}: nu se parsează ({exc})")
            continue
        for line, why in _bad_calls(tree):
            gasite.append(f"{path.relative_to(ROOT).as_posix()}:{line} — {why}")

    assert not gasite, (
        "apeluri de logare pe care `logging` le refuză:\n    "
        + "\n    ".join(gasite)
        + "\n\nCâmpurile proprii se trec prin `extra={...}`. Un `TypeError` de "
          "aici cade în bucla care conține apelul — pe 25 august 2026 a oprit "
          "colectarea pentru toate sursele.")


def test_the_detector_recognises_the_call_that_broke_ingest() -> None:
    """Garda gărzii, cu linia exactă care a picat.

    Fără ea, un detector care nu potrivește nimic ar trece verde pe orice arbore
    — aceeași scăpare pe care o păzește `test_repo_is_sanitised` pentru scanarea
    lui.
    """
    rau = ast.parse('log.info("login sessions projected", **proiectat)')
    assert _bad_calls(rau), "detectorul nu vede apelul care a oprit ingestia"

    rau2 = ast.parse('log.info("ceva", sessions_opened=3)')
    assert _bad_calls(rau2), "detectorul nu vede un argument cu nume"


def test_the_detector_accepts_the_correct_form() -> None:
    """Un detector care țipă și la forma corectă e unul pe care cineva îl scoate.

    `extra=` e chiar felul în care trebuie scris, iar `exc_info=True` e forma
    obișnuită dintr-un `except`.
    """
    for bun in ('log.info("ceva", extra={"n": 3})',
                'log.error("ceva", exc_info=True)',
                'log.warning("ceva")',
                'rezultat.error("nu e un logger", detail=1)'):
        assert not _bad_calls(ast.parse(bun)), bun


def test_the_search_actually_walks_the_shipped_code() -> None:
    """O căutare pe zero fișiere trece verde și nu vede nimic."""
    fisiere = _python_files()
    assert len(fisiere) > 50, f"doar {len(fisiere)} fișiere căutate"
    assert any(p.name == "ingest_service.py" for p in fisiere)
