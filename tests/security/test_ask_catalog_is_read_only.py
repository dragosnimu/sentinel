"""Catalogul `/intreaba` trebuie să rămână SELECT-only.

Modelul alege o cheie din `sentinel/ai/ask.py:CATALOG` și niște parametri
validați — nu scrie SQL. Dar dacă o intrare nouă din catalog ar strecura vreodată
un `INSERT`/`UPDATE`/`DELETE`/DDL, comanda ar deveni o cale de scriere pornită
dintr-un chat Telegram, exact ce §5 din arhitectură exclude explicit pentru
canalul ăsta. Verificarea e statică: caută cuvintele-cheie de scriere direct în
sursă, fără bază de date și fără rețea.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

ASK_PY = Path(__file__).resolve().parents[2] / "sentinel" / "ai" / "ask.py"

_WRITE_VERBS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|GRANT|REVOKE|CREATE)\b",
    re.IGNORECASE)


def test_the_file_is_actually_found() -> None:
    """Un test care caută într-un fișier inexistent trece verde fără să
    verifice nimic — la fel de gol ca lipsa lui."""
    assert ASK_PY.is_file()


def test_no_catalog_query_contains_a_write_verb() -> None:
    source = ASK_PY.read_text(encoding="utf-8")
    offenders = [line.strip() for line in source.splitlines()
                if _WRITE_VERBS.search(line)]
    assert not offenders, (
        "verb de scriere găsit în sentinel/ai/ask.py: " + " | ".join(offenders)
        + "\n  Catalogul /intreaba trebuie să rămână SELECT-only — o comandă "
          "read-only pornită dintr-un chat Telegram nu are voie să scrie.")


def test_the_guard_can_actually_see_a_write_verb() -> None:
    """Garda gărzii: fără asta, un tipar prea îngust ar trece verde pentru
    totdeauna, indiferent ce se scrie în catalog."""
    assert _WRITE_VERBS.search("DELETE FROM ask_log")
    assert _WRITE_VERBS.search("insert into blocklist")
    assert not _WRITE_VERBS.search("SELECT count(*) FROM ask_log")
