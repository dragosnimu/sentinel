"""Catalogul `/intreaba` trebuie să rămână SELECT-only.

Modelul alege o cheie din `sentinel/ai/ask.py:CATALOG` și niște parametri
validați — nu scrie SQL. Dar dacă o intrare nouă din catalog ar strecura vreodată
un verb de scriere (DML, DDL, sau ceva ca `DO`/`CALL`/`COPY ... TO PROGRAM` care
execută cod în loc să citească date), comanda ar deveni o cale de scriere pornită
dintr-un chat Telegram, exact ce §5 din arhitectură exclude explicit pentru
canalul ăsta.

Verificarea e statică, prin AST — nu grep pe text brut. Un grep pe text brut a
fost prima versiune, și un verificator a demonstrat că extinderea listei de verbe
cu cuvinte scurte ca `CALL` sau `DO` ar fi transformat garda într-un fals-pozitiv
permanent: `ask.py` însuși vorbește despre „the second model **call**" și „if
this **call** is unavailable" în docstring-uri și comentarii — cuvinte englezești
obișnuite, nu SQL. Citind doar argumentele-șir trimise efectiv la
`db.fetch`/`fetchval`/`fetchrow`/`execute`, garda vede SQL-ul real și ignoră
proza din jurul lui.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

ASK_PY = Path(__file__).resolve().parents[2] / "sentinel" / "ai" / "ask.py"

_DB_METHODS = {"fetch", "fetchval", "fetchrow", "execute", "executemany"}

# DML/DDL, plus verbe PostgreSQL care execută cod sau scriu fișiere fără să fie
# UPDATE/INSERT/DELETE în sens clasic: `DO` rulează un bloc PL/pgSQL anonim,
# `CALL` invocă o procedură (poate scrie orice), `COPY ... TO PROGRAM` scrie pe
# disc și poate rula un shell, `MERGE` (PG16+) e INSERT+UPDATE+DELETE într-o
# singură instrucțiune.
_WRITE_VERBS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|GRANT|REVOKE|CREATE|"
    r"MERGE|COPY|CALL|DO)\b",
    re.IGNORECASE)


def _sql_argument_strings(path: Path = ASK_PY) -> list[tuple[str, int]]:
    """Fiecare literal-șir trimis ca argumentul `sql` al unei metode `db.*` de
    citire/scriere, cu linia lui. Nu docstring-uri, nu comentarii, nu proză —
    doar ce ajunge cu adevărat la PostgreSQL.

    `Database.execute(self, sql, ...)` (și celelalte) acceptă `sql` fie
    poziţional, fie pe nume — `db.execute(sql="...")` e o formă la fel de
    validă ca `db.execute("...")`. O primă versiune verifica doar
    `node.args[0]` și sărea tăcut orice apel scris cu `sql=`, exact gaura pe
    care `test_telegram_command_names.py` a documentat-o deja pentru
    `CommandHandler(command=...)` — aceeași lecție, alt fișier, nescrisă aici
    până acum.

    `path` e parametrizabil ca `test_the_search_finds_sql_passed_as_a_keyword_argument`
    să poată rula EXTRACȚIA REALĂ pe un modul fabricat, nu o copie a logicii ei
    — o copie ar putea diverge tăcut de original și ar da o falsă senzație de
    siguranță."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in _DB_METHODS:
            continue
        first = node.args[0] if node.args else next(
            (kw.value for kw in node.keywords if kw.arg == "sql"), None)
        if first is None:
            # Nici argument poziţional, nici `sql=` pe nume — un apel căruia
            # nu i se poate găsi interogarea nu poate fi declarat curat.
            found.append((f"<fără argument sql găsit, linia {node.lineno}>", node.lineno))
        elif isinstance(first, ast.Constant) and isinstance(first.value, str):
            found.append((first.value, first.lineno))
        else:
            # O interogare construită altfel decât un literal-șir simplu (o
            # f-string, o concatenare) nu poate fi citită static — și tocmai de
            # asta există `test_the_search_actually_walks_real_calls` mai jos,
            # ca o listă goală aici să nu treacă drept „totul e curat".
            found.append((f"<neconstant, linia {node.lineno}>", node.lineno))
    return found


def test_the_file_is_actually_found() -> None:
    """Un test care caută într-un fișier inexistent trece verde fără să
    verifice nimic — la fel de gol ca lipsa lui."""
    assert ASK_PY.is_file()


def test_the_search_actually_walks_real_calls() -> None:
    """Zece interogări în catalog — dacă parcurgerea AST nu le vede pe toate,
    garda de mai jos pare să treacă fără să fi verificat nimic."""
    queries = _sql_argument_strings()
    assert len(queries) >= 10, f"doar {len(queries)} interogări găsite; formatul s-a schimbat?"
    ilizibile = [q for q in (t[0] for t in queries)
                if q.startswith("<neconstant") or q.startswith("<fără argument")]
    assert not ilizibile, f"interogări necitibile static: {ilizibile}"


def test_the_search_finds_sql_passed_as_a_keyword_argument() -> None:
    """`Database.execute(self, sql, ...)` acceptă `sql` și pe nume —
    `db.execute(sql="DELETE FROM ask_log")` e la fel de valid pentru Python ca
    forma pozițională. O primă versiune a gărzii verifica doar `node.args[0]`
    și sărea complet un apel scris așa — verificatorul a demonstrat exact asta
    injectat în `ask.py`, cu garda rămasă verde. Aici se dovedește prin
    execuție, pe un modul fabricat, că extragerea chiar vede forma pe nume."""
    import tempfile

    sursa = (
        "async def f(db):\n"
        "    await db.execute(sql=\"DELETE FROM ask_log\")\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                     encoding="utf-8", newline="\n") as tmp:
        tmp.write(sursa)
        tmp_path = Path(tmp.name)
    try:
        # Extracția REALĂ, nu o copie a ei — vezi docstring-ul lui `_sql_argument_strings`.
        found = _sql_argument_strings(tmp_path)
        assert found == [("DELETE FROM ask_log", 2)], found
        assert _WRITE_VERBS.search(found[0][0])
    finally:
        tmp_path.unlink()


def test_no_catalog_query_contains_a_write_verb() -> None:
    offenders = [f"linia {line}: {sql.strip()[:80]!r}"
                for sql, line in _sql_argument_strings() if _WRITE_VERBS.search(sql)]
    assert not offenders, (
        "verb de scriere găsit într-o interogare din sentinel/ai/ask.py:\n    "
        + "\n    ".join(offenders)
        + "\n  Catalogul /intreaba trebuie să rămână SELECT-only — o comandă "
          "read-only pornită dintr-un chat Telegram nu are voie să scrie.")


def test_the_guard_can_actually_see_a_write_verb() -> None:
    """Garda gărzii: fără asta, un tipar prea îngust ar trece verde pentru
    totdeauna, indiferent ce se scrie în catalog."""
    assert _WRITE_VERBS.search("DELETE FROM ask_log")
    assert _WRITE_VERBS.search("insert into blocklist")
    assert _WRITE_VERBS.search("DO $$ BEGIN RAISE NOTICE 'x'; END $$")
    assert _WRITE_VERBS.search("CALL some_procedure()")
    assert _WRITE_VERBS.search("COPY ask_log TO PROGRAM 'rm -rf /'")
    assert _WRITE_VERBS.search("MERGE INTO ask_log USING x ON true WHEN MATCHED THEN DELETE")
    assert not _WRITE_VERBS.search("SELECT count(*) FROM ask_log")


def test_the_guard_ignores_the_word_call_in_prose() -> None:
    """Motivul pentru care garda citește doar argumentele SQL, nu tot fișierul:
    `ask.py` chiar conține cuvântul "call" de multe ori, în engleză obișnuită."""
    source = ASK_PY.read_text(encoding="utf-8")
    assert re.search(r"\bcall\b", source, re.IGNORECASE), (
        "fixtura asta presupune că fișierul chiar conține cuvântul 'call' în "
        "proză — dacă nu mai există, testul nu demonstrează nimic")
    # Și totuși garda reală, care citește doar argumentele SQL, nu găsește CALL.
    assert not any(_WRITE_VERBS.search(sql) and "CALL" in sql.upper()
                  for sql, _ in _sql_argument_strings())
