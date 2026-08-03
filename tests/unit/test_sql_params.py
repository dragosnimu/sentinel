"""Parameter typing in SQL that the test stubs cannot see.

Every repo test drives a stub database that records the SQL string and hands
back canned rows. That catches wrong *logic* and is blind to wrong *SQL*: a
statement Postgres refuses to even prepare passes every one of those tests and
then fails on the first real call.

One such statement shipped. `finish_execution` wrote

    rollback_reason = $5,
    rollback_at = CASE WHEN $5 IS NULL THEN rollback_at ELSE now() END

and Postgres could not determine the type of `$5`. `IS NULL` accepts anything,
so it contributes no type; and an UPDATE SET assignment is coerced *after*
parameter inference runs, so `rollback_reason = $5` contributed none either.
The result was `AmbiguousParameterError` on every call, whatever the values —
so no execution the patch runner ever started could be finished.

This file pins the pattern. It is a lint, not a substitute for a real database:
it catches the shape that bit us, not every possible typing mistake.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SOURCES = sorted((REPO / "sentinel").rglob("*.py")) + sorted((REPO / "executor").rglob("*.py"))

# `$5 IS NULL` / `$5 IS NOT NULL` with no cast between the parameter and IS.
UNCAST_IS_NULL = re.compile(r"\$\d+\s+IS\s+(?:NOT\s+)?NULL", re.I)

# Any $N, and the same $N followed by ::type.
PARAM = re.compile(r"\$(\d+)")


def _sql_literals(path: Path) -> list[tuple[int, str]]:
    """Every string constant in the file that looks like SQL."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:  # pragma: no cover - would fail the compile test first
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
            if PARAM.search(text) and re.search(
                r"\b(SELECT|INSERT|UPDATE|DELETE)\b", text, re.I
            ):
                out.append((node.lineno, text))
    return out


def test_no_parameter_is_null_without_a_cast():
    """`$N IS NULL` gives Postgres nothing to infer from. Cast it: `$N::text`."""
    offenders = []
    for path in SOURCES:
        for lineno, sql in _sql_literals(path):
            if UNCAST_IS_NULL.search(sql):
                offenders.append(f"{path.relative_to(REPO)}:{lineno}")
    assert not offenders, (
        "uncast parameter in an IS NULL test — Postgres cannot infer its type: "
        + ", ".join(offenders)
    )


def test_the_statement_that_broke_is_fully_cast():
    """Regression: pin the exact statement, so a future edit that drops the
    casts fails here rather than on the operator's screen."""
    src = (REPO / "sentinel" / "db" / "repo" / "patches.py").read_text(encoding="utf-8")
    # Anchored on the function, not on the first `UPDATE patch_executions` in
    # the file — other statements touch that table, and matching one of those
    # instead would make this test pass while checking nothing.
    fn = src.split("async def finish_execution", 1)[1].split("\nasync def ", 1)[0]
    stmt = fn.split("UPDATE patch_executions SET", 1)[1].split('"""', 1)[0]
    for param in ("$2", "$3", "$4", "$5", "$6"):
        assert f"{param}::" in stmt, f"{param} is uncast in finish_execution"
    assert "$5::text IS NULL" in stmt


def test_the_lint_actually_matches_the_broken_shape():
    """Guard the guard: a regex that silently stops matching is a test that
    passes forever. Feed it the statement as it shipped."""
    broken = """
        UPDATE patch_executions SET rollback_reason = $5,
            rollback_at = CASE WHEN $5 IS NULL THEN rollback_at ELSE now() END
        WHERE id = $1
    """
    assert UNCAST_IS_NULL.search(broken)
    assert not UNCAST_IS_NULL.search(broken.replace("$5 IS NULL", "$5::text IS NULL"))


# A broader rule — "every parameter used twice must be cast somewhere" — was
# tried and thrown away: it flagged a dozen correct statements. `INSERT ...
# VALUES ($1,$2)` and `make_interval(mins => $1 * 60)` are typed positions, and
# demanding casts there is noise that trains people to ignore the file. The two
# type-free positions are `IS NULL` and an UPDATE SET target, and only the
# combination of the two is unresolvable — which is exactly what is pinned above.
