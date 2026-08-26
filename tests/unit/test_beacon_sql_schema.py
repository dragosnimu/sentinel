"""Every column the beacon's SQL names must exist in the migrated schema.

The beacon shipped with `SELECT hash FROM audit_log` for a year. The audit log
has `prev_hash` and `entry_hash`; it has never had `hash`. Postgres refused the
statement on every run, the probe caught the exception, logged a WARNING and
sent the beat anyway — so the external witness received `audit_head: ""` from
the day it was installed. The one field that makes a forged heartbeat expensive
was never in the signal, and nothing said so.

Every unit test passed throughout, because they all drive a stub database that
matches SQL by substring and hands back canned values: a stub cannot refuse a
column that does not exist. A test with a real Postgres would have caught it in
one call, and there is no Postgres in this suite.

So this is a lint, and it is worth being precise about what it can and cannot
prove:

*   it proves that every identifier the module's SQL uses in a column position
    is declared for the table the statement reads, and that every table it names
    exists — which is exactly the class of error that shipped;
*   it also pins the two ends of the audit chain against each other: the head
    the beacon reports and the head the writer chains onto are compared
    statement to statement, because the repaired probe is only correct relative
    to `db/repo/audit.py`, and a comment saying so does not enforce it;
*   it does NOT prove the statements are otherwise valid SQL, that the types
    work out, that a cast is inferable, or that the row means what the caller
    thinks. Only a real database proves that, and `pytest -m integration`
    against one is still the only way;
*   and it is blind where `KEYWORDS` is wrong: a column named after a SQL
    keyword would be skipped. None exists today, and the list is small enough to
    read.

Scope is deliberately narrow. Widening it to all of `sentinel/` is the obvious
next step, but it would first have to be reconciled with whatever else it flags,
and that is a different change from repairing the beacon.

`sentinel/db/identity_mirror.py` was added to `MODULES` when it was written, not
later: it is the only writer of the instance-identity mirror, its statements name
four columns across two tables, and a misspelling there is the same failure with
a longer fuse — the mirror never appears, and the one comparison that detects a
database restored onto a cloned host has nothing to compare against.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

REPO = Path(__file__).resolve().parents[2]
MIGRATIONS = REPO / "sentinel" / "db" / "migrations"
MODULE = REPO / "sentinel" / "report" / "beacon.py"
MODULES = (MODULE, REPO / "sentinel" / "db" / "identity_mirror.py")
CHAIN_WRITER = REPO / "sentinel" / "db" / "repo" / "audit.py"

# The one statement in `audit.record()` that reads the entry being chained onto.
WRITER_HEAD = re.compile(r'"([^"]*\bFROM audit_log\b[^"]*)"')

# `CREATE TABLE x (\n ... \n) [PARTITION BY ...];` — the newline after the open
# paren is what separates a real column list from `CREATE TABLE p PARTITION OF t
# FOR VALUES FROM (...) TO (...)`, which declares no columns of its own.
CREATE_TABLE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\(\s*\n(.*?)\n\)[^;]*;",
    re.I | re.S,
)
ALTER_TABLE = re.compile(r"ALTER\s+TABLE\s+(?:ONLY\s+)?(\w+)(.*?);", re.I | re.S)
ADD_COLUMN = re.compile(r"ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)", re.I)

# Line-leading words that begin a table constraint rather than a column.
NOT_A_COLUMN = {
    "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT", "EXCLUDE", "LIKE",
}

# Everything the beacon's statements contain that is not an identifier. Kept as
# a fixed list rather than a full SQL grammar: this file lints six statements,
# and a token missing from here fails loudly with the token in the message,
# which is a better failure than a parser that guesses.
KEYWORDS = {
    "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "NULL", "IS", "IN", "AS",
    "ORDER", "GROUP", "BY", "ASC", "DESC", "LIMIT", "OFFSET", "DISTINCT",
    "INSERT", "INTO", "VALUES", "ON", "CONFLICT", "DO", "NOTHING", "UPDATE",
    "SET", "RETURNING", "DELETE", "JOIN", "LEFT", "RIGHT", "INNER", "OUTER",
    "CASE", "WHEN", "THEN", "ELSE", "END", "FOR", "EXCLUDED", "WITH",
    # Literali booleeni, nu identificatori. Lipseau, iar lipsa lor s-a văzut
    # exact cum e proiectat să se vadă: primul `VALUES (true, $1)` care a trecut
    # pe aici a fost raportat drept „`true` nu e o coloană". Nicio instrucțiune
    # de dinainte nu conținea un boolean, deci golul nu era vizibil altfel.
    "TRUE", "FALSE",
}

TABLE_AFTER = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE)\s+([a-zA-Z_]\w*)", re.I)
STRING_LITERAL = re.compile(r"'[^']*'")
CAST = re.compile(r"::\s*\w+(?:\[\])?")
FUNCTION_CALL = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")
QUALIFIED = re.compile(r"\b([a-zA-Z_]\w*)\.(\w+)")
IDENTIFIER = re.compile(r"\b([a-zA-Z_]\w*)\b")
LOOKS_LIKE_SQL = re.compile(r"\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b")


def schema() -> dict[str, set[str]]:
    """table -> declared columns, from the migrations as they will be applied."""
    tables: dict[str, set[str]] = {}
    for path in sorted(MIGRATIONS.glob("*.sql")):
        text = path.read_text(encoding="utf-8")
        for name, body in CREATE_TABLE.findall(text):
            cols = tables.setdefault(name.lower(), set())
            depth = 0
            for line in body.splitlines():
                line = line.split("--", 1)[0]
                stripped = line.strip()
                # Only a line that starts at paren depth 0 starts a column; the
                # continuation of a multi-line CHECK does not.
                if depth == 0 and stripped:
                    word = re.match(r"(\w+)", stripped)
                    if word and word.group(1).upper() not in NOT_A_COLUMN:
                        cols.add(word.group(1).lower())
                depth += line.count("(") - line.count(")")
        for name, rest in ALTER_TABLE.findall(text):
            added = ADD_COLUMN.findall(rest)
            if added:
                tables.setdefault(name.lower(), set()).update(c.lower() for c in added)
    return tables


def statements(path: Path) -> list[tuple[int, str]]:
    """Every string constant in the module that is a SQL statement."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if LOOKS_LIKE_SQL.search(node.value):
                out.append((node.lineno, node.value))
    return out


def writer_head_statement() -> str:
    """The SQL `audit.record()` uses to find the entry it chains onto.

    Anchored on the function, not on the first SELECT over `audit_log` in the
    file: `verify_chain` and `recent` read the same table for other reasons, and
    matching one of those would make the comparison below pass while checking
    nothing.
    """
    src = CHAIN_WRITER.read_text(encoding="utf-8")
    fn = src.split("async def record", 1)[1].split("\nasync def ", 1)[0]
    found = WRITER_HEAD.findall(fn)
    assert len(found) == 1, (
        f"expected exactly one statement reading audit_log in record(), found "
        f"{len(found)}: {found}. Reformatted? Then this comparison is not "
        f"reading what it thinks, and must be repaired before it is trusted.")
    return found[0]


def shape(sql: str) -> str:
    """Whitespace and the writer's row lock removed; nothing else."""
    return " ".join(sql.split()).rstrip(";").removesuffix(" FOR UPDATE")


def check(sql: str, tables: dict[str, set[str]]) -> list[str]:
    """Identifiers in `sql` that no referenced table declares.

    Returns human-readable complaints; empty means the statement only names
    columns that exist.
    """
    problems: list[str] = []

    named = {t.lower() for t in TABLE_AFTER.findall(sql)} - {k.lower() for k in KEYWORDS}
    unknown_tables = sorted(t for t in named if t not in tables)
    problems += [f"unknown table `{t}`" for t in unknown_tables]
    known = [t for t in named if t in tables]
    if not known:
        # A statement whose table we cannot see is a statement this lint is not
        # checking. Saying so beats passing quietly.
        return problems + ["no table recognised — the lint cannot check this statement"]

    allowed: set[str] = set()
    for t in known:
        allowed |= tables[t]

    text = STRING_LITERAL.sub(" ", sql)
    text = CAST.sub(" ", text)                       # ::bigint is a type, not a column
    functions = {f.lower() for f in FUNCTION_CALL.findall(text)}
    qualified = {q.lower() for q, _ in QUALIFIED.findall(text)}

    for ident in IDENTIFIER.findall(text):
        low = ident.lower()
        # `named`, not `tables`: a table name is not an identifier only where the
        # statement itself uses it as one. Exempting every table in the schema
        # would wave through `SELECT incidents FROM audit_log`, and 51 free
        # passes is how a lint stops finding things.
        if (ident.upper() in KEYWORDS or low in named or low in functions
                or low in qualified or low in allowed):
            continue
        problems.append(f"`{ident}` is not a column of {'/'.join(sorted(known))}")
    return problems


# --- the schema map itself --------------------------------------------------
def test_the_schema_map_is_populated():
    """Guard the guard. A parser that quietly returns nothing makes every check
    below pass forever — the exact shape of test that has already cost this
    project an outage."""
    tables = schema()
    assert len(tables) > 20, f"only parsed {len(tables)} tables from the migrations"
    assert tables["audit_log"] >= {"id", "at", "prev_hash", "entry_hash"}
    assert "hash" not in tables["audit_log"], \
        "if this ever passes, the premise of this file changed"
    # A table declared by ALTER in a later migration must be visible too.
    assert "token_hash" in tables["sessions"]
    # A partition (`CREATE TABLE x PARTITION OF y`) declares no columns and must
    # not be mistaken for one with an empty column list.
    assert not tables.get("raw_events_default")
    assert {"id", "ts", "src_ip"} <= tables["raw_events"]


# --- the lint itself --------------------------------------------------------
def test_the_lint_flags_the_column_that_shipped():
    """The statement exactly as it ran on the server for a year. If this stops
    being flagged, the file below is decoration."""
    problems = check("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1", schema())
    assert any("`hash`" in p for p in problems), problems


def test_the_lint_accepts_the_repaired_statement():
    """The other half: a lint that flags everything is uninstallable, and gets
    uninstalled."""
    from sentinel.report import beacon
    assert check(beacon.AUDIT_HEAD_SQL, schema()) == []


def test_the_lint_flags_a_table_that_does_not_exist():
    """A misspelled table fails the same way a misspelled column does — at
    execution, on the server, inside an except branch.

    Asserted on the *complaint*, not on "some complaint came back". The first
    version of this test asserted only that the list was non-empty, and deleting
    the unknown-table branch outright left it green: the statement still tripped
    "no table recognised" five lines below, so the test was a duplicate of its
    neighbour wearing this one's docstring."""
    alone = check("SELECT id FROM audit_logs LIMIT 1", schema())
    assert any("unknown table `audit_logs`" in p for p in alone), alone

    # And mixed with a real table, where nothing else can catch it: the lint
    # recognises `audit_log`, so it does not bail out, and the only thing left
    # that notices `audit_logs` is the unknown-table branch.
    mixed = check("SELECT entry_hash FROM audit_log JOIN audit_logs ON 1=1", schema())
    assert any("unknown table `audit_logs`" in p for p in mixed), mixed


def test_a_column_that_shares_a_name_with_a_table_is_not_waved_through():
    """`incidents` is a table, so an identifier called `incidents` used as a
    column used to be exempted everywhere — the lint would have passed
    `SELECT incidents FROM audit_log`. Postgres would not."""
    problems = check("SELECT incidents FROM audit_log LIMIT 1", schema())
    assert any("`incidents`" in p for p in problems), problems


def test_the_lint_refuses_to_pass_a_statement_it_cannot_read():
    """SQL assembled from pieces hides the table from a static reader. Reporting
    "no problems" there would be the same lie in a new place."""
    assert check("SELECT entry_hash ORDER BY id DESC", schema())


# --- the two ends of the chain ---------------------------------------------
def test_the_beacon_reads_the_head_the_writer_chains_onto():
    """The probe and the audit writer must mean the same thing by "head".

    If the writer chains onto one row and the beacon reports another, the value
    in the heartbeat still looks like a hash and still changes, so nothing looks
    wrong — but it is no longer the head of the chain, and the one field that
    makes a forged beat expensive silently stops being evidence of anything.

    Comparing the two statements, not asserting a literal in each file: an
    assertion that `beacon.py` contains "ORDER BY id DESC" is satisfied by
    `beacon.py` alone, and `audit.py` can drift away from it untouched."""
    from sentinel.report import beacon
    assert shape(beacon.AUDIT_HEAD_SQL) == shape(writer_head_statement())


def test_the_writer_statement_was_actually_found():
    """Guard the guard: if the extraction above returns something that is not
    the writer's head read, the comparison passes on the wrong evidence."""
    stmt = writer_head_statement()
    assert "entry_hash" in stmt and "ORDER BY" in stmt, stmt
    # The lock is the writer's business and is deliberately the only thing
    # `shape` is allowed to drop — so it must actually be there to drop.
    assert stmt.endswith("FOR UPDATE"), stmt


# --- the modules -----------------------------------------------------------
def test_the_modules_have_statements_to_check():
    """An extractor that finds nothing would make the check below vacuous."""
    found = statements(MODULE)
    assert len(found) >= 6, f"only found {len(found)} statements in {MODULE.name}"
    assert any("audit_log" in sql for _, sql in found)

    mirror = statements(MODULES[1])
    assert len(mirror) >= 3, f"only found {len(mirror)} statements in {MODULES[1].name}"
    assert any("instance_identity" in sql for _, sql in mirror)
    assert any("collector_cursors" in sql for _, sql in mirror)


def test_the_sql_only_names_columns_that_exist():
    """These statements must read the schema that is actually deployed.

    A probe that names a column Postgres does not have fails on every run
    forever; the beat still leaves, so the operator sees a green service and the
    witness sees a field that is permanently empty. That is worse than a missing
    field, because it looks like an answer.

    For the mirror writer the fuse is longer and the end is quieter: the INSERT
    is refused every time, the row never appears, and the comparison that detects
    a database restored onto a cloned host has nothing left to compare."""
    tables = schema()
    offenders = []
    for module in MODULES:
        for lineno, sql in statements(module):
            for problem in check(sql, tables):
                offenders.append(f"{module.name}:{lineno}: {problem}")
    assert not offenders, "\n  " + "\n  ".join(offenders)
