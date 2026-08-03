"""Static checks on the SQL migrations that only a real Postgres would otherwise catch.

An index that references a non-IMMUTABLE function (now(), date_trunc on a
timestamptz, extract, ...) is accepted by every editor and every unit test that
does not actually run it, then rejected by Postgres at migration time with
"functions in index ... must be marked IMMUTABLE". It bit 0002 (a predicate) and
0008 (an expression) on the first real deploy. This keeps the class out.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

MIGRATIONS = Path(__file__).resolve().parents[2] / "sentinel" / "db" / "migrations"

# Functions that are STABLE/VOLATILE (not IMMUTABLE) and so cannot appear in an
# index expression or predicate. date_trunc is IMMUTABLE for `timestamp` but
# STABLE for `timestamptz`; the columns here are timestamptz, so treat it as
# unsafe in an index and use a stored column instead.
UNSAFE = re.compile(r"\b(now\s*\(|current_(date|time|timestamp)|date_trunc|extract\s*\(|to_char\s*\()", re.I)
CREATE_INDEX = re.compile(r"CREATE\s+(?:UNIQUE\s+)?INDEX.*?;", re.I | re.S)


def test_no_non_immutable_functions_in_indexes():
    offenders: list[str] = []
    for f in sorted(MIGRATIONS.glob("*.sql")):
        text = f.read_text(encoding="utf-8")
        for m in CREATE_INDEX.finditer(text):
            if UNSAFE.search(m.group(0)):
                line = text[: m.start()].count("\n") + 1
                offenders.append(f"{f.name}:{line}: {' '.join(m.group(0).split())[:90]}")
    assert not offenders, (
        "non-IMMUTABLE function in an index — Postgres rejects these at migration "
        "time. Use a stored column instead:\n  " + "\n  ".join(offenders)
    )


def test_migration_versions_are_unique():
    """Two files with the same number make `migrate` refuse to run at all — the
    whole schema stops advancing. It happened: a migration was renamed locally
    while the old file stayed on the server, and the duplicate was only found
    after deploying. This catches it before the tarball is built."""
    import collections
    import re
    from pathlib import Path

    migrations = Path(__file__).resolve().parents[2] / "sentinel" / "db" / "migrations"
    versions = collections.Counter()
    for f in migrations.glob("*.sql"):
        m = re.match(r"^(\d+)_", f.name)
        assert m, f"{f.name} does not start with a version number"
        versions[int(m.group(1))] += 1
    dupes = {v: n for v, n in versions.items() if n > 1}
    assert not dupes, f"duplicate migration versions: {sorted(dupes)}"


def test_migration_versions_have_no_gaps():
    """A gap usually means a file was deleted after being applied somewhere,
    which leaves environments silently disagreeing about the schema."""
    import re
    from pathlib import Path

    migrations = Path(__file__).resolve().parents[2] / "sentinel" / "db" / "migrations"
    nums = sorted(int(re.match(r"^(\d+)_", f.name).group(1))
                  for f in migrations.glob("*.sql"))
    assert nums == list(range(nums[0], nums[0] + len(nums))), \
        f"gap in migration numbering: {nums}"
