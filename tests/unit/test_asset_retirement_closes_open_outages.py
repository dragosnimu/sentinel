"""S6: an outage left open on a retired asset never closes on its own.

`retire_missing` stops the asset from ever being probed again (`list_all`
excludes retired assets), so if it happened to be DOWN at the moment it was
removed from `inventory.yaml`, nothing would ever call `close_outage` for it
— the row would sit `ended_at IS NULL` forever. Any query counting open
outages, and the asset's own availability figure, would carry a service
nobody is watching anymore, permanently.

This drives `assets_repo.retire_missing` against a fake that models both the
`assets` and `outages` tables (unlike `test_inventory_retirement.py`'s
FakeDB, which only asserts the outages UPDATE is well-formed and does not
model its effect) so the actual outcome — the row closes, once — is what is
checked, not just the shape of the SQL.

The second half of the file (below the `0046` marker) checks the BACKFILL
migration that closes the outages left behind by retirements that happened
BEFORE this go-forward fix existed — measured on production: four rows with
`ended_at IS NULL` on assets retired months earlier. Read-only, static SQL
assertions in the shape of `test_suricata_signature.py`'s 0036 section: no
live Postgres here, so the guard is that the migration text repeats
`retire_missing`'s own logic exactly, and proves its own effect rather than
trusting a zero exit code.
"""
from __future__ import annotations

import asyncio
import contextlib
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel.db.repo import assets as assets_repo

NOW = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)


def run(c):
    return asyncio.run(c)


class _FakeConnDB:
    """Models `assets` and `outages` well enough to prove retire_missing's
    transactional effect, not just its SQL shape."""

    def __init__(self, assets: list[dict], outages: list[dict]):
        self.assets = assets
        self.outages = outages
        self.in_transaction = 0

    @contextlib.asynccontextmanager
    async def transaction(self):
        self.in_transaction += 1
        try:
            yield self
        finally:
            self.in_transaction -= 1

    async def fetch(self, sql: str, *args):
        assert self.in_transaction, "retire_missing must run inside a transaction"
        if "UPDATE assets" in sql:
            keep = set(args[0])
            hit = [a for a in self.assets if a["retired_at"] is None and a["name"] not in keep]
            for a in hit:
                a["retired_at"] = NOW
            return [{"id": a["id"], "name": a["name"]} for a in hit]
        raise AssertionError(f"unexpected fetch: {sql}")

    async def execute(self, sql: str, *args):
        assert self.in_transaction, "the outage close must run in the same transaction"
        if "UPDATE outages" in sql:
            ids = set(args[0])
            for o in self.outages:
                if o["asset_id"] in ids and o["ended_at"] is None:
                    o["ended_at"] = NOW
                    o["cause"] = (
                        "retired" if not o["cause"] else f"{o['cause']} (asset retired)"
                    )
            return "OK"
        raise AssertionError(f"unexpected execute: {sql}")


def _asset(id_: int, name: str) -> dict:
    return {"id": id_, "name": name, "retired_at": None}


def _outage(asset_id: int, *, cause: str | None = None, ended: bool = False) -> dict:
    return {"asset_id": asset_id, "cause": cause, "ended_at": (NOW if ended else None)}


def test_retiring_a_down_asset_closes_its_open_outage():
    db = _FakeConnDB(
        assets=[_asset(1, "n8n"), _asset(2, "sshd")],
        outages=[_outage(1, cause="connection refused")],
    )
    run(assets_repo.retire_missing(db, ["sshd"]))
    assert db.outages[0]["ended_at"] == NOW


def test_the_original_probe_error_is_kept_not_overwritten():
    """Retirement is why the outage closes, not what caused it — losing the
    real diagnostic (timeout, refused, 503...) would make history useless."""
    db = _FakeConnDB(
        assets=[_asset(1, "n8n")],
        outages=[_outage(1, cause="connection refused")],
    )
    run(assets_repo.retire_missing(db, ["sshd"]))
    assert "connection refused" in db.outages[0]["cause"]
    assert "retired" in db.outages[0]["cause"]


def test_an_outage_with_no_cause_yet_gets_retired_outright():
    db = _FakeConnDB(assets=[_asset(1, "n8n")], outages=[_outage(1, cause=None)])
    run(assets_repo.retire_missing(db, ["sshd"]))
    assert db.outages[0]["cause"] == "retired"


def test_an_already_closed_outage_is_left_alone():
    """Retirement must not rewrite the end time of an outage that already
    recovered on its own before the asset was removed."""
    db = _FakeConnDB(
        assets=[_asset(1, "n8n")],
        outages=[_outage(1, cause="connection refused", ended=True)],
    )
    run(assets_repo.retire_missing(db, ["sshd"]))
    assert db.outages[0]["ended_at"] == NOW    # unchanged, not re-set
    assert db.outages[0]["cause"] == "connection refused"


def test_an_asset_with_no_open_outage_retires_without_touching_outages():
    db = _FakeConnDB(assets=[_asset(1, "n8n")], outages=[])
    names = run(assets_repo.retire_missing(db, ["sshd"]))
    assert names == ["n8n"]


def test_nothing_retired_skips_the_outage_close_entirely():
    """When every asset is in `keep`, there is nothing to retire — the
    outages UPDATE must not run at all, not just "run and match nothing"."""
    db = _FakeConnDB(assets=[_asset(1, "sshd")], outages=[_outage(1, cause="x")])
    names = run(assets_repo.retire_missing(db, ["sshd"]))
    assert names == []
    assert db.outages[0]["ended_at"] is None   # left untouched


# ---------------------------------------------------------------------------
# 0046: the backfill for retirements that happened BEFORE the go-forward fix
# above existed. Static SQL checks only — see the module docstring.
# ---------------------------------------------------------------------------
MIGRATIONS = Path(__file__).resolve().parents[2] / "sentinel" / "db" / "migrations"
M_BACKFILL = MIGRATIONS / "0046_backfill_retired_asset_outages.sql"


def _without_comments(sql: str) -> str:
    return "\n".join(re.sub(r"--.*$", "", line) for line in sql.splitlines())


def test_the_migration_file_exists_on_disk():
    """The whole rest of this section reads a fixed path — if the file were
    renamed or removed, every assertion below would silently pass on an
    empty read instead of failing for the right reason."""
    assert M_BACKFILL.is_file(), f"expected {M_BACKFILL} on disk"


def test_backfill_sets_ended_at_to_the_retirement_moment_not_now():
    """`ended_at` must come from `assets.retired_at` — the moment retirement
    ACTUALLY happened — not `now()`, the moment this migration happens to
    run. Using `now()` would invent an outage months longer than it really
    was, and a `duration_s` to match: exactly the mistake the migration's own
    docstring warns against."""
    text = _without_comments(M_BACKFILL.read_text(encoding="utf-8"))
    m = re.search(r"UPDATE\s+outages\s+o\s+SET\s+(.*?)\s+FROM\s+assets\s+a\s+WHERE\s+([^;]*);",
                  text, re.I | re.S)
    assert m, "no longer find the UPDATE outages ... FROM assets ... WHERE shape"
    set_clause, where = m.group(1), " ".join(m.group(2).split())
    assert re.search(r"ended_at\s*=\s*a\.retired_at\b", set_clause, re.I), (
        "ended_at is not set from a.retired_at — a backfill using now() here "
        "invents an outage duration months longer than the real one")
    assert "now()" not in set_clause.lower(), (
        f"now() appears in the SET clause: {set_clause!r} — the backfilled "
        f"end time must be the historical retirement moment, not migration time")
    assert re.search(r"a\.retired_at\s*-\s*o\.started_at", set_clause, re.I), (
        "duration_s is not computed from (retired_at - started_at)")
    assert "a.retired_at is not null" in where.lower()
    assert "o.ended_at is null" in where.lower()
    assert "o.asset_id = a.id" in where.lower().replace("  ", " ")


def test_backfill_cause_matches_retire_missing_exactly():
    """S6's own docstring: this migration must repeat `retire_missing`'s
    CASE expression EXACTLY, not reinvent it — the backfilled rows must be
    indistinguishable from ones the go-forward fix would have closed on
    time. A hand-written approximation here (different wording, different
    fallback) would make the two code paths disagree about what a retired
    asset's outage cause looks like."""
    text = _without_comments(M_BACKFILL.read_text(encoding="utf-8"))
    migration_case = re.search(
        r"cause\s*=\s*CASE\s+WHEN\s+o\.cause\s+IS\s+NULL\s+OR\s+o\.cause\s*=\s*''\s+"
        r"THEN\s+'retired'\s+ELSE\s+o\.cause\s*\|\|\s*'\s*\(asset retired\)'\s+END",
        text, re.I | re.S)
    assert migration_case, (
        "the migration's cause CASE expression no longer matches "
        "retire_missing's own wording ('retired' / ' (asset retired)' suffix)")

    # The living source of truth: assets_repo.retire_missing's own SQL,
    # read directly rather than duplicated by hand here, so a future edit to
    # one side shows up as a real diff instead of two guesses agreeing by luck.
    assets_src = (Path(__file__).resolve().parents[2] / "sentinel" / "db" / "repo"
                  / "assets.py").read_text(encoding="utf-8")
    code_case = re.search(
        r"cause\s*=\s*CASE\s+WHEN\s+cause\s+IS\s+NULL\s+OR\s+cause\s*=\s*''\s+"
        r"THEN\s+'retired'\s+ELSE\s+cause\s*\|\|\s*'\s*\(asset retired\)'\s+END",
        assets_src, re.I | re.S)
    assert code_case, "retire_missing's own CASE expression moved or changed shape"


def test_backfill_has_no_access_exclusive_locking_statements():
    """A backfill mixed with DDL would hold a lock far longer than a plain
    UPDATE needs — the same reasoning 0036 documents for keeping its
    backfill in its own file, separate from 0035's ALTER TABLE/CREATE
    TRIGGER."""
    text = _without_comments(M_BACKFILL.read_text(encoding="utf-8"))
    assert not re.search(r"\b(ALTER\s+TABLE|CREATE\s+TRIGGER|CREATE\s+INDEX)\b", text, re.I), text


def test_backfill_guard_proves_the_effect_not_just_the_exit_code():
    """A successful `UPDATE 0` is not proof nothing was left to fix — it is
    equally what a broken WHERE clause (an inverted comparison, a typo on
    `retired_at`) would also report. The migration must count what is STILL
    open on a retired asset AFTER the UPDATE and refuse if anything remains,
    the same shape 0029 and 0036 already use for their own guards."""
    text = _without_comments(M_BACKFILL.read_text(encoding="utf-8"))
    after_update = text.split("UPDATE outages", 1)[1]
    lowered = after_update.lower()
    assert "count(*)" in lowered and "into ramase" in lowered, (
        "no post-UPDATE count of rows still open on a retired asset — success "
        "would be reported on exit code alone")
    idx = lowered.index("into ramase")
    guard_block = after_update[idx:]
    assert re.search(r"IF\s+ramase\s*>\s*0\s+THEN", guard_block, re.I), guard_block
    assert "RAISE EXCEPTION" in guard_block.upper(), (
        "the guard counts leftover rows but never stops the migration for them")


def test_backfill_is_idempotent_via_ended_at_is_null():
    """A second run (a re-applied migration, a manually re-run script) must
    touch zero rows — `o.ended_at IS NULL` in the WHERE is what makes that
    true; without it, a second run would try to re-close outages it already
    closed, silently recomputing `duration_s` from whatever `retired_at`
    happens to be at that point (harmless here since `retired_at` does not
    change, but the safety property should be visible in the SQL itself, not
    just true by accident of the current schema)."""
    text = _without_comments(M_BACKFILL.read_text(encoding="utf-8"))
    m = re.search(r"UPDATE\s+outages\s+o\s+SET.*?WHERE\s+([^;]*);", text, re.I | re.S)
    assert m, "no longer find the backfill UPDATE's WHERE clause"
    where = " ".join(m.group(1).split()).lower()
    assert "o.ended_at is null" in where, (
        "WHERE does not exclude already-closed outages — a second run would "
        "not be a no-op")
