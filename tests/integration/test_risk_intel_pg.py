"""Real Postgres runs the SQL of the risk pass the way a fake database cannot.

The unit tests of `risk.py`, `epss.py`, `redhat.py` and `osv.py` decide with
plain dicts. They cannot tell whether `0047_risk_intel.sql` applies, whether the
CHECK that ties colour to decision holds, whether `enrich` rewrites only what
changed (a BEFORE UPDATE trigger turns every rewrite into a re-shipment to the
external witness), whether the red-announcement claim is atomic, or whether the
columns that now travel to the witness still encode — `encode_value` refuses a
`float`, and a `real` column would have stopped the whole findings stream.

OPTIONAL, same convention as the other `*_pg.py` files: runs against
`SENTINEL_TEST_PG_DSN`, or against a disposable `postgres:16-alpine` when docker
answers, and is skipped — with the reason — otherwise. Migrations go through the
real runner.

Falsify (each turns a named test red):
  * `risk_score real` instead of `numeric(6,5)` in 0047 ->
    `test_every_column_the_shipper_sends_still_encodes`;
  * drop `AND risk_red_announced_at IS NULL` from the claim in
    `enrich._announce_red` -> `test_the_red_announcement_is_claimed_once_even_if_two_passes_race`;
  * drop the `_differs` guard in `enrich._run` -> `test_a_pass_that_changes_nothing_writes_nothing`.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import shutil
import socket
import subprocess
import time
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

asyncpg = pytest.importorskip("asyncpg", reason="asyncpg not installed")

from sentinel.config import Config  # noqa: E402
from sentinel.db.engine import Database  # noqa: E402
from sentinel.db.migrate import run_migrations  # noqa: E402
from sentinel.db.repo import findings as fx  # noqa: E402
from sentinel.intel import epss, mirror, redhat, vulnrichment  # noqa: E402
from sentinel.report import shipper  # noqa: E402
from sentinel.patch import planner  # noqa: E402
from sentinel.predict import exposure  # noqa: E402
from sentinel.scan import enrich, risk  # noqa: E402

WIDE_OPEN_DOS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
WIDE_OPEN_TOTAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LOW_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L"


def _docker_daemon_reachable() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=5, check=True)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _wait_until_reachable(dsn: str, timeout_s: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            conn = await asyncpg.connect(dsn, timeout=3)
        except (OSError, asyncpg.PostgresError):
            await asyncio.sleep(0.5)
            continue
        await conn.close()
        return True
    return False


@pytest.fixture(scope="module")
def pg_dsn():
    env_dsn = os.environ.get("SENTINEL_TEST_PG_DSN")
    if env_dsn:
        rc = run_migrations(dry_run=False, dsn=env_dsn)
        if rc != 0:
            pytest.skip(f"SENTINEL_TEST_PG_DSN set but migrations failed (rc={rc})")
        yield env_dsn
        return
    if not _docker_daemon_reachable():
        pytest.skip("neither SENTINEL_TEST_PG_DSN nor a reachable docker daemon is "
                    "available -- the real-SQL check of the risk pass did not run")
    port = _free_tcp_port()
    name = f"sentinel-test-risk-intel-pg-{port}"
    subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name,
         "-e", "POSTGRES_PASSWORD=test", "-e", "POSTGRES_DB=sentinel_test",
         "-p", f"127.0.0.1:{port}:5432", "postgres:16-alpine"],
        check=True, capture_output=True, timeout=30)
    dsn = f"postgresql://postgres:test@127.0.0.1:{port}/sentinel_test"
    try:
        if not asyncio.run(_wait_until_reachable(dsn)):
            pytest.skip("throwaway Postgres container did not become reachable in time")
        rc = run_migrations(dry_run=False, dsn=dsn)
        assert rc == 0, "migrations failed against the throwaway test container"
        yield dsn
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15)


def _cfg(*, intel: bool = False, announce: bool = True) -> Config:
    cfg = Config()
    cfg.intel.enabled = intel          # the pass must not reach the network here
    cfg.scan.announce_new = announce
    return cfg


def _run_async(pg_dsn, body):
    async def _wrapped() -> Any:
        db = Database(cfg=Config(), dsn=pg_dsn)
        await db.connect()
        try:
            await db.execute("DELETE FROM findings")
            for table in ("epss_scores", "vuln_intel", "intel_state", "kev_catalog",
                          "vulnrichment"):
                await db.execute(f"DELETE FROM {table}")
            # A fresh KEV mirror: without it every "not in KEV" is unknowable.
            await db.execute(
                "INSERT INTO kev_catalog (cve, due_date, updated_at) "
                "VALUES ('CVE-2026-9000', '2026-10-20', now())")
            return await body(db)
        finally:
            await db.close()
    return asyncio.run(_wrapped())


async def _finding(db: Database, key: str, *, scanner="trivy_image", ecosystem="npm",
                   cve="CVE-2026-0001", vector=WIDE_OPEN_DOS, cvss=7.5,
                   severity="high", status="open", package="pkg") -> int:
    ok = await fx.upsert_finding(db, {
        "finding_key": key, "scanner": scanner, "cve": cve, "severity": severity,
        "cvss": cvss, "cvss_vector": vector, "package": package, "ecosystem": ecosystem,
        "raw": {}})
    assert ok is True
    row_id = await db.fetchval("SELECT id FROM findings WHERE finding_key = $1", key)
    if status != "open":
        await db.execute("UPDATE findings SET status = $2 WHERE id = $1", row_id, status)
    return int(row_id)


async def _seed_epss(db: Database, cve: str, p: float, pct: float = 0.5,
                     days_old: int = 1) -> None:
    await db.execute(
        "INSERT INTO epss_scores (cve, epss, percentile, score_date) VALUES ($1, $2, $3, $4) "
        "ON CONFLICT (cve) DO UPDATE SET epss = EXCLUDED.epss, percentile = EXCLUDED.percentile, "
        "score_date = EXCLUDED.score_date",
        cve, Decimal(str(p)), Decimal(str(pct)),
        (datetime.now(timezone.utc) - timedelta(days=days_old)).date())


async def _publish(db: Database, cve: str, exploitation: str | None = "none",
                   automatable: str | None = None, technical_impact: str | None = None,
                   at: datetime | None = None) -> None:
    """What CISA published for `cve`, written through the real `store` (so the
    real SQL, CHECKs included, is what the pass reads back). The default is the
    everyday case: looked at, no exploitation seen."""
    published = exploitation or automatable or technical_impact
    await vulnrichment.store(db, cve, mirror.Outcome("found", {
        "exploitation": exploitation, "automatable": automatable,
        "technical_impact": technical_impact,
        "ssvc_at": (at or datetime(2026, 9, 1, tzinfo=timezone.utc)) if published else None,
        "ssvc_version": "2.0.3" if published else None}))


async def _row(db: Database, row_id: int):
    return await db.fetchrow("SELECT * FROM findings WHERE id = $1", row_id)


# ---------------------------------------------------------------------------
async def _tied_band(db) -> dict[str, int]:
    """Four open findings in ONE priority band (0) with risk_score 0.2 / NULL /
    0.8 / 0.5, all KEV with a fix on the host's own ecosystem so both consumers
    select them. Inserted so that neither physical order nor id order is the
    right answer."""
    ids = {}
    for key, score in (("low", Decimal("0.2")), ("unscored", None),
                       ("high", Decimal("0.8")), ("mid", Decimal("0.5"))):
        rid = await _finding(db, key, ecosystem=planner.OS_PACKAGE_ECOSYSTEM["rhel"],
                             cve=f"CVE-2026-{len(ids) + 100}")
        await db.execute(
            "UPDATE findings SET priority = 0, risk_score = $2, kev = true, "
            "fixed_version = '9.9' WHERE id = $1", rid, score)
        ids[key] = rid
    return ids


def test_both_consumers_order_a_priority_tie_by_risk_score_with_unscored_last(
        pg_dsn, monkeypatch):
    """Postgres sorts NULL FIRST on `DESC`, SQLite sorts it last, so only a real
    Postgres can show what `NULLS LAST` buys. Without it, a finding nobody has
    scored (a fresh row, a stream that has not been assessed yet) is placed
    ahead of every scored one, and it takes the first of the KEV planner's three
    model-call slots and the head of the exposure crossing's 500 rows."""
    chosen: list[int] = []

    async def _generate(db, cfg, api_key, finding_id, **kw):
        chosen.append(finding_id)
        return None, "stub"

    monkeypatch.setattr(planner, "generate", _generate)

    async def body(db):
        ids = await _tied_band(db)
        cfg = Config()
        cfg.platform.family = "rhel"
        await planner.generate_for_kev(db, cfg=cfg, api_key="sk-test", limit=3)

        seen: list[int] = []

        class _Spy:
            async def fetch(self, sql, *a):
                rows = await db.fetch(sql, *a)
                if "FROM findings" in sql and not seen:
                    seen.extend(int(r["id"]) for r in rows)
                return rows

        await exposure.detect(_Spy())
        return ids, seen

    ids, seen = _run_async(pg_dsn, body)
    assert chosen == [ids["high"], ids["mid"], ids["low"]], (
        f"the KEV planner took {chosen}; the unscored finding {ids['unscored']} "
        "must not outrank the scored ones")
    assert seen == [ids["high"], ids["mid"], ids["low"], ids["unscored"]], (
        f"exposure.detect read its findings in the order {seen}")


# ---------------------------------------------------------------------------
def test_the_migration_applies_and_the_colour_decision_constraint_holds(pg_dsn):
    """A colour with no matching decision is a row that disagrees with itself;
    the CHECK refuses it at the door instead of letting two screens disagree."""
    async def body(db):
        rid = await _finding(db, "k1")
        for color, decision in [("red", "attend"), ("grey", "act"), ("green", None),
                                ("amber", "track"), ("purple", None)]:
            with pytest.raises(asyncpg.CheckViolationError):
                await db.execute(
                    "UPDATE findings SET risk_color = $2, risk_decision = $3 WHERE id = $1",
                    rid, color, decision)
        for color, decision in [("red", "act"), ("amber", "attend"), ("green", "track"),
                                ("green", "track_star"), ("grey", None)]:
            await db.execute("UPDATE findings SET risk_color = $2, risk_decision = $3 "
                             "WHERE id = $1", rid, color, decision)
    _run_async(pg_dsn, body)


def test_a_new_row_starts_grey_with_the_unassessed_priority(pg_dsn):
    """"Never evaluated" is grey, not green; and the priority it carries is the
    grey band's, so it sorts above every evaluated green."""
    async def body(db):
        rid = await _finding(db, "k1")
        row = await _row(db, rid)
        assert (row["risk_color"], row["risk_decision"], row["risk_changed_at"]) == (
            "grey", None, None)
        assert row["priority"] == risk.UNASSESSED_PRIORITY
    _run_async(pg_dsn, body)


def test_a_pass_writes_colours_priorities_and_the_named_source(pg_dsn):
    async def body(db):
        hot = await _finding(db, "hot", cve="CVE-2026-0001", vector=WIDE_OPEN_TOTAL, cvss=9.8)
        calm = await _finding(db, "calm", cve="CVE-2026-0002")
        kev = await _finding(db, "kev", cve="CVE-2026-9000",
                             vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", cvss=7.0)
        nodata = await _finding(db, "nodata", cve="CVE-2026-0003")
        await _seed_epss(db, "CVE-2026-0001", 0.95, 0.999)
        await _seed_epss(db, "CVE-2026-0002", 0.004, 0.4)
        await _seed_epss(db, "CVE-2026-9000", 0.006, 0.5)
        await _publish(db, "CVE-2026-0001", "active")
        await _publish(db, "CVE-2026-0002", "none")
        await _publish(db, "CVE-2026-9000", "none")      # KEV outranks a stale `none`
        out = await enrich.run(db, _cfg())
        assert out["status"] == "completed" and out["findings"] == 4
        r = {name: await _row(db, rid) for name, rid in
             (("hot", hot), ("calm", calm), ("kev", kev), ("nodata", nodata))}
        assert (r["hot"]["risk_color"], r["hot"]["risk_decision"]) == ("red", "act")
        assert (r["calm"]["risk_color"], r["calm"]["risk_decision"]) == ("green", "track")
        assert (r["kev"]["risk_color"], r["kev"]["risk_decision"]) == ("amber", "attend")
        assert r["kev"]["kev"] is True and r["kev"]["kev_due_date"] == date(2026, 10, 20)
        assert (r["nodata"]["risk_color"], r["nodata"]["risk_decision"]) == ("grey", None)
        assert r["nodata"]["risk_score"] is None
        assert json.loads(r["nodata"]["risk"])["missing"] == ["vulnrichment"]
        # grey above green, amber above grey, red above amber
        pr = {k: v["priority"] for k, v in r.items()}
        assert pr["hot"] > pr["kev"] > pr["nodata"] > pr["calm"]
        risk_json = json.loads(r["hot"]["risk"])
        assert risk_json["cvss"]["source"] == "trivy"
        assert risk_json["points"]["exploitation"] == {
            "value": "active", "basis": "vulnrichment", "as_of": "2026-09-01"}
        assert json.loads(r["kev"]["risk"])["points"]["exploitation"] == {
            "value": "active", "basis": "kev"}
        assert r["hot"]["epss"] == Decimal("0.9500")
        assert r["hot"]["epss_percentile"] == Decimal("0.9990")
    _run_async(pg_dsn, body)


def test_a_pass_that_changes_nothing_writes_nothing(pg_dsn):
    """A BEFORE UPDATE trigger bumps `updated_at` on ANY update, and the
    shipper copies rows by `updated_at`. An hourly pass that rewrote unchanged
    rows would re-ship every open finding to the external witness every hour."""
    async def body(db):
        rid = await _finding(db, "k1")
        await _seed_epss(db, "CVE-2026-0001", 0.004)
        await _publish(db, "CVE-2026-0001")
        await enrich.run(db, _cfg())
        before = await _row(db, rid)
        out = await enrich.run(db, _cfg())
        after = await _row(db, rid)
        assert out["changed"] == 0
        assert after["updated_at"] == before["updated_at"]
        assert after["risk_changed_at"] == before["risk_changed_at"]
    _run_async(pg_dsn, body)


def test_new_data_moves_the_row_and_only_that_row(pg_dsn):
    async def body(db):
        a = await _finding(db, "a", cve="CVE-2026-0001")
        b = await _finding(db, "b", cve="CVE-2026-0002")
        await _publish(db, "CVE-2026-0001")
        await _publish(db, "CVE-2026-0002")
        await enrich.run(db, _cfg())
        b_before = await _row(db, b)
        await _publish(db, "CVE-2026-0001", "active")        # CISA re-evaluated one CVE
        out = await enrich.run(db, _cfg())
        assert out["changed"] == 1
        assert (await _row(db, a))["risk_color"] == "amber"
        assert (await _row(db, b))["updated_at"] == b_before["updated_at"]
    _run_async(pg_dsn, body)


def test_resolved_and_decided_findings_are_not_evaluated(pg_dsn):
    """`resolved`, `accepted_risk` and `false_positive` are closed or decided by
    a person; a colour on them is noise, and the rewrite would be a reship."""
    async def body(db):
        ids = [await _finding(db, f"k{i}", status=s, cve=f"CVE-2026-010{i}")
               for i, s in enumerate(("resolved", "accepted_risk", "false_positive", "deferred"))]
        out = await enrich.run(db, _cfg())
        assert out["findings"] == 1       # only `deferred` is still someone's problem
        assert (await _row(db, ids[3]))["risk_changed_at"] is not None
        for closed in ids[:3]:
            assert (await _row(db, closed))["risk_changed_at"] is None
    _run_async(pg_dsn, body)


def test_a_pending_reboot_lowers_urgency_one_step_and_the_pass_records_it(pg_dsn):
    async def body(db):
        rid = await _finding(db, "k1", scanner="dnf", ecosystem="rpm", vector=WIDE_OPEN_TOTAL, cvss=9.8)
        await db.execute(
            "UPDATE findings SET raw = $2::jsonb WHERE id = $1", rid,
            json.dumps({"fix_state": {"state": "pending_reboot"}}))
        await _publish(db, "CVE-2026-0001", "active")
        await enrich.run(db, _cfg())
        row = await _row(db, rid)
        data = json.loads(row["risk"])
        assert (row["risk_decision"], data["decision_before_reboot"]) == ("attend", "act")
    _run_async(pg_dsn, body)


def test_a_scan_upsert_afterwards_does_not_erase_the_assessment(pg_dsn):
    """The nightly upsert rewrites the finding from the scanner's output, which
    knows nothing of EPSS, priority or the vendor score. If it overwrote them,
    the page would flicker back to "no data" every night until the next pass."""
    async def body(db):
        rid = await _finding(db, "k1", scanner="dnf", ecosystem="rpm", cve="CVE-2026-0001",
                             vector=None, cvss=None, severity="medium")
        await db.execute(
            "INSERT INTO vuln_intel (vuln_id, source, status, cvss_score, cvss_vector, "
            "cvss_version, severity) VALUES ('CVE-2026-0001', 'redhat', 'found', 3.1, $1, '3.1', 'Low')",
            LOW_VECTOR)
        await _seed_epss(db, "CVE-2026-0001", 0.0045, 0.3682)
        await _publish(db, "CVE-2026-0001")
        await enrich.run(db, _cfg())
        before = await _row(db, rid)
        assert before["cvss"] == Decimal("3.1") and before["cvss_vector"] == LOW_VECTOR
        assert json.loads(before["risk"])["cvss"]["source"] == "redhat"

        await fx.upsert_finding(db, {            # the scanner again, with nothing new
            "finding_key": "k1", "scanner": "dnf", "cve": "CVE-2026-0001",
            "severity": "medium", "ecosystem": "rpm", "package": "pkg", "raw": {}})
        after = await _row(db, rid)
        for column in ("cvss", "cvss_vector", "epss", "epss_percentile", "priority",
                       "risk_color", "risk_decision", "risk_score", "risk"):
            assert after[column] == before[column], column
        # and the next pass reaches the same verdict without a rewrite
        assert (await enrich.run(db, _cfg()))["changed"] == 0
    _run_async(pg_dsn, body)


def test_the_scanners_own_cvss_is_never_overwritten_by_the_pass(pg_dsn):
    async def body(db):
        rid = await _finding(db, "k1", vector=WIDE_OPEN_DOS, cvss=7.5)
        await db.execute(
            "INSERT INTO vuln_intel (vuln_id, source, status, cvss_score, cvss_vector, "
            "cvss_version) VALUES ('CVE-2026-0001', 'osv', 'found', 1.0, $1, '3.1')", LOW_VECTOR)
        await _publish(db, "CVE-2026-0001")
        await enrich.run(db, _cfg())
        row = await _row(db, rid)
        assert row["cvss"] == Decimal("7.5") and row["cvss_vector"] == WIDE_OPEN_DOS
        assert json.loads(row["risk"])["cvss"]["source"] == "trivy"
    _run_async(pg_dsn, body)


def test_a_vendor_preferred_over_the_scanner_leaves_the_scanners_column_alone(pg_dsn):
    """Red Hat is preferred for rpm, so the DECISION uses its 5.0; but the scanner's
    own 9.9 in `findings.cvss` is evidence, not ours to overwrite — the nightly
    upsert would put it back and the page would flip twice a day."""
    async def body(db):
        rid = await _finding(db, "k1", scanner="trivy_image", ecosystem="rpm",
                             vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cvss=9.9)
        await db.execute(
            "INSERT INTO vuln_intel (vuln_id, source, status, cvss_score, cvss_vector, cvss_version) "
            "VALUES ('CVE-2026-0001', 'redhat', 'found', 5.0, $1, '3.1')", LOW_VECTOR)
        await _publish(db, "CVE-2026-0001")
        await enrich.run(db, _cfg())
        row = await _row(db, rid)
        assert json.loads(row["risk"])["cvss"]["source"] == "redhat"
        assert row["cvss"] == Decimal("9.9"), "the scanner's own score was overwritten"
        assert row["cvss_vector"].startswith("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C")
    _run_async(pg_dsn, body)


# --- the red announcement ------------------------------------------------------
async def _make_assessed_then_hot(db: Database, key: str = "k1") -> int:
    rid = await _finding(db, key, vector=WIDE_OPEN_TOTAL, cvss=9.8)
    await _publish(db, "CVE-2026-0001")
    await enrich.run(db, _cfg())                 # baseline: green
    await _publish(db, "CVE-2026-0001", "active")  # CISA now sees exploitation
    return rid


def test_an_upgrade_into_red_is_announced_once(pg_dsn):
    """The brief: announce only upgrades into red, and once. A published value
    that flips back and forth must not reopen the channel."""
    async def body(db):
        rid = await _make_assessed_then_hot(db)
        sent: list[list[dict]] = []

        async def announce(items):
            sent.append(items)
            return 1
        out = await enrich.run(db, _cfg(), announce_fn=announce)
        assert out["announced_red"] == 1 and len(sent) == 1
        assert [i["id"] for i in sent[0]] == [rid]
        # it dips and rises again: not announced a second time
        await _publish(db, "CVE-2026-0001", "none")
        await enrich.run(db, _cfg(), announce_fn=announce)
        await _publish(db, "CVE-2026-0001", "active")
        await enrich.run(db, _cfg(), announce_fn=announce)
        assert len(sent) == 1
    _run_async(pg_dsn, body)


def test_first_assessment_is_a_baseline_not_an_announcement(pg_dsn):
    """After a deploy every open finding is assessed for the first time. Four
    messages about old facts is the tap the operator asked not to open."""
    async def body(db):
        await _finding(db, "k1", vector=WIDE_OPEN_TOTAL, cvss=9.8)
        await _publish(db, "CVE-2026-0001", "active")
        calls: list[Any] = []

        async def announce(items):
            calls.append(items)
            return 1
        out = await enrich.run(db, _cfg(), announce_fn=announce)
        assert calls == [] and out["announced_red"] == 0
        row = await db.fetchrow("SELECT risk_color, risk_red_announced_at FROM findings")
        assert row["risk_color"] == "red" and row["risk_red_announced_at"] is not None
    _run_async(pg_dsn, body)


def test_a_finding_new_in_this_scan_is_left_to_the_new_findings_message(pg_dsn):
    """The race that makes `new_keys` necessary: the hourly maintenance pass saw the
    row between the scan's upsert and the scan's own pass, assessed it GREY (CISA
    not asked yet), and the data arrived afterwards. The row is then "previously
    assessed", so only `new_keys` stops a "became red" next to the "new
    vulnerabilities" message that already lists it."""
    async def body(db):
        await _finding(db, "k1", vector=WIDE_OPEN_TOTAL, cvss=9.8)
        await enrich.run(db, _cfg())                  # assessed early: grey, CISA not asked yet
        assert (await db.fetchval("SELECT risk_color FROM findings")) == "grey"
        await _publish(db, "CVE-2026-0001", "active")  # the data arrives
        calls: list[Any] = []

        async def announce(items):
            calls.append(items)
            return 1
        out = await enrich.run(db, _cfg(), new_keys={"k1"}, announce_fn=announce)
        assert calls == [] and out["colors"].get("red") == 1
        # the same transition on a row that is NOT new this scan IS announced
        await db.execute("UPDATE findings SET risk_red_announced_at = NULL, risk_color = 'grey', "
                         "risk_decision = NULL")
        await enrich.run(db, _cfg(), announce_fn=announce)
        assert len(calls) == 1
    _run_async(pg_dsn, body)


def test_a_delivery_that_reaches_nobody_is_retried_not_forgotten(pg_dsn):
    async def body(db):
        rid = await _make_assessed_then_hot(db)

        async def nobody(items):
            return 0
        assert (await enrich.run(db, _cfg(), announce_fn=nobody))["announced_red"] == 0
        assert (await _row(db, rid))["risk_red_announced_at"] is None   # claim released
        got: list[Any] = []

        async def somebody(items):
            got.append(items)
            return 1
        assert (await enrich.run(db, _cfg(), announce_fn=somebody))["announced_red"] == 1
        assert len(got) == 1
    _run_async(pg_dsn, body)


def test_a_failing_announcement_never_breaks_the_pass(pg_dsn):
    async def body(db):
        await _make_assessed_then_hot(db)

        async def boom(items):
            raise RuntimeError("telegram is down")
        out = await enrich.run(db, _cfg(), announce_fn=boom)
        assert out["status"] == "completed" and out["announced_red"] == 0
    _run_async(pg_dsn, body)


def test_with_the_channel_switched_off_rows_are_marked_without_a_message(pg_dsn):
    """`scan.announce_new: false` is the operator's switch; flipping it back on
    later must not deliver a backlog of old "became red"."""
    async def body(db):
        rid = await _make_assessed_then_hot(db)
        calls: list[Any] = []

        async def announce(items):
            calls.append(items)
            return 1
        await enrich.run(db, _cfg(announce=False), announce_fn=announce)
        assert calls == []
        assert (await _row(db, rid))["risk_red_announced_at"] is not None
    _run_async(pg_dsn, body)


def test_the_red_announcement_is_claimed_once_even_if_two_passes_race(pg_dsn):
    """The scan and the hourly maintenance pass both run this. The claim is one
    UPDATE ... WHERE announced IS NULL RETURNING, so exactly one of two
    concurrent passes gets the row."""
    async def body(db):
        await _make_assessed_then_hot(db)
        sent: list[list[dict]] = []

        async def announce(items):
            await asyncio.sleep(0.05)
            sent.append(items)
            return 1
        await asyncio.gather(enrich.run(db, _cfg(), announce_fn=announce),
                             enrich.run(db, _cfg(), announce_fn=announce))
        assert sum(len(s) for s in sent) == 1
    _run_async(pg_dsn, body)


# --- what travels to the external witness ------------------------------------
def test_every_column_the_shipper_sends_still_encodes(pg_dsn):
    """`encode_value` refuses `float` (a float cannot be signed identically at
    both ends), and a refused column stops the WHOLE findings stream — silently,
    as a growing `ship:lag`. The new columns must arrive as Decimal or text."""
    async def body(db):
        rid = await _finding(db, "k1", vector=WIDE_OPEN_TOTAL, cvss=9.8)
        await _seed_epss(db, "CVE-2026-0001", 0.97, 0.99)
        await _publish(db, "CVE-2026-0001", "active")
        await enrich.run(db, _cfg())
        cols = ", ".join(shipper.select_columns(shipper.FINDING_STREAM))
        record = await db.fetchrow(f"SELECT {cols} FROM findings WHERE id = $1", rid)
        row, _ = shipper.encode_row(shipper.FINDING_STREAM, record, rid, 100)
        assert row["risk_color"] == "red" and row["risk_decision"] == "act"
        assert isinstance(row["risk_score"], str) and isinstance(row["epss_percentile"], str)
        assert isinstance(row["risk"], str) and json.loads(row["risk"])["decision"] == "act"
    _run_async(pg_dsn, body)


# --- the mirrors' own SQL --------------------------------------------------------
def _gz(rows: dict[str, tuple[str, str]], filler: int = 5) -> bytes:
    lines = ["#model_version:v2026.06.15,score_date:2026-10-01T12:00:22Z", "cve,epss,percentile"]
    lines += [f"{c},{e},{p}" for c, (e, p) in rows.items()]
    lines += [f"CVE-2000-{i:05d},0.00100,0.10000" for i in range(filler)]
    return gzip.compress(("\n".join(lines) + "\n").encode())


def test_epss_refresh_writes_known_and_absent_rows_and_the_state(pg_dsn, monkeypatch):
    monkeypatch.setattr(epss, "MIN_ROWS", 3)

    async def body(db):
        blob = _gz({"CVE-2024-6501": ("0.00450", "0.36820")})
        client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, content=blob)), follow_redirects=True)
        out = await epss.refresh(db, {"CVE-2024-6501", "CVE-2099-0001"}, http=client)
        assert out["status"] == "updated"
        got = await epss.load(db, {"CVE-2024-6501", "CVE-2099-0001"})
        assert got["CVE-2024-6501"].epss == pytest.approx(0.0045)
        assert got["CVE-2099-0001"].epss is None and got["CVE-2099-0001"].score_date == date(2026, 10, 1)
        st = await mirror.state(db, "epss")
        assert st["last_ok_at"] is not None and st["last_error"] is None
        again = await epss.refresh(db, {"CVE-2024-6501", "CVE-2099-0001"}, http=client)
        assert again["status"] == "fresh"
    _run_async(pg_dsn, body)


def test_a_failed_refresh_keeps_the_last_success_and_records_the_error(pg_dsn):
    async def body(db):
        await mirror.record(db, "epss", ok=True)
        ok_at = (await mirror.state(db, "epss"))["last_ok_at"]
        await mirror.record(db, "epss", ok=False, error="HTTP 503")
        st = await mirror.state(db, "epss")
        assert st["last_ok_at"] == ok_at and st["last_error"] == "HTTP 503"
        await mirror.record(db, "epss", ok=True)
        assert (await mirror.state(db, "epss"))["last_error"] is None
    _run_async(pg_dsn, body)


def test_vendor_rows_round_trip_and_due_follows_age(pg_dsn):
    async def body(db):
        found = mirror.Outcome("found", {"cvss_score": 3.1, "cvss_vector": LOW_VECTOR,
                                         "cvss_version": "3.1", "severity": "Low",
                                         "justification": "very unlikely", "aliases": [],
                                         "advisories": ["RHSA-2024:9317"]})
        await mirror.store_vuln(db, "CVE-2024-6501", "redhat", found)
        await mirror.store_vuln(db, "CVE-2026-0002", "redhat", mirror.Outcome("not_found", {}))
        loaded = await redhat.load(db, {"CVE-2024-6501", "CVE-2026-0002"})
        assert loaded["CVE-2024-6501"].score == 3.1 and loaded["CVE-2024-6501"].advisories == ("RHSA-2024:9317",)
        assert loaded["CVE-2026-0002"].status == "not_found"
        ids = {"CVE-2024-6501", "CVE-2026-0002", "CVE-2026-0003"}
        assert await mirror.due(db, "redhat", ids, found_days=7, unrated_days=1,
                                not_found_days=7) == ["CVE-2026-0003"]
        await db.execute("UPDATE vuln_intel SET fetched_at = now() - interval '8 days'")
        assert await mirror.due(db, "redhat", ids, found_days=7, unrated_days=1,
                                not_found_days=7) == ids_sorted(ids)
        with pytest.raises(asyncpg.CheckViolationError):      # not_found cannot carry a score
            await db.execute(
                "INSERT INTO vuln_intel (vuln_id, source, status, cvss_score) "
                "VALUES ('CVE-2026-0009', 'osv', 'not_found', 5.0)")
    _run_async(pg_dsn, body)


def ids_sorted(ids: set[str]) -> list[str]:
    return sorted(ids)


# --- every reader of the colour, on real SQL ---------------------------------------
async def _colored(db: Database, key: str, color: str, decision: str | None, *,
                   priority: int, score: Decimal | None = None, status: str = "open",
                   kev: bool = False, **kw) -> int:
    rid = await _finding(db, key, status=status, **kw)
    await db.execute(
        "UPDATE findings SET risk_color = $2, risk_decision = $3, priority = $4, "
        "risk_score = $5, kev = $6 WHERE id = $1", rid, color, decision, priority, score, kev)
    return rid


def test_list_open_orders_by_band_then_score_and_counts_by_colour(pg_dsn):
    """The order the operator reads: red, amber, grey, green; inside a band the
    probability x impact number. `priority` alone has 20 steps per band, so
    hundreds of greens would otherwise sort by severity, i.e. by CVSS."""
    async def body(db):
        # The HIGHER score is inserted first: without `risk_score` in the ORDER BY the
        # tie falls to `last_seen DESC`, which would put the lower score on top.
        await _colored(db, "g-high", "green", "track", priority=3, score=Decimal("0.300"), cve="CVE-2026-0011")
        await _colored(db, "g-low", "green", "track", priority=3, score=Decimal("0.001"), cve="CVE-2026-0010")
        await _colored(db, "grey", "grey", None, priority=45, cve="CVE-2026-0012")
        await _colored(db, "amber", "amber", "attend", priority=70, score=Decimal("0.5"), cve="CVE-2026-0013")
        await _colored(db, "red", "red", "act", priority=95, score=Decimal("0.9"), cve="CVE-2026-0014")
        await _colored(db, "closed", "red", "act", priority=99, status="resolved", cve="CVE-2026-0015")
        rows = await fx.list_open(db)
        assert [r["cve"] for r in rows] == [
            "CVE-2026-0014", "CVE-2026-0013", "CVE-2026-0012", "CVE-2026-0011", "CVE-2026-0010"]
        counts = await fx.risk_counts(db)
        assert counts == {"red": 1, "amber": 1, "grey": 1, "green": 2, "total": 5}
        await db.execute("UPDATE findings SET status = 'resolved' WHERE risk_color <> 'red'")
        assert await fx.risk_counts(db) == {"red": 1, "amber": 0, "grey": 0, "green": 0, "total": 1}, (
            "a colour with no rows must still be in the answer, with zero")
        await db.execute("UPDATE findings SET status = 'open' WHERE risk_color <> 'red' "
                         "AND finding_key <> 'closed'")
        only = await fx.list_open(db, colors=["grey"])
        assert [r["cve"] for r in only] == ["CVE-2026-0012"]
        assert await fx.list_open(db, colors=[]) == []        # [] means none, not all
        assert (await fx.open_counts(db, colors=["green"]))["total"] == 2
    _run_async(pg_dsn, body)


def test_the_dashboard_the_insight_and_the_report_count_the_colours(pg_dsn):
    from sentinel.analytics import aggregate, insights, reports

    async def body(db):
        await _colored(db, "r", "red", "act", priority=95, cve="CVE-2026-0021")
        await _colored(db, "a1", "amber", "attend", priority=70, cve="CVE-2026-0022")
        await _colored(db, "a2", "amber", "attend", priority=70, cve="CVE-2026-0023")
        await _colored(db, "gy", "grey", None, priority=45, cve="CVE-2026-0024")
        await _colored(db, "gn", "green", "track", priority=3, cve="CVE-2026-0025")
        await _colored(db, "gn2", "green", "track", priority=3, cve="CVE-2026-0027")
        await _colored(db, "gn3", "green", "track", priority=3, cve="CVE-2026-0028")
        await _colored(db, "closed", "red", "act", priority=99, status="resolved", cve="CVE-2026-0026")
        kpi = await aggregate.kpis(db)
        assert (kpi["vuln_deschise"], kpi["vuln_rosii"], kpi["vuln_galbene"], kpi["vuln_gri"]) == (7, 1, 2, 1)
        found = await insights._vuln_insight(db)
        assert found[0].level == "critical" and found[0].evidence["rosii"] == 1
        assert found[0].evidence["fara_date"] == 1
        rep = await reports.overview(db, hours=24, rollup_from=None, installed_from=None)
        f = rep["findings"]
        assert (f["open"], f["red"], f["amber"], f["grey"]) == (7, 1, 2, 1)
    _run_async(pg_dsn, body)


def test_the_vendors_justification_is_read_on_demand_and_only_for_rpm(pg_dsn):
    async def body(db):
        await db.execute(
            "INSERT INTO vuln_intel (vuln_id, source, status, justification) "
            "VALUES ('CVE-2024-6501', 'redhat', 'found', 'very unlikely to have DEBUG logs on')")
        rpm = {"cve": "CVE-2024-6501", "ecosystem": "rpm"}
        assert await fx.vendor_justification(db, rpm) == ("very unlikely to have DEBUG logs on", "Red Hat")
        assert await fx.vendor_justification(db, {**rpm, "ecosystem": "npm"}) is None
        assert await fx.vendor_justification(db, {"cve": None, "ecosystem": "rpm"}) is None
        assert await fx.vendor_justification(db, {"cve": "CVE-2099-1", "ecosystem": "rpm"}) is None
    _run_async(pg_dsn, body)


def test_resolved_findings_keep_their_legacy_priority_and_nothing_reorders_them(pg_dsn):
    """The migration lifts only unresolved rows to the grey band. Rewriting ~6,700
    resolved rows would bump `updated_at` on all of them and re-ship every one to
    the external witness for a number nobody sorts by."""
    async def body(db):
        rid = await _finding(db, "old", status="resolved")
        await db.execute("UPDATE findings SET priority = 83 WHERE id = $1", rid)
        await enrich.run(db, _cfg())
        row = await _row(db, rid)
        assert row["priority"] == 83 and row["risk_changed_at"] is None
    _run_async(pg_dsn, body)


# --- the migration over a database that already has findings --------------------------
def test_the_migration_lifts_unresolved_rows_to_the_grey_band_and_leaves_closed_ones(monkeypatch):
    """Production has ~7,500 findings when 0047 lands. The unresolved ones must not
    keep a priority from the old formula next to a "no data" colour; the closed ones
    must NOT be rewritten (a BEFORE UPDATE trigger would re-ship ~6,700 rows)."""
    from sentinel.db import migrate

    if os.environ.get("SENTINEL_TEST_PG_DSN") or not _docker_daemon_reachable():
        pytest.skip("needs its own throwaway Postgres (a database frozen at version 46)")
    port = _free_tcp_port()
    name = f"sentinel-test-risk-mig-pg-{port}"
    subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_PASSWORD=test",
         "-e", "POSTGRES_DB=sentinel_test", "-p", f"127.0.0.1:{port}:5432", "postgres:16-alpine"],
        check=True, capture_output=True, timeout=30)
    dsn = f"postgresql://postgres:test@127.0.0.1:{port}/sentinel_test"
    try:
        assert asyncio.run(_wait_until_reachable(dsn))
        real_discover = migrate.discover
        monkeypatch.setattr(migrate, "discover",
                            lambda: [m for m in real_discover() if m.version <= 46])
        assert run_migrations(dry_run=False, dsn=dsn) == 0
        monkeypatch.setattr(migrate, "discover", real_discover)

        async def seed() -> dict:
            conn = await asyncpg.connect(dsn)
            try:
                for key, status, prio in (("open", "open", 83), ("deferred", "deferred", 70),
                                          ("patching", "patching", 90), ("resolved", "resolved", 83),
                                          ("accepted", "accepted_risk", 90)):
                    await conn.execute(
                        "INSERT INTO findings (finding_key, scanner, severity, status, priority) "
                        "VALUES ($1, 'dnf', 'high', $2, $3)", key, status, prio)
                return {r["finding_key"]: r["updated_at"]
                        for r in await conn.fetch("SELECT finding_key, updated_at FROM findings")}
            finally:
                await conn.close()

        before = asyncio.run(seed())
        assert run_migrations(dry_run=False, dsn=dsn) == 0       # applies 0047

        async def check() -> None:
            conn = await asyncpg.connect(dsn)
            try:
                rows = {r["finding_key"]: r for r in await conn.fetch(
                    "SELECT finding_key, priority, risk_color, risk_decision, updated_at FROM findings")}
                for key in ("open", "deferred", "patching"):
                    assert rows[key]["priority"] == risk.UNASSESSED_PRIORITY == 40, key
                for key, legacy in (("resolved", 83), ("accepted", 90)):
                    assert rows[key]["priority"] == legacy, key
                    assert rows[key]["updated_at"] == before[key], (
                        f"{key} a fost rescris: s-ar reexpedia catre martorul extern")
                assert all(r["risk_color"] == "grey" and r["risk_decision"] is None
                           for r in rows.values())
                idx = await conn.fetchval(
                    "SELECT count(*) FROM pg_indexes WHERE indexname = 'findings_open_risk_idx'")
                assert idx == 1
            finally:
                await conn.close()
        asyncio.run(check())
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15)


def test_a_stale_kev_mirror_makes_not_in_kev_unknowable_in_the_real_pass(pg_dsn):
    """With a month-old KEV table "not in KEV" is a guess. The pass must say grey
    with the reason, not paint the row from the old table."""
    async def body(db):
        rid = await _finding(db, "k1")
        await _publish(db, "CVE-2026-0001")
        await db.execute("UPDATE kev_catalog SET updated_at = now() - interval '30 days'")
        await enrich.run(db, _cfg())
        row = await _row(db, rid)
        assert row["risk_color"] == "grey"
        assert "kev_mirror" in json.loads(row["risk"])["missing"]
        await db.execute("DELETE FROM kev_catalog")
        await enrich.run(db, _cfg())
        assert (await _row(db, rid))["risk_color"] == "grey"          # an empty mirror too
        await db.execute("INSERT INTO kev_catalog (cve, updated_at) VALUES ('CVE-2026-9999', now())")
        await enrich.run(db, _cfg())
        assert (await _row(db, rid))["risk_color"] == "green"         # fresh again
    _run_async(pg_dsn, body)


def test_an_advisory_without_a_cve_is_decided_through_its_osv_alias_end_to_end(pg_dsn):
    """10 of the 17 open GHSA advisories have no alias (grey, correctly); 7 have one
    and are evaluated through it — EPSS and KEV are looked up for the alias."""
    async def body(db):
        rid = await _finding(db, "ghsa", cve=None, vector=WIDE_OPEN_TOTAL, cvss=9.8)
        await db.execute("UPDATE findings SET advisory_id = 'GHSA-2x7j-588g-ccc2' WHERE id = $1", rid)
        await db.execute(
            "INSERT INTO vuln_intel (vuln_id, source, status, aliases) "
            "VALUES ('GHSA-2x7j-588g-ccc2', 'osv', 'found', ARRAY['CVE-2026-9000'])")
        await _publish(db, "CVE-2026-9000")
        await enrich.run(db, _cfg())
        row = await _row(db, rid)
        data = json.loads(row["risk"])
        assert data["cve"] == "CVE-2026-9000" and data["cve_via"] == "GHSA-2x7j-588g-ccc2"
        assert row["kev"] is True and row["risk_color"] == "red"        # the alias IS in KEV: active + automatable + total
        # an advisory with no alias at all stays grey
        rid2 = await _finding(db, "ghsa2", cve=None, vector=WIDE_OPEN_TOTAL, cvss=9.8)
        await db.execute("UPDATE findings SET advisory_id = 'GHSA-aaaa-bbbb-cccc' WHERE id = $1", rid2)
        await enrich.run(db, _cfg())
        assert (await _row(db, rid2))["risk_color"] == "grey"
    _run_async(pg_dsn, body)


def test_epss_older_than_a_week_no_longer_greys_the_row_but_drops_the_ordering_number(pg_dsn):
    """EPSS is not a decision point any more: an old value cannot leave a row
    undecided. It is also not used as a probability, so `risk_score` goes NULL and
    the row keeps its colour."""
    async def body(db):
        rid = await _finding(db, "k1")
        await _publish(db, "CVE-2026-0001")
        await _seed_epss(db, "CVE-2026-0001", 0.004, days_old=2)
        await enrich.run(db, _cfg())
        row = await _row(db, rid)
        assert row["risk_color"] == "green" and row["risk_score"] is not None
        await _seed_epss(db, "CVE-2026-0001", 0.004, days_old=epss.MAX_AGE_DAYS + 3)
        await enrich.run(db, _cfg())
        row = await _row(db, rid)
        assert row["risk_color"] == "green" and row["risk_score"] is None
        assert json.loads(row["risk"])["epss"]["stale"] is True
    _run_async(pg_dsn, body)


# --- CISA Vulnrichment: the real SQL ----------------------------------------------
def test_the_vulnrichment_table_refuses_what_is_not_the_coordinator_vocabulary(pg_dsn):
    """The CHECKs are the last line behind `parse`: a word outside CISA's tree, a
    `not_found` row that carries points, or a source name `intel_state` does not
    know must be refused by the database, not stored."""
    async def body(db):
        for column, bad in (("exploitation", "public poc"), ("automatable", "maybe"),
                            ("technical_impact", "TOTAL")):
            with pytest.raises(asyncpg.CheckViolationError):
                await db.execute(
                    f"INSERT INTO vulnrichment (cve, status, {column}) "
                    "VALUES ('CVE-2026-0001', 'found', $1)", bad)
        with pytest.raises(asyncpg.CheckViolationError):
            await db.execute("INSERT INTO vulnrichment (cve, status, exploitation) "
                             "VALUES ('CVE-2026-0001', 'not_found', 'none')")
        await db.execute("INSERT INTO intel_state (source) VALUES ('vulnrichment')")
        # the control's own row (migration 0049): without it `mirror.record` would be
        # refused here and, because it swallows errors, the verdict would never be written
        await db.execute("INSERT INTO intel_state (source) VALUES ($1)",
                         vulnrichment.CANARY_SOURCE)
        with pytest.raises(asyncpg.CheckViolationError):
            await db.execute("INSERT INTO intel_state (source) VALUES ('cisa')")
    _run_async(pg_dsn, body)


def test_a_later_answer_without_points_does_not_erase_a_good_evaluation(pg_dsn):
    """CISA does not retract an evaluation, so "found, no points" arriving after a
    real one is a truncated or blind response. Overwriting with NULL would turn a
    CISA-published `active` into "unpublished" with no trace."""
    async def body(db):
        await _publish(db, "CVE-2026-0001", "active", "yes", "total")
        await vulnrichment.store(db, "CVE-2026-0001", mirror.Outcome("found", {
            "exploitation": None, "automatable": None, "technical_impact": None,
            "ssvc_at": None, "ssvc_version": None}))
        row = (await vulnrichment.load(db, {"CVE-2026-0001"}))["CVE-2026-0001"]
        assert (row.exploitation, row.automatable, row.technical_impact) == (
            "active", "yes", "total")
        assert row.ssvc_at is not None and row.published is True
        # ...and a newer real evaluation DOES replace it.
        await _publish(db, "CVE-2026-0001", "poc", "no", "partial")
        row = (await vulnrichment.load(db, {"CVE-2026-0001"}))["CVE-2026-0001"]
        assert (row.exploitation, row.automatable, row.technical_impact) == (
            "poc", "no", "partial")
    _run_async(pg_dsn, body)


def test_due_follows_age_in_the_real_table(pg_dsn):
    async def body(db):
        now = datetime.now(timezone.utc)
        await _publish(db, "CVE-2026-0001", "none", "yes", "total")          # evaluated
        await _publish(db, "CVE-2026-0002", None)                            # unevaluated
        await vulnrichment.store(db, "CVE-2026-0003", mirror.Outcome("not_found", {}))
        wanted = {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"}
        assert await vulnrichment.due(db, wanted, now=now) == ["CVE-2026-0004"]
        later = now + timedelta(days=3)
        assert await vulnrichment.due(db, wanted, now=later) == ["CVE-2026-0002", "CVE-2026-0004"]
        much_later = now + timedelta(days=8)
        assert await vulnrichment.due(db, wanted, now=much_later) == sorted(wanted)
    _run_async(pg_dsn, body)


def test_the_pass_asks_cisa_once_stores_the_points_and_decides_on_them(pg_dsn):
    """End to end through `enrich.run` with the CVE service answered by a recorded
    real response: the points land in the table, the row is decided on them with
    `basis = vulnrichment`, and the next pass finds the answer fresh and asks nobody."""
    asked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(str(request.url))
        payload = json.loads((Path(__file__).parent.parent / "fixtures" / "intel"
                              / "cveawg_CVE-2025-29927.json").read_text(encoding="utf-8"))
        return httpx.Response(200, json=payload)
    control = f"https://cveawg.mitre.org/api/cve/{vulnrichment.CANARY_CONTROL_CVES[0]}"

    async def body(db):
        rid = await _finding(db, "k1", vector=WIDE_OPEN_TOTAL, cvss=9.8)
        cfg = _cfg(intel=True)
        cfg.intel.epss = False                  # the pass must not download FIRST's file here
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            out = await enrich.run(db, cfg, http=http)
            assert out["sources"]["vulnrichment"]["found"] == 1
            row = await _row(db, rid)
            data = json.loads(row["risk"])
            assert data["points"]["exploitation"] == {"value": "none", "basis": "vulnrichment",
                                                      "as_of": "2025-04-08"}
            assert data["points"]["technical_impact"]["basis"] == "vulnrichment"
            assert (row["risk_color"], row["risk_decision"]) == ("green", "track")
            await enrich.run(db, cfg, http=http)
        finally:
            await http.aclose()
        state = await mirror.state(db, "vulnrichment")
        assert state is not None and state["last_ok_at"] is not None
        canary = await mirror.state(db, vulnrichment.CANARY_SOURCE)
        assert canary is not None and canary["last_ok_at"] is not None
        assert json.loads(canary["detail"])["canary"] == "control_ok"
    _run_async(pg_dsn, body)
    # the host CVE once; the control (one request, on EVERY pass) twice; nobody else
    assert asked == ["https://cveawg.mitre.org/api/cve/CVE-2026-0001", control, control], asked


def test_a_blind_verdict_survives_an_ordinary_pass_in_the_real_table_and_only_a_confirmation_clears_it(
        pg_dsn):
    """The defect, through the real SQL of `mirror.record` (the fake database in the unit
    tests cannot show what Postgres does with the upsert): the pass that raised the alarm
    wrote `intel_state.detail`, and the next ordinary pass rewrote it. Now the verdict has
    its own row. Blind world over two passes of different size, then a healed one: the
    row stays unconfirmed (`last_ok_at` NULL) and carries the error until the control gets
    points, and the self-check, reading the real rows, says degraded, degraded, ok."""
    from sentinel.selfcheck import checks
    fixtures = Path(__file__).parent.parent / "fixtures" / "intel"

    def world(blind: bool):
        def handler(request: httpx.Request) -> httpx.Response:
            cve = request.url.path.rsplit("/", 1)[-1]
            name = cve if (cve in vulnrichment.CANARY_CONTROL_CVES and not blind) else "CVE-2025-40075"
            return httpx.Response(200, json=json.loads(
                (fixtures / f"cveawg_{name}.json").read_text(encoding="utf-8")))
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def status(db):
        out = {r.key: r for r in await checks.check_risk_intel(db)}
        return out["risk:vulnrichment"].status

    async def body(db):
        big = {f"CVE-2026-{n:04d}" for n in range(1, 31)}
        small = {f"CVE-2026-{n:04d}" for n in range(31, 36)}
        await db.execute("INSERT INTO intel_state (source, last_attempt_at, last_ok_at) "
                         "VALUES ('risk', now(), now())")
        async with world(blind=True) as http:
            await vulnrichment.ensure(db, big, http=http, pause_s=0)
            assert await status(db) == "degraded"
            await vulnrichment.ensure(db, small, http=http, pause_s=0)
        lookups = await mirror.state(db, vulnrichment.SOURCE)
        canary = await mirror.state(db, vulnrichment.CANARY_SOURCE)
        assert lookups["last_ok_at"] is not None, "the ordinary pass really did succeed"
        assert canary["last_ok_at"] is None and canary["last_error"]
        assert json.loads(canary["detail"])["canary"] == "control_blind"
        assert await status(db) == "degraded", "the success of an ordinary pass cleared the alarm"
        async with world(blind=False) as http:
            await vulnrichment.ensure(db, small, http=http, pause_s=0)
        canary = await mirror.state(db, vulnrichment.CANARY_SOURCE)
        assert canary["last_ok_at"] is not None and canary["last_error"] is None
        assert await status(db) == "ok"
    _run_async(pg_dsn, body)


# --- a REAL shipped row, through the receiver's own validators ---------------------
_RECEIVER_BRIDGE = """
import { allStreams } from "../lib/streams.ts";
import { prepareRows } from "../lib/ingest.ts";
const rows = JSON.parse(process.argv[2]);
const stream = allStreams().find((s) => s.name === "findings");
const out = prepareRows(stream, rows, "instanta-test", 1);
process.stdout.write(JSON.stringify(out.ok ? { ok: true } : { ok: false, detail: out.detail }));
"""


def _receiver_verdict(rows: list[dict]) -> dict:
    import tempfile
    from pathlib import Path

    node = shutil.which("node")
    aggregator = Path(__file__).resolve().parents[2] / "aggregator"
    if node is None or not (aggregator / "node_modules").is_dir():
        pytest.skip("node/aggregator/node_modules missing: the receiver was NOT consulted "
                    "(unverified, not 'accepted')")
    with tempfile.TemporaryDirectory(dir=aggregator, prefix=".tmp-risk-rows-") as tmp:
        script = Path(tmp) / "bridge.mjs"
        script.write_text(_RECEIVER_BRIDGE, encoding="utf-8", newline="\n")
        proc = subprocess.run([node, "--import", "tsx", str(script), json.dumps(rows)],
                              cwd=aggregator, capture_output=True, text=True, encoding="utf-8",
                              timeout=180, env={**os.environ, "NO_COLOR": "1"})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(proc.stdout)


def test_a_real_assessed_row_passes_the_receivers_validators_and_a_float_does_not(pg_dsn):
    """The row the shipper encodes from a real database is accepted by the
    aggregator's own `prepareRows` — every new column, in the form the real
    receiver checks (decimal as a canonical string, `risk` as valid JSON, colour and
    decision within their byte limits). And the failure that stops a stream for
    good, a JSON number where a decimal string belongs, is refused there by name."""
    async def body(db):
        rid = await _finding(db, "k1", vector=WIDE_OPEN_TOTAL, cvss=9.8)
        await _seed_epss(db, "CVE-2026-0001", 0.97, 0.99)
        await _publish(db, "CVE-2026-0001", "active")
        await enrich.run(db, _cfg())
        cols = ", ".join(shipper.select_columns(shipper.FINDING_STREAM))
        record = await db.fetchrow(f"SELECT {cols} FROM findings WHERE id = $1", rid)
        row, _ = shipper.encode_row(shipper.FINDING_STREAM, record, rid, 100)
        return row

    row = _run_async(pg_dsn, body)
    assert _receiver_verdict([row]) == {"ok": True}
    # Reproduce the defect the numeric column prevents: a float on the wire.
    bad = {**row, "risk_score": 0.97}
    verdict = _receiver_verdict([bad])
    assert verdict["ok"] is False and "risk_score" in verdict["detail"], verdict


def test_a_stale_cisa_observation_with_a_high_epss_lifts_the_row_and_the_lift_survives_the_database(
        pg_dsn):
    """Sentinel's own overlay, through the real SQL: EPSS 0.99 beside a CISA
    `none` from 2025-04-08 (the CVE-2025-29927 shape) is written as amber/attend
    (the colour/decision CHECK accepts it), `risk.overlay` records the rule and
    what SSVC alone said, a second pass writes nothing (the row must not be
    rewritten, and re-shipped, every hour), and the row passes the receiver's own
    validators, whose WAF edge scores the text of `risk`."""
    async def body(db):
        rid = await _finding(db, "k1", vector=WIDE_OPEN_TOTAL, cvss=9.1)
        await _seed_epss(db, "CVE-2026-0001", 0.99225, 0.99936)
        await _publish(db, "CVE-2026-0001", "none", "yes", "total",
                       at=datetime(2025, 4, 8, 15, 16, tzinfo=timezone.utc))
        await enrich.run(db, _cfg())
        first = await _row(db, rid)
        out = await enrich.run(db, _cfg())
        second = await _row(db, rid)
        assert out["changed"] == 0 and second["updated_at"] == first["updated_at"]
        cols = ", ".join(shipper.select_columns(shipper.FINDING_STREAM))
        record = await db.fetchrow(f"SELECT {cols} FROM findings WHERE id = $1", rid)
        shipped, _ = shipper.encode_row(shipper.FINDING_STREAM, record, rid, 100)
        return first, shipped

    first, shipped = _run_async(pg_dsn, body)
    assert (first["risk_color"], first["risk_decision"]) == ("amber", "attend")
    assert 60 <= first["priority"] < 80
    data = json.loads(first["risk"])
    assert data["points"]["exploitation"]["value"] == "none"
    assert data["overlay"]["basis"] == "epss_overlay"
    assert data["overlay"]["ssvc_decision"] == "track"
    assert data["overlay"]["observation_as_of"] == "2025-04-08"
    assert _receiver_verdict([shipped]) == {"ok": True}


def test_a_kev_row_outranks_an_epss_lifted_row_in_the_list_the_operator_reads(pg_dsn):
    """The operator's rule, through the real SQL and the real list query: what was
    OBSERVED goes before what is PREDICTED. A KEV row (1.0 x CVSS 7.5) and a row lifted by
    the EPSS rule (0.99 x CVSS 9.1, scoring HIGHER) are written by `enrich.run`; the list
    the operator reads (`list_open`, `ORDER BY priority DESC, risk_score DESC`) must put the
    KEV row first. Before, the forecast stood 1st of 812 on the real host at priority 77,
    above both KEV rows at 75 and 74."""
    async def body(db):
        kev = await _finding(db, "kev", cve="CVE-2026-9000", vector=WIDE_OPEN_DOS, cvss=7.5)
        lifted = await _finding(db, "lifted", cve="CVE-2026-0001",
                                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", cvss=9.1)
        await _seed_epss(db, "CVE-2026-0001", 0.99225, 0.99936)
        await _publish(db, "CVE-2026-0001", "none", "yes", "total",
                       at=datetime(2025, 4, 8, 15, 16, tzinfo=timezone.utc))
        await enrich.run(db, _cfg())
        rows = await fx.list_open(db, limit=10)
        return kev, lifted, [r["id"] for r in rows], {r["id"]: r for r in rows}

    kev, lifted, order, by_id = _run_async(pg_dsn, body)
    assert by_id[kev]["risk_color"] == by_id[lifted]["risk_color"] == "amber"
    assert float(by_id[lifted]["risk_score"]) > float(by_id[kev]["risk_score"]), (
        "the premise: the forecast scores higher than the observation")
    assert by_id[kev]["priority"] > by_id[lifted]["priority"]
    assert order.index(kev) < order.index(lifted)
    assert 60 <= by_id[lifted]["priority"] < 70 and 70 <= by_id[kev]["priority"] < 80


def test_a_lifted_row_with_a_pending_reboot_is_one_step_down_in_the_database_too(pg_dsn):
    """The reboot demotion acts on the floor's result, in the row the operator sees: Track*
    (green) with the reboot mark, the colour/decision CHECK accepting it, and the record
    naming both steps. Checked through the real pending-reboot SQL (`fix_state` in `raw`)."""
    async def body(db):
        rid = await _finding(db, "k1", vector=WIDE_OPEN_TOTAL, cvss=9.1)
        await db.execute(
            "UPDATE findings SET raw = $2::jsonb WHERE id = $1", rid,
            json.dumps({"fix_state": {"state": "pending_reboot"}}))
        await _seed_epss(db, "CVE-2026-0001", 0.99225, 0.99936)
        await _publish(db, "CVE-2026-0001", "none", "yes", "total",
                       at=datetime(2025, 4, 8, 15, 16, tzinfo=timezone.utc))
        await enrich.run(db, _cfg())
        return await _row(db, rid)

    row = _run_async(pg_dsn, body)
    data = json.loads(row["risk"])
    assert data["reboot_pending"] is True, "the premise: the real SQL saw the pending reboot"
    assert (row["risk_color"], row["risk_decision"]) == ("green", "track_star")
    assert data["decision_before_reboot"] == "attend"
    assert data["overlay"]["ssvc_decision"] == "track"
