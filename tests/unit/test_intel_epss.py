"""The EPSS mirror: what it accepts, what it refuses, and when it goes to the
network.

The failure this file exists to prevent, in the operator's terms: a download
that is truncated, reformatted or empty must never become "EPSS says zero" on
the page. A refusal leaves the old values (old) and says so in `intel_state`;
a read of an old value says it is old (grey), it does not pretend.

Real-SQL behaviour of the tables lives in
`tests/integration/test_risk_intel_pg.py`; here the database is a small fake
that only records what was asked, so these tests are about decisions.
"""

from __future__ import annotations

import asyncio
import gzip
from datetime import date, datetime, timedelta, timezone
from typing import Any

import httpx
import pytest

from sentinel.intel import epss

NOW = datetime(2026, 10, 2, 3, 15, tzinfo=timezone.utc)


def _file(rows: dict[str, tuple[str, str]], *, score_date: str = "2026-10-01",
          header: str | None = None, filler: int = 0) -> bytes:
    """A file shaped like FIRST's: comment line, column line, then rows."""
    lines = [header if header is not None
             else f"#model_version:v2026.06.15,score_date:{score_date}T12:00:22Z",
             "cve,epss,percentile"]
    lines += [f"{cve},{e},{p}" for cve, (e, p) in rows.items()]
    lines += [f"CVE-2000-{i:05d},0.00100,0.10000" for i in range(filler)]
    return gzip.compress(("\n".join(lines) + "\n").encode())


@pytest.fixture(autouse=True)
def small_files(monkeypatch):
    """Most tests use a tiny file; the size floor has its own tests below."""
    monkeypatch.setattr(epss, "MIN_ROWS", 3)


def test_parse_keeps_only_the_cves_asked_for_and_reads_the_date():
    blob = _file({"CVE-2024-6501": ("0.00450", "0.36820"),
                  "CVE-2025-1": ("x", "y")}, filler=5)
    date_, found, valid = epss.parse(blob, {"CVE-2024-6501", "CVE-2099-0001"})
    assert date_ == date(2026, 10, 1)
    assert found == {"CVE-2024-6501": (0.0045, 0.3682)}
    assert valid == 6   # 1 good + 5 filler; the malformed row is not counted


def test_a_truncated_download_is_refused_not_read_as_far_as_it_goes():
    """gzip decompresses a cut-off stream "successfully" up to the cut. Reading
    that as the whole file would mark every CVE after the cut as absent."""
    blob = _file({}, filler=2000)
    with pytest.raises(epss.FileRejected, match="trunchiat"):
        epss.parse(blob[: len(blob) // 2], set())


def test_a_file_that_is_not_gzip_is_refused():
    with pytest.raises(epss.FileRejected):
        epss.parse(b"<html>503 Service Unavailable</html>", set())


@pytest.mark.parametrize("header,message", [
    ("model_version:v1", "antet"),                    # no leading '#'
    ("#model_version:v2026.06.15", "score_date"),      # no date
    ("#score_date:2026-13-45T00:00:00Z", "score_date"),
])
def test_without_a_date_the_age_of_the_values_is_unknowable(header, message):
    """`score_date` is how a value says how old it is. A file without it would
    make every score look fresh forever."""
    with pytest.raises(epss.FileRejected, match=message):
        epss.parse(_file({}, header=header, filler=5), set())


def test_a_changed_column_header_is_refused():
    blob = gzip.compress(b"#score_date:2026-10-01T00:00:00Z\ncve,score,pct\nCVE-2024-1,0.1,0.2\n")
    with pytest.raises(epss.FileRejected, match="antet de coloane"):
        epss.parse(blob, set())


def test_a_file_far_smaller_than_the_real_one_is_refused(monkeypatch):
    """The real file has ~380,000 rows. A 5-row "file" is a different page or a
    broken export, and accepting it would write "EPSS has never heard of" to
    every CVE we asked about."""
    monkeypatch.setattr(epss, "MIN_ROWS", 100_000)
    with pytest.raises(epss.FileRejected, match="rânduri valide"):
        epss.parse(_file({"CVE-2024-6501": ("0.0045", "0.3682")}, filler=4), set())


def test_a_file_of_realistic_size_is_accepted(monkeypatch):
    monkeypatch.setattr(epss, "MIN_ROWS", 100_000)
    blob = _file({"CVE-2024-6501": ("0.00450", "0.36820")}, filler=120_000)
    _, found, valid = epss.parse(blob, {"CVE-2024-6501"})
    assert valid == 120_001 and found["CVE-2024-6501"] == (0.0045, 0.3682)


def test_out_of_range_values_are_rows_that_do_not_count():
    """A score of 7 is not a probability; counted as valid it would reach a
    column whose CHECK rejects it and fail the whole batch."""
    blob = _file({"CVE-2024-6501": ("7", "0.3")}, filler=5)
    _, found, valid = epss.parse(blob, {"CVE-2024-6501"})
    assert found == {} and valid == 5


def test_too_many_unreadable_rows_refuse_the_file(monkeypatch):
    monkeypatch.setattr(epss, "MAX_BAD_ROWS", 2)
    blob = _file({f"CVE-2024-{i}": ("x", "y") for i in range(1000, 1010)}, filler=10)
    with pytest.raises(epss.FileRejected, match="ilizibile"):
        epss.parse(blob, set())


# ---------------------------------------------------------------------------
# is_fresh: an old value is not a measurement
# ---------------------------------------------------------------------------
TODAY = date(2026, 10, 2)


def test_a_value_older_than_a_week_is_not_used():
    """FIRST publishes daily; nine days of silence means the mirror is broken,
    and a confident colour on nine-day-old data is the quiet kind of wrong."""
    fresh = epss.Row(0.1, 0.9, TODAY - timedelta(days=epss.MAX_AGE_DAYS))
    old = epss.Row(0.1, 0.9, TODAY - timedelta(days=epss.MAX_AGE_DAYS + 1))
    assert epss.is_fresh(fresh, TODAY) is True
    assert epss.is_fresh(old, TODAY) is False


@pytest.mark.parametrize("row", [None, epss.Row(None, None, TODAY),
                                 epss.Row(0.1, 0.2, None)])
def test_absent_or_undated_values_are_not_fresh(row):
    assert epss.is_fresh(row, TODAY) is False


# ---------------------------------------------------------------------------
# refresh: when it goes to the network, and what a failure leaves behind
# ---------------------------------------------------------------------------
class FakeDB:
    """Just enough database for `epss.refresh`: two tables as dicts."""

    def __init__(self, *, ok_ago_h: float | None = None, attempt_ago_h: float | None = None,
                 mirrored: set[str] | None = None) -> None:
        self.state: dict[str, Any] | None = None
        if ok_ago_h is not None or attempt_ago_h is not None:
            self.state = {
                "last_ok_at": None if ok_ago_h is None else NOW - timedelta(hours=ok_ago_h),
                "last_attempt_at": None if attempt_ago_h is None
                else NOW - timedelta(hours=attempt_ago_h),
                "last_error": None, "detail": {}}
        self.rows = {c: None for c in (mirrored or set())}
        self.written: list[tuple] = []
        self.recorded: list[tuple] = []

    async def fetchrow(self, sql: str, *args: Any):
        assert "FROM intel_state" in sql
        return self.state

    async def fetch(self, sql: str, *args: Any):
        assert "FROM epss_scores" in sql
        return [{"cve": c} for c in args[0] if c in self.rows]

    async def executemany(self, sql: str, rows: list[tuple]):
        assert "INSERT INTO epss_scores" in sql
        self.written += rows
        for r in rows:
            self.rows[r[0]] = r

    async def execute(self, sql: str, *args: Any):
        assert "INSERT INTO intel_state" in sql
        self.recorded.append(args)
        source, ok, error = args[0], args[1], args[2]
        assert source == "epss"
        prev = self.state or {"last_ok_at": None}
        self.state = {"last_ok_at": NOW if ok else prev["last_ok_at"],
                      "last_attempt_at": NOW, "last_error": error, "detail": {}}


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)


def _serve(blob: bytes, calls: list[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path.endswith("-current.csv.gz"):
            return httpx.Response(302, headers={"location": "/epss_scores-2026-10-01.csv.gz"})
        return httpx.Response(200, content=blob)
    return handler


def _run(coro):
    return asyncio.run(coro)


def test_first_run_downloads_once_follows_the_redirect_and_mirrors_only_what_was_asked():
    calls: list[str] = []
    blob = _file({"CVE-2024-6501": ("0.00450", "0.36820"),
                  "CVE-2025-0001": ("0.5", "0.99")}, filler=5)
    db = FakeDB()
    out = _run(epss.refresh(db, {"CVE-2024-6501", "CVE-2099-0001"},
                            http=_client(_serve(blob, calls)), now=NOW))
    assert out["status"] == "updated"
    assert len(calls) == 2 and calls[0].endswith("epss_scores-current.csv.gz")
    assert set(db.rows) == {"CVE-2024-6501", "CVE-2099-0001"}   # not the other 5,000
    assert db.rows["CVE-2024-6501"][1:3] == (0.0045, 0.3682)
    assert db.state["last_ok_at"] == NOW


def test_a_cve_the_file_does_not_know_is_mirrored_as_absent_not_skipped():
    """"EPSS has not scored it yet" is an answer. Skipped, the CVE would be
    "missing" on every pass and drag the file down again each hour."""
    db = FakeDB()
    _run(epss.refresh(db, {"CVE-2099-0001"}, http=_client(_serve(
        _file({}, filler=5), [])), now=NOW))
    row = db.rows["CVE-2099-0001"]
    assert row[1] is None and row[2] is None and row[3] == date(2026, 10, 1)


def test_a_fresh_complete_mirror_makes_no_request():
    """The maintenance timer runs hourly; without this it would fetch 2.7 MB
    twenty-four times a day for a file that changes once."""
    calls: list[str] = []
    db = FakeDB(ok_ago_h=3, attempt_ago_h=3, mirrored={"CVE-2024-6501"})
    out = _run(epss.refresh(db, {"CVE-2024-6501"},
                            http=_client(_serve(b"", calls)), now=NOW))
    assert out["status"] == "fresh" and calls == []


def test_a_stale_mirror_is_refreshed():
    calls: list[str] = []
    db = FakeDB(ok_ago_h=30, attempt_ago_h=30, mirrored={"CVE-2024-6501"})
    out = _run(epss.refresh(db, {"CVE-2024-6501"}, http=_client(_serve(
        _file({"CVE-2024-6501": ("0.1", "0.5")}, filler=5), calls)), now=NOW))
    assert out["status"] == "updated" and calls


def test_a_new_cve_in_a_fresh_mirror_triggers_one_download_but_not_every_hour():
    """A CVE that appeared after the last download has no row. It earns a
    fetch, but a second hour later must not repeat it."""
    calls: list[str] = []
    db = FakeDB(ok_ago_h=7, attempt_ago_h=7, mirrored={"CVE-2024-6501"})
    blob = _file({"CVE-2026-9999": ("0.2", "0.7")}, filler=5)
    first = _run(epss.refresh(db, {"CVE-2024-6501", "CVE-2026-9999"},
                              http=_client(_serve(blob, calls)), now=NOW))
    assert first["status"] == "updated" and "CVE-2026-9999" in db.rows
    n = len(calls)
    again = _run(epss.refresh(db, {"CVE-2024-6501", "CVE-2026-9999"},
                              http=_client(_serve(blob, calls)), now=NOW))
    assert again["status"] == "fresh" and len(calls) == n


def test_a_failed_attempt_is_not_repeated_within_the_hour():
    """A down source must not be hammered by an hourly timer's neighbours: the
    scan and the maintenance run both call this."""
    calls: list[str] = []
    db = FakeDB(ok_ago_h=40, attempt_ago_h=0.2)
    out = _run(epss.refresh(db, {"CVE-2024-6501"}, http=_client(_serve(b"", calls)), now=NOW))
    assert out["status"] == "skipped" and calls == []


def test_a_server_error_is_recorded_leaves_old_rows_alone_and_does_not_raise():
    """The point of the whole design: a dead feed is not a failed scan and not
    a silent zero. Old values stay, the failure is written where the
    self-check can read it."""
    def boom(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="down")
    db = FakeDB(ok_ago_h=40, attempt_ago_h=40, mirrored={"CVE-2024-6501"})
    out = _run(epss.refresh(db, {"CVE-2024-6501"}, http=_client(boom), now=NOW))
    assert out["status"] == "failed"
    assert db.written == []
    assert db.state["last_error"] and "503" in db.state["last_error"]
    assert db.state["last_ok_at"] == NOW - timedelta(hours=40)   # not moved


def test_a_rejected_file_is_a_failure_and_writes_nothing():
    db = FakeDB()
    out = _run(epss.refresh(db, {"CVE-2024-6501"}, http=_client(_serve(
        b"<html>maintenance</html>", [])), now=NOW))
    assert out["status"] == "failed" and db.written == []
    assert db.state["last_ok_at"] is None


def test_a_network_error_does_not_raise():
    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")
    out = _run(epss.refresh(FakeDB(), {"CVE-2024-6501"}, http=_client(unreachable), now=NOW))
    assert out["status"] == "failed"


def test_ids_that_are_not_cves_are_never_sent_anywhere():
    """Ids come from scanner output. Only well-formed CVE ids may reach SQL or
    a cache key."""
    db = FakeDB()
    out = _run(epss.refresh(db, {"GHSA-aaaa-bbbb-cccc", "x; DROP TABLE y", ""},
                            http=_client(_serve(b"", [])), now=NOW))
    assert out["status"] == "fresh" and db.written == []
