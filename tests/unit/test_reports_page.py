"""The Reports page and its drill-down, driven through the real application.

Real middleware, real router, real Jinja templates; only the database is a stub.
That is the combination that catches what a unit test cannot: a template that
renders in isolation but names a context key the handler never passes, a page
that forgets the CSRF token the shared sidebar needs, or markup that the
deployed CSP would refuse to apply.

Each test names the failure it prevents. The two that would be invisible on a
developer's screen and fatal on the server:

  * a chart drawn with `style="height:…"` — the CSP is `style-src 'self'` with
    no `unsafe-inline`, so the browser drops the attribute and the chart renders
    as a blank strip that looks exactly like "no attacks";
  * an empty aggregate rendered as a quiet week instead of as an aggregate that
    never ran.
"""

from __future__ import annotations

import contextlib
import pathlib
from datetime import date, datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from sentinel.analytics import reports
from sentinel.config import Config, Secrets
from sentinel.util import tz
from sentinel.web.security import COOKIE_NAME

SESSION_SECRET = "e" * 64
TOKEN = "test-session-token"
# A FIXED moment, injected into the handler through the `now_utc` dependency.
#
# It used to be `datetime.now()` evaluated at import, while the handler read its
# own clock per request. When the two landed either side of an hour boundary the
# stub's newest rollup bucket fell behind the chart's newest column, and the
# guards for the round-1 blocker failed — an alarm saying "the blocker is back"
# roughly 0.4% of runs, and more than that on a loaded CI box. A test that cries
# wolf is a test that gets ignored, and this repository has already paid for one
# that "passed for exactly three days".
#
# 06:37 is deliberately mid-hour: the newest hour bucket is then genuinely
# partial, which is the interesting case.
NOW = datetime(2026, 8, 9, 6, 37, 12, tzinfo=timezone.utc)

# Fusul in care pagina ALINIAZA marginile de interval, citit din `Config`, nu
# scris a doua oara aici: un literal s-ar desparti tacut de configuratia pe care
# o foloseste aplicatia, iar testele ar verifica alta aliniere decat cea
# desenata. Din 28 august 2026 zilele/saptamanile/lunile/anii incep la miezul
# noptii LOCAL; ora ramane aliniata absolut (vezi `reports.align_zone`).
TZ = Config().timezone

# Midnight-ish, where the daily chart's newest column starts at the same instant
# as `max(bucket)` — the exact shape that made the daily chart hatch today.
MIDNIGHT = datetime(2026, 8, 9, 0, 12, 30, tzinfo=timezone.utc)


def _kpi_cards(html: str) -> dict[str, str]:
    """The KPI row, split into one chunk per card, keyed by its label.

    Narrowed to `<div class="kpis">` first: the last card's chunk would
    otherwise run to the end of the document and swallow every panel below it,
    so an assertion about "this card carries no caveat" would be answered by
    some other card's caveat further down the page.
    """
    row = html.split('<div class="kpis">', 1)[1].split('<div class="grid">', 1)[0]
    return {b.split("</span>")[0].lstrip(">").strip(): b
            for b in row.split('class="kpi-label"')[1:]}


def _session_row(csrf: str = "csrf-token-value") -> dict:
    return {
        "id": "sess1", "user_id": 1, "pending_totp": False, "csrf_token": csrf,
        "expires_at": NOW + timedelta(hours=8), "created_at": NOW - timedelta(hours=1),
        "last_seen_at": NOW, "ip": "203.0.113.7",
    }


def _user_row() -> dict:
    return {
        "id": 1, "username": "operator", "password_hash": "x", "password_algo": "argon2id",
        "totp_secret": None, "totp_confirmed": True, "totp_last_counter": None,
        "role": "owner", "failed_attempts": 0, "locked_until": None, "disabled": False,
    }


class StubDB:
    """Answers by matching a distinctive fragment of the SQL.

    Insertion order matters: the first needle that appears in the statement
    wins, so the specific patterns are registered before the general ones.
    """

    def __init__(self, *, rollup_earliest=None, rollup_latest=None,
                 raw_from=None, installed=None, event_rows=None,
                 incident_rows=None, patch_rows=None, drill_rows=None):
        self.rows = {
            # -- auth --------------------------------------------------------
            "FROM sessions": _session_row(),
            "FROM users WHERE id": _user_row(),
            # -- coverage probe (must precede the overview's rollup query) ----
            "AS earliest": {"earliest": rollup_earliest, "latest": rollup_latest},
            # -- overview ----------------------------------------------------
            "AS hostile": {"total": 1234, "hostile": 900},
            "AS succeeded": {"succeeded": 2, "failed": 1, "rolled_back": 0, "total": 3},
            "AS deschise": {"deschise": 5, "kev": 1, "grave": 2, "noi": 3, "rezolvate": 4},
        }
        self.lists = {
            "COALESCE(source, '')": event_rows or [],
            "COALESCE(action, '')": [],
            "COALESCE(severity, '')": incident_rows or [],
            "split_part(split_part": [],
            "FROM patch_executions": patch_rows or [],
            # The needle has to track the statement: after the source card
            # gained a folded tail the LIMIT became a bound parameter, and a
            # stale needle would have made this stub answer [] for ever while
            # the card's tests went on passing.
            "ORDER BY 2 DESC LIMIT $2": [{"k": "nginx", "n": 900},
                                         {"k": "sshd", "n": 40}],
            "status IN ('open','acknowledged')": [{"k": "high", "n": 2}, {"k": "low", "n": 1}],
            "first_detection_at >= $1 GROUP BY 1": [{"k": "high", "n": 1}],
            "_drill": drill_rows or [],
        }
        self.vals = {
            "pg_inherits": raw_from,
            "schema_version": installed,
            # The recoverability edge. Explicit and None by default: a test that
            # has not thought about it gets "we could not ask", which never
            # produces a final verdict — the safe direction.
            "min(bucket) FROM event_rollup_1m": None,
        }
        self.sql: list[str] = []
        # Si argumentele legate. Textul singur nu poate arata CE fus a ajuns in
        # `AT TIME ZONE $2`, iar diferenta dintre `Europe/Bucharest` si `UTC`
        # acolo e chiar subiectul paginii.
        self.calls: list[tuple[str, tuple]] = []

    async def connect(self):
        return None

    async def close(self):
        return None

    async def healthy(self):
        return True

    async def fetchrow(self, sql, *a):
        self.sql.append(sql)
        for needle, row in self.rows.items():
            if needle in sql:
                return row
        return None

    async def fetch(self, sql, *a):
        self.sql.append(sql)
        self.calls.append((sql, a))
        # Checked first: a drill-down statement shares most of its WHERE clause
        # with the series query it came from, so matching on the breakdown
        # column would hand the drill-down the chart's rows.
        #
        # `$3` as well as `$4`: the all-categories drill drops the category
        # predicate and so shifts the LIMIT placeholder. A needle pinned to one
        # of them would make this stub answer [] for the other, for ever, while
        # its tests went on passing.
        if "LIMIT $4" in sql or "LIMIT $3" in sql:
            return self.lists["_drill"]
        for needle, rows in self.lists.items():
            if needle in sql and needle != "_drill":
                return rows
        return []

    async def fetchval(self, sql, *a):
        self.sql.append(sql)
        for needle, val in self.vals.items():
            if needle in sql:
                return val
        return None

    async def execute(self, sql, *a):
        self.sql.append(sql)
        return "UPDATE 1"


@contextlib.contextmanager
def _client(db: StubDB, *, authenticated: bool = True, now: datetime = NOW):
    """The real app over a stub database.

    `create_app`'s lifespan constructs a `Database`, which would need a DSN and
    a live PostgreSQL; swapping the class is the same trick `test_web_routes`
    uses. Everything else — middleware, routers, templates — is genuine.

    https, not http: every cookie Sentinel sets carries `Secure`, and an HTTP
    client refuses to send those back, which would look like a session bug.

    The clock is overridden rather than mocked out: `now_utc` is a real
    dependency the handlers take, so the override exercises the same code path
    production does and simply pins the value.
    """
    from sentinel.web import app as app_module
    from sentinel.web.deps import now_utc

    def _stub_database(_cfg):
        return db

    original = app_module.Database
    app_module.Database = _stub_database          # type: ignore[assignment]
    try:
        cfg = Config()
        cfg.web.domain = "sentinel.example.com"
        secrets = Secrets({"SENTINEL_SESSION_SECRET": SESSION_SECRET})
        app = app_module.create_app(cfg, secrets)
        app.dependency_overrides[now_utc] = lambda: now
        with TestClient(app, base_url="https://testserver") as client:
            if authenticated:
                client.cookies.set(COOKIE_NAME, TOKEN)
            yield client
    finally:
        app_module.Database = original            # type: ignore[assignment]


def _naive_bucket(start: datetime, unit: str) -> datetime:
    """Marginea, in forma in care o intoarce chiar `date_trunc`.

    `date_trunc($1, ts AT TIME ZONE $2)` intoarce un `timestamp` FARA fus: ceasul
    de perete al zonei de aliniere. Un stub care ar intoarce ceasul UTC pentru o
    galeata aliniata local ar ascunde exact greseala de citire pe care o poate
    face pagina — barele ar cadea pe alte coloane decat cele desenate, si nimic
    nu s-ar plange.
    """
    return tz.to_local(start, reports.align_zone(unit, TZ)).replace(tzinfo=None)


def _event_rows(earliest: datetime, now: datetime = NOW,
                latest: datetime | None = None) -> list[dict]:
    """Rollup rows for every day and hour bucket the coverage actually claims.

    Only inside the coverage: a stub that hands back rows for a period it also
    reports as dropped is a shape PostgreSQL cannot produce, and asserting
    against it proves nothing about the real page.
    """
    rows = []
    for unit, count in (("day", 30), ("hour", 48)):
        for i, s in enumerate(reports.bucket_starts(unit, now=now, count=count, tz_name=TZ)):
            if s < earliest:
                continue
            # Taierea de sus se face pe INSTANTE, nu pe ceasul de perete: lista
            # amesteca galeti aliniate local cu galeti aliniate absolut, iar o
            # comparatie intre doua ceasuri de perete din zone diferite ar taia
            # cu decalajul in plus sau in minus.
            if latest is not None and s >= latest + timedelta(hours=1):
                continue
            rows.append({"b": _naive_bucket(s, unit), "k": "nginx", "n": 40 + i})
    return rows


def _set_rollup(stub: StubDB, *, earliest: datetime | None, latest: datetime | None) -> None:
    """Move the stub's rollup coverage AND its rows together, so the two never
    contradict each other the way only a stub can."""
    stub.rows["AS earliest"] = {"earliest": earliest, "latest": latest}
    stub.lists["COALESCE(source, '')"] = (
        [] if earliest is None or latest is None
        else _event_rows(earliest, latest=latest))


@pytest.fixture
def stub() -> StubDB:
    """A populated, healthy install: the rollup covers 40 days and is current.

    `rollup_latest` is on an hour boundary because that is what
    `max(bucket)` returns — `bucket` is `date_trunc('hour', …)`. The first
    version of this fixture used `NOW - 15 minutes`, a value the database cannot
    produce, and that convenience is precisely why the page tests stayed green
    while the newest column of every hourly chart was rendered as "no data".
    """
    starts = reports.bucket_starts("day", now=NOW, count=30, tz_name=TZ)
    earliest = NOW - timedelta(days=40)
    return StubDB(
        rollup_earliest=earliest,
        rollup_latest=reports.truncate(NOW, "hour", tz_name=TZ),
        raw_from=(NOW - timedelta(days=25)).date(),
        installed=NOW - timedelta(days=60),
        event_rows=_event_rows(earliest),
        incident_rows=[{"b": _naive_bucket(starts[-2], "day"), "k": "high", "n": 3},
                       {"b": _naive_bucket(starts[-1], "day"), "k": "critical", "n": 1}],
        patch_rows=[{"b": _naive_bucket(starts[-1], "day"), "k": "succeeded", "n": 2}],
    )


# ---------------------------------------------------------------------------
# The page exists, is gated, and renders
# ---------------------------------------------------------------------------
def test_reports_requires_a_session():
    """A page of aggregated security history behind no authentication would be
    the single largest disclosure in the product."""
    with _client(StubDB(), authenticated=False) as c:
        r = c.get("/reports", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_reports_renders_with_data(stub):
    with _client(stub) as c:
        r = c.get("/reports")
    assert r.status_code == 200
    assert "Rapoarte" in r.text
    assert "Incidente pe severitate" in r.text
    assert "Patch-uri pe stare" in r.text


def test_reports_renders_on_a_completely_empty_install(stub):
    """A fresh install must not 500 on empty tables — that is the state every
    operator sees first."""
    with _client(StubDB()) as c:
        r = c.get("/reports")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# CSP: what the browser will actually apply
# ---------------------------------------------------------------------------
def test_the_page_ships_no_script_at_all(stub):
    """`script-src 'self'` with no `unsafe-inline`. An inline handler or a
    <script> block would be refused by the browser, so a page that needs one is
    a page that does not work on the server."""
    with _client(stub) as c:
        body = c.get("/reports").text.lower()
    assert "<script" not in body
    assert "javascript:" not in body
    assert "onclick" not in body and "onload" not in body


def test_no_element_sizes_itself_with_an_inline_style(stub):
    """The chart is the whole point of the page, and CSP3 falls `style-src-attr`
    back to `style-src` — which here is `'self'` with no `unsafe-inline`. A bar
    whose height comes from a `style` attribute is dropped by the browser and
    renders as nothing, which is indistinguishable from "no attacks". Geometry
    therefore lives in SVG presentation attributes."""
    with _client(stub) as c:
        body = c.get("/reports").text
    assert 'style="' not in body
    assert "<svg" in body and "<rect" in body


def test_the_chart_is_real_svg_geometry_not_an_empty_frame(stub):
    """Guards the case where the SVG is emitted but every bar has zero height —
    the page would look built and show nothing."""
    with _client(stub) as c:
        body = c.get("/reports").text
    import re
    heights = [float(h) for h in re.findall(r'<rect[^>]*height="([\d.]+)"', body)]
    assert heights, "no <rect> heights in the page at all"
    assert max(heights) > 10, f"every bar is flat: {sorted(heights)[-5:]}"


def test_the_sidebar_logout_form_carries_a_usable_csrf_token(stub):
    """base.html puts the logout form on every authenticated page. A handler
    that forgets `csrf_token` renders it empty, and the middleware then bounces
    the operator to /login?e=csrf instead of logging them out."""
    with _client(stub) as c:
        body = c.get("/reports").text
    assert 'name="csrf_token" value="csrf-token-value"' in body


# ---------------------------------------------------------------------------
# Honesty about missing data
# ---------------------------------------------------------------------------
def test_an_aggregate_that_never_ran_is_announced_not_drawn_as_calm():
    """`event_rollup_1h` empty means the maintenance pass has never completed.
    Every event chart is then blank — and a blank chart reads as a quiet server.
    The page has to say which one it is."""
    with _client(StubDB()) as c:
        body = c.get("/reports").text
    assert "Agregatul orar de evenimente este gol" in body
    assert "sentinel-maintenance" in body


def test_a_stale_aggregate_reports_its_lag(stub):
    """The rollup timer is hourly. Nine hours behind means runs are failing, and
    the missing tail of every chart is absence of data, not absence of attacks.

    The NUMBER is asserted, not the word. Checking only for "întârziere" left
    the figure free to come from the machine's clock instead of the page's, and
    it passed either way because the fixture moment happened to fall on the same
    calendar day as the sandbox — the same coincidence that let the W2 guard
    pass in round 2.
    """
    latest = reports.truncate(NOW, "hour", tz_name=TZ) - timedelta(hours=9)
    _set_rollup(stub, earliest=NOW - timedelta(days=40), latest=latest)
    with _client(stub) as c:
        body = c.get("/reports").text
    expected = round((NOW - latest).total_seconds() / 3600, 1)
    assert expected == 9.6                       # 06:37:12 against 21:00
    assert f"întârziere de {expected} ore" in body
    assert "lipsă de date" in body
    # Scris in fusul configurat, cu marcaj: pagina nu mai afirma „UTC" peste o
    # ora pe care operatorul o citeste pe alt ceas.
    assert tz.fmt(latest, "%d.%m.%Y %H:%M", tz_name=TZ) in body
    assert latest.strftime("%d.%m.%Y %H:%M") + " UTC" not in body


def test_a_current_aggregate_raises_no_alarm(stub):
    with _client(stub) as c:
        body = c.get("/reports").text
    assert "Agregatul orar de evenimente este gol" not in body
    assert "întârziere de" not in body


def test_uncovered_buckets_are_hatched_rather_than_flat(stub):
    """Retention dropped those months. The bar must not be a zero-height bar."""
    _set_rollup(stub, earliest=NOW - timedelta(days=3),
                latest=reports.truncate(NOW, "hour", tz_name=TZ))
    with _client(stub) as c:
        body = c.get("/reports").text
    assert "url(#hatch-" in body
    assert "fără date păstrate" in body


def test_full_coverage_shows_no_hatching(stub):
    with _client(stub) as c:
        body = c.get("/reports").text
    assert "fără date păstrate" not in body


_NEWEST_CASES = [("hour", NOW), ("day", NOW), ("day", MIDNIGHT), ("hour", MIDNIGHT)]
_NEWEST_IDS = ["hour-midmorning", "day-midmorning", "day-first-hour-utc",
               "hour-first-hour-utc"]


def _events_drill_href(bucket: str, start: datetime, value: str) -> str:
    """The href the events-by-source chart puts on one bar, as rendered."""
    raw = reports.drill_href({"kind": "events", "dim": "source", "bucket": bucket},
                             start=start, value=value)
    return raw.replace("&", "&amp;")          # Jinja escapes the separators


def _rect_after(body: str, anchor: str) -> dict[str, str] | None:
    """Attributes of the <rect> that `anchor` wraps, or None if it wraps none."""
    import re

    if anchor not in body:
        return None
    tail = body.split(anchor, 1)[1]
    m = re.match(r"\s*<rect\b([^>]*)>", tail, re.S)
    if not m:
        return None
    return dict(re.findall(r'(\w[\w-]*)="([^"]*)"', m.group(1)))


@pytest.mark.parametrize(("bucket", "now"), _NEWEST_CASES, ids=_NEWEST_IDS)
def test_the_newest_bucket_with_no_events_is_a_covered_zero_not_a_gap(bucket, now):
    """The edge bug in the case the row-count guard in `build_series` cannot
    rescue: with no rows there is no direct evidence to override a wrong
    coverage edge, so a genuinely quiet newest bucket is still marked as having
    no data. Quiet and unrecorded have to stay distinguishable exactly where the
    arithmetic is hardest.

    `rep-pending` is asserted absent as well as the hatch. Restoring the round-1
    blocker no longer produces a hatch — it produces a pending outline — so a
    test that only looked for hatching went silent on the very regression it was
    written for."""
    earliest = now - timedelta(days=40)
    db = StubDB(rollup_earliest=earliest,
                rollup_latest=reports.truncate(now, "hour", tz_name=TZ),
                installed=now - timedelta(days=60))
    with _client(db, now=now) as c:
        body = c.get(f"/reports?bucket={bucket}").text
    assert "fără date păstrate" not in body
    assert "url(#hatch-" not in body
    assert 'class="rep-pending"' not in body, "a covered quiet bucket was marked pending"
    assert "încă neagregat" not in body
    assert "zero înseamnă chiar zero" in body


@pytest.mark.parametrize(
    ("bucket", "now"),
    # The daily chart failed ONLY while `max(bucket)` equalled the start of
    # today's day bucket — i.e. between 00:00 and 01:00 UTC. Parametrising over
    # the bucket alone left the `day` case unable to fail at all outside that
    # hour: it looked like coverage and was decoration. The clock is part of the
    # case, so it is part of the parameter.
    _NEWEST_CASES,
    ids=_NEWEST_IDS,
)
def test_the_newest_bucket_with_data_is_drawn_as_a_bar_with_its_own_drill_link(
    bucket, now
):
    """End-to-end form of the blocker: the newest column held events and was
    drawn as a gap, with no drill-down link, while the header total disagreed
    with the sum of the bars.

    Asserted POSITIVELY, and that is the point. The previous version checked
    only that no hatch appeared and that *some* drill link existed somewhere on
    the page. Adding the fourth state made the regression draw a grey dotted
    outline instead of a hatch, and the "some link somewhere" clause stayed true
    while the newest column lost its own — so the guard went silent on exactly
    the failure it was written for. That is the pattern CLAUDE.md names: an
    assertion on the presence of a marker instead of on the decision taken.
    """
    earliest = now - timedelta(days=40)
    db = StubDB(
        rollup_earliest=earliest,
        rollup_latest=reports.truncate(now, "hour", tz_name=TZ),
        raw_from=(now - timedelta(days=25)).date(),
        installed=now - timedelta(days=60),
        event_rows=_event_rows(earliest, now),
    )
    with _client(db, now=now) as c:
        body = c.get(f"/reports?bucket={bucket}").text

    newest = reports.truncate(now, reports.BUCKETS[bucket].unit, tz_name=TZ)
    anchor = f'<a href="{_events_drill_href(bucket, newest, "nginx")}">'
    rect = _rect_after(body, anchor)

    assert rect is not None, (
        f"the newest {bucket} bucket ({newest.isoformat()}) has no drill-down "
        "link wrapping a bar of its own")
    assert "rep-seg" in rect.get("class", ""), (
        f"the newest bucket is drawn as {rect.get('class')!r}, not as a bar")
    assert float(rect["height"]) > 0.5, f"the newest bar has height {rect['height']}"

    # And the header total is the sum of what is actually drawn — the observable
    # symptom on the live host was 4800 in the header over 4700 of bars.
    import re
    drawn = sum(int(m) for m in re.findall(r"<title>[^<]*: (\d+)", body))
    headers = [int(m) for m in re.findall(r"(\d+) în total", body)]
    assert headers and drawn == sum(headers), f"{drawn} drawn vs {headers} in headers"


# Deliberately years away from any plausible wall clock. The first version of
# the test below used the ordinary fixture moment and PASSED under a mutation
# that put `datetime.now()` back in the handler — because the sandbox clock
# happened to sit in the same hour of the same day. A guard whose verdict can
# coincide with the thing it is guarding against is not a guard.
FAR_FUTURE = datetime(2031, 3, 2, 6, 37, 12, tzinfo=timezone.utc)


def test_the_page_renders_against_the_injected_clock_not_the_wall_clock():
    """`now_utc` is a dependency so the handler and the test agree on one
    instant. A handler that reads `datetime.now()` itself cannot be tested
    across a time boundary — the round-1 guards failed at random whenever the
    real clock crossed an hour between collection and the request, and an alarm
    that says "the blocker is back" 0.4% of the time is an alarm nobody reads.

    Everything here is dated 2031, so a wall-clock read puts the chart's columns
    five years away from the stub's rows: no bar lands, no drill link is
    emitted, and the printed window is a date the machine's clock cannot
    produce.
    """
    earliest = FAR_FUTURE - timedelta(days=40)
    db = StubDB(rollup_earliest=earliest,
                rollup_latest=reports.truncate(FAR_FUTURE, "hour", tz_name=TZ),
                installed=FAR_FUTURE - timedelta(days=60),
                event_rows=_event_rows(earliest, FAR_FUTURE))
    with _client(db, now=FAR_FUTURE) as c:
        body = c.get("/reports?bucket=hour").text

    # Rows landed in the charted span: the handler used the injected moment.
    assert "/reports/drill?" in body
    assert "2031" in body
    window_start = reports.truncate(FAR_FUTURE - timedelta(hours=24), "hour", tz_name=TZ)
    # Scrisa in fusul paginii, cu marcaj: fereastra numarata si ora citita de
    # operator trebuie sa fie acelasi lucru.
    assert f"{tz.fmt(window_start, '%d.%m %H:%M', tz_name=TZ)} → acum" in body


def test_a_bucket_the_rollup_has_not_reached_is_pending_not_deleted(stub):
    """The live state the verifier found at 07:35 UTC: `max(bucket)` was 06:00
    because the maintenance timer fired at 07:00:07, before any minute bucket
    for 07:00 existed. Nothing had been deleted — retention is 400 days — yet
    the newest column was hatched "fără date păstrate".

    A hatch that shows up at the right-hand edge most hours is a hatch the
    operator learns to skip, and it is the only mark that says a month really
    was dropped."""
    _set_rollup(stub, earliest=NOW - timedelta(days=40),
                latest=reports.truncate(NOW, "hour", tz_name=TZ) - timedelta(hours=1))
    with _client(stub) as c:
        body = c.get("/reports?bucket=hour").text
    assert "încă neagregat" in body
    assert "fără date păstrate" not in body
    assert "url(#hatch-" not in body
    assert 'class="rep-pending"' in body


def test_a_deleted_month_still_gets_the_loud_hatch(stub):
    """The other side: the hatch has to keep firing where it means something."""
    _set_rollup(stub, earliest=NOW - timedelta(days=3),
                latest=reports.truncate(NOW, "hour", tz_name=TZ))
    with _client(stub) as c:
        body = c.get("/reports?bucket=day").text
    assert "fără date păstrate" in body
    assert "url(#hatch-" in body


def test_the_page_states_where_the_raw_detail_starts(stub):
    """The drill-down can only reach as far back as the surviving partitions.
    Saying so up front stops "no events" from being read as a finding."""
    with _client(stub) as c:
        body = c.get("/reports").text
    assert "Detaliul brut" in body


def test_unknown_raw_coverage_is_stated_as_unknown(stub):
    """If the catalog query cannot answer, the page says "necunoscut" rather
    than picking a date."""
    stub.vals["pg_inherits"] = None
    with _client(stub) as c:
        body = c.get("/reports").text
    assert "detaliul brut: necunoscut" in body


# ---------------------------------------------------------------------------
# Selectors
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bucket", sorted(reports.BUCKETS))
def test_every_offered_bucket_renders(stub, bucket):
    """The selector lists them, so every one must work — including `year`,
    whose span reaches past retention on purpose."""
    with _client(stub) as c:
        r = c.get(f"/reports?bucket={bucket}")
    assert r.status_code == 200, bucket
    assert reports.BUCKETS[bucket].label in r.text


@pytest.mark.parametrize("window", sorted(reports.WINDOWS))
def test_every_offered_window_renders(stub, window):
    with _client(stub) as c:
        r = c.get(f"/reports?window={window}")
    assert r.status_code == 200


def test_a_window_wider_than_the_data_is_flagged_on_the_card_itself(stub):
    """On the live host "7z" and "30z" printed the same number, because only
    5.8 days of rollup exist. The caveat has to sit next to the figure: a
    paragraph elsewhere on the page is not read at the same moment."""
    _set_rollup(stub, earliest=NOW - timedelta(days=5, hours=19),
                latest=reports.truncate(NOW, "hour", tz_name=TZ))
    with _client(stub) as c:
        wide = c.get("/reports?window=30z").text
        narrow = c.get("/reports?window=24h").text

    # Attached to the figure, not merely present somewhere on the page — that
    # distinction IS the finding. Each chunk runs from one KPI label to the
    # next, so a caveat that drifted to another card falls outside it.
    events = _kpi_cards(wide).get("Evenimente")
    assert events is not None, "the Evenimente KPI card disappeared"
    assert "acoperă doar" in events
    assert "5.8 z din 30 z" in events
    # And absent where it does not apply, or it becomes wallpaper.
    assert "acoperă doar" not in narrow


def test_the_page_prints_the_exact_window_it_counted(stub):
    """"Ultimele 24h" is rounded to whole hours because the aggregate is hourly.
    Printing the interval is what keeps the rounding from being a silent
    difference between the label and the number."""
    with _client(stub) as c:
        body = c.get("/reports?window=24h").text
    expected = reports.truncate(NOW - timedelta(hours=24), "hour", tz_name=TZ)
    assert f"{tz.fmt(expected, '%d.%m %H:%M', tz_name=TZ)} → acum" in body


def test_the_stylesheet_link_is_versioned_by_content(stub):
    """THE round-2 blocker. nginx serves `/static/` with `expires 7d` and
    `Cache-Control: public, immutable`, and `immutable` means Firefox will not
    revalidate even on an explicit reload. An unversioned href therefore keeps
    a pre-deploy stylesheet for a week — and every chart on this page gets its
    colours only from CSS classes, because the CSP forbids inline style. Against
    a stale sheet the bars have no `fill` (black on a near-black card) and the
    axis lines have no `stroke`: five empty strips, no console error, exactly
    the "row of nothing that looks like no data" the SVG approach was chosen to
    avoid — arriving through the HTTP cache instead of the CSP."""
    from sentinel.web.jinja import STATIC_DIR, asset_digest

    with _client(stub) as c:
        body = c.get("/reports").text
    expected = asset_digest(STATIC_DIR / "css" / "sentinel.css")
    assert expected, "the stylesheet could not be hashed"
    assert f'href="/static/css/sentinel.css?v={expected}"' in body
    assert 'href="/static/css/sentinel.css"' not in body


def test_a_partly_covered_empty_chart_counts_the_real_zeros(stub):
    """The normal state of a young install, and the branch that was missing.
    "Patch-uri pe stare" with 11 covered days and 19 older ones said "intervalul
    nu e acoperit de datele păstrate" — blaming retention for a real zero. The
    actionable fact is "no patch applied in the 10 days we have", not "data
    missing". On a `year` chart two columns stay uncovered for another two
    years, so every live-but-empty table was getting the wrong sentence."""
    # Sentinel installed 11 days ago; patch_executions therefore has nothing
    # before that, and the 30-day chart is 11 covered days + 19 unknown ones.
    stub.vals["schema_version"] = NOW - timedelta(days=11)
    stub.lists["FROM patch_executions"] = []
    with _client(stub) as c:
        body = c.get("/reports?bucket=day").text
    assert "zero înseamnă chiar zero" in body
    assert "mai vechi decât datele păstrate" in body
    # And the blanket "nothing is covered" sentence must NOT be used here.
    assert "nu se poate spune nimic despre ele" not in body


def test_a_chart_with_no_coverage_at_all_says_so_plainly(stub):
    """The other end of the same branch: when nothing is covered there is no
    real zero to report, and claiming one would be the opposite lie."""
    _set_rollup(stub, earliest=None, latest=None)
    stub.vals["schema_version"] = None
    with _client(stub) as c:
        body = c.get("/reports?bucket=day").text
    assert "nu se poate spune nimic despre ele" in body


def _empty_chart_counts(body: str) -> list[tuple[int, int]]:
    """(counted, total) for every empty-chart sentence on the page.

    `counted` is the sum of the numbers the sentence actually accounts for —
    covered, plus the older-than-retention clause, plus the not-yet-aggregated
    one. `total` is the column count it claims out of.
    """
    import re

    out = []
    for m in re.finditer(
            r"Zero în (\d+) din (\d+) intervale(.*?)</p>", body, re.S):
        counted = int(m.group(1))
        rest = m.group(3)
        for clause in (r"(\d+) sunt mai vechi decât datele păstrate",
                       r"(\d+) nu au fost agregate, iar datele din care",
                       r"(\d+) nu au fost încă agregate"):
            found = re.search(clause, rest)
            if found:
                counted += int(found.group(1))
        out.append((counted, int(m.group(2))))
    return out


def test_a_pending_column_is_never_described_as_full_coverage(stub):
    """On the live host at `bucket=hour` the page printed "the whole interval is
    covered" while the chart drew a pending column and the legend carried an
    "încă neagregat" entry — three statements on one card contradicting each
    other. The round-2 fix branched on `unknown_buckets`; the fourth state
    reopened the same hole one branch further along."""
    _set_rollup(stub, earliest=NOW - timedelta(days=40),
                latest=reports.truncate(NOW, "hour", tz_name=TZ) - timedelta(hours=1))
    stub.lists["COALESCE(source, '')"] = []
    with _client(stub) as c:
        body = c.get("/reports?bucket=hour").text
    assert "nu au fost încă agregate" in body
    assert "încă neagregat" in body                    # the legend agrees
    counts = _empty_chart_counts(body)
    assert counts, "no empty-chart sentence was rendered at all"
    for counted, total in counts:
        assert counted == total, f"sentence accounts for {counted} of {total} columns"


def test_the_empty_chart_sentence_accounts_for_every_column_drawn(stub):
    """A young install whose aggregation has also fallen behind: covered,
    deleted and not-yet-aggregated columns all at once. The round-2 wording said
    "Celelalte N", which implied a remainder — and the remainder was short by
    exactly the number of pending columns, on a page whose subject is honest
    counting."""
    _set_rollup(stub, earliest=NOW - timedelta(hours=20),
                latest=reports.truncate(NOW, "hour", tz_name=TZ) - timedelta(hours=5))
    stub.lists["COALESCE(source, '')"] = []
    with _client(stub) as c:
        body = c.get("/reports?bucket=hour").text
    assert "mai vechi decât datele păstrate" in body
    assert "nu au fost încă agregate" in body
    counts = _empty_chart_counts(body)
    assert counts
    for counted, total in counts:
        assert total == reports.BUCKETS["hour"].span
        assert counted == total, f"sentence accounts for {counted} of {total} columns"


def test_columns_past_the_minute_table_are_the_only_ones_called_final(stub):
    """The reproduced rollup outage, with the two lower stores at their real
    retentions: raw 30 days, minutes 90. The hourly rollup stalled 200 days
    back, so a month chart carries both kinds at once.

    Only the columns the MINUTE table cannot rebuild may be called final. The
    ones in the 30–90 day band have no raw detail — no list to click through to
    — but one repaired maintenance run refills the bar, and saying "nothing
    left" about them points at writing the period off instead of at restarting
    the timer.
    """
    minute_from = reports.truncate(NOW - timedelta(days=90), "day", tz_name=TZ)
    raw_from = reports.truncate(NOW - timedelta(days=25), "day", tz_name=TZ)
    _set_rollup(stub, earliest=NOW - timedelta(days=400),
                latest=reports.truncate(NOW - timedelta(days=200), "hour", tz_name=TZ))
    stub.vals["pg_inherits"] = raw_from.date()
    stub.vals["min(bucket) FROM event_rollup_1m"] = minute_from

    with _client(stub) as c:
        body = c.get("/reports?bucket=month").text

    starts = reports.bucket_starts("month", now=NOW, count=reports.BUCKETS["month"].span, tz_name=TZ)
    covered_to = reports.truncate(NOW - timedelta(days=200), "hour", tz_name=TZ) + timedelta(hours=1)
    blank = [s for s in starts if s >= covered_to]
    expect_missed = [s for s in blank
                     if reports.advance(s, "month", 1, tz_name=TZ) <= minute_from]
    expect_pending = [s for s in blank if s not in expect_missed]
    assert expect_missed and expect_pending, "the scenario produced only one kind"

    assert f"{len(expect_missed)} nu au fost agregate, iar datele din care s-ar fi" in body
    assert f"{len(expect_pending)} nu au fost încă agregate — se refac când" in body
    for counted, total in _empty_chart_counts(body):
        assert counted == total, f"sentence accounts for {counted} of {total}"

    # The summary makes no claim about raw detail: it is true for some pending
    # columns and false for others, and the per-column tooltip is where it is
    # checked.
    assert "detaliul brut încă există" not in body
    assert "nu a mai rămas nimic" in body                 # only for the final ones
    assert "se reface din tabela de minute" in body       # the recoverable ones

    # No column older than the raw edge offers a list of events.
    for s in blank:
        if reports.advance(s, "month", 1, tz_name=TZ) > raw_from:
            continue
        href = reports.drill_href(
            {"kind": "events", "dim": "source", "bucket": "month", "scope": "all"},
            start=s, value="").replace("&", "&amp;")
        assert f'<a href="{href}">' not in body, f"{s.isoformat()} offered a dead click"

    # Final columns are hatched; recoverable ones keep the "not yet" outline.
    assert body.count('fill="url(#hatch-') >= 2 * len(expect_missed)
    assert body.count('class="rep-pending"') == 2 * len(expect_pending)


def test_a_pending_column_offers_the_drill_down_it_promises(stub):
    """Its tooltip says the raw rows exist. `raw_events` can be read for exactly
    that bucket, so telling the operator the data is there and giving them no
    route to it is a worse answer than saying nothing."""
    pending_start = reports.truncate(NOW, "hour", tz_name=TZ)
    _set_rollup(stub, earliest=NOW - timedelta(days=40),
                latest=pending_start - timedelta(hours=1))
    stub.lists["COALESCE(source, '')"] = []
    with _client(stub) as c:
        body = c.get("/reports?bucket=hour").text

    expected = reports.drill_href(
        {"kind": "events", "dim": "source", "bucket": "hour", "scope": "all"},
        start=pending_start, value="").replace("&", "&amp;")
    anchor = f'<a href="{expected}">'
    rect = _rect_after(body, anchor)
    assert rect is not None, "the pending column carries no drill-down link"
    assert "rep-pending" in rect.get("class", "")

    # And the link it offers actually answers.
    stub.lists["_drill"] = [{
        "ts": NOW, "source": "nginx", "action": "request", "src_ip": "203.0.113.9",
        "username": None, "http_method": "GET", "http_path": "/x", "http_status": 200,
        "http_host": "example.com", "geo_country": "DE", "geo_asn": 64512,
        "process": None,
    }]
    with _client(stub) as c:
        r = c.get(expected.replace("&amp;", "&"))
    assert r.status_code == 200
    assert "toate categoriile" in r.text
    assert "203.0.113.9" in r.text


def test_the_all_categories_scope_is_refused_where_there_is_no_raw_table(stub):
    """Only events have a raw table to fall back on. Accepting `scope=all` for
    incidents or patches would answer a question with the wrong rows rather than
    refusing it."""
    from urllib.parse import urlencode

    start = reports.bucket_starts("day", now=NOW, count=30, tz_name=TZ)[-1]
    for kind, dim in (("incidents", "severity"), ("patches", "status")):
        url = "/reports/drill?" + urlencode(
            {"kind": kind, "dim": dim, "bucket": "day", "scope": "all",
             "value": "", "start": start.isoformat()})
        with _client(stub) as c:
            assert c.get(url).status_code == 400, kind


def test_an_unknown_scope_is_refused(stub):
    from urllib.parse import urlencode

    start = reports.bucket_starts("day", now=NOW, count=30, tz_name=TZ)[-1]
    url = "/reports/drill?" + urlencode(
        {"kind": "events", "dim": "source", "bucket": "day", "scope": "everything",
         "value": "nginx", "start": start.isoformat()})
    with _client(stub) as c:
        assert c.get(url).status_code == 400


def test_a_windowed_caveat_never_lands_under_an_as_of_now_figure(stub):
    """Round 1 was a missing warning; this is a warning in the wrong place, and
    that is how warnings become wallpaper. "Vulnerabilități deschise: 58" is a
    count as of now and complete — `overview()` deliberately does not window it.
    A block-level "acoperă doar 9.8 z din 30 z" under it reads as "58 is an
    undercount". It is not."""
    _set_rollup(stub, earliest=NOW - timedelta(days=9, hours=19),
                latest=reports.truncate(NOW, "hour", tz_name=TZ))
    stub.vals["schema_version"] = NOW - timedelta(days=9, hours=19)
    with _client(stub) as c:
        body = c.get("/reports?window=30z").text

    cards = _kpi_cards(body)
    for as_of_now in ("Incidente deschise", "Vulnerabilități deschise"):
        block = cards[as_of_now]
        assert "kpi-note-warn" not in block, f"{as_of_now} carries a block-level caveat"
        # The windowed sub-phrase still has to be qualified, inline.
        assert "cov-inline" in block, f"{as_of_now} lost the inline qualifier"
        assert "noi în 30z" in block
    # Where the headline figure IS the windowed one, the block-level note stays.
    assert "kpi-note-warn" in cards["Evenimente"]


def test_the_reports_page_carries_no_state_changing_form(stub):
    """The web tier never reaches the executor — a compromised dashboard is a
    disclosure, not a takeover. The only POST on this page is the sidebar's
    logout; the selector is a GET, which also means a report is bookmarkable and
    the back button works."""
    import re
    with _client(stub) as c:
        body = c.get("/reports").text
    forms = re.findall(r"<form[^>]*>", body)
    assert len(forms) == 2, forms
    assert [f for f in forms if 'method="post"' in f] == [
        '<form method="post" action="/logout" class="inline">']


def test_a_nonsense_selector_falls_back_instead_of_erroring(stub):
    """A stale bookmark or a probe must not produce a 500 on a security page."""
    with _client(stub) as c:
        r = c.get("/reports?bucket=../../etc&window=99y")
    assert r.status_code == 200
    assert reports.BUCKETS[reports.DEFAULT_BUCKET].label in r.text


# ---------------------------------------------------------------------------
# Drill-down
# ---------------------------------------------------------------------------
def _drill_url(kind: str, dim: str, value: str, bucket: str = "day", offset: int = -1) -> str:
    from urllib.parse import urlencode
    start = reports.bucket_starts(bucket, now=NOW, count=reports.BUCKETS[bucket].span, tz_name=TZ)[offset]
    return "/reports/drill?" + urlencode(
        {"kind": kind, "dim": dim, "bucket": bucket, "value": value,
         "start": start.isoformat()})


def test_drilling_into_incidents_lists_them_and_links_each_one(stub):
    """The point of the whole feature: a bar leads to the rows behind it, and
    each row leads to the incident."""
    stub.lists["_drill"] = [{
        "id": 42, "severity": "high", "status": "open", "title": "Brute-force SSH",
        "actor_key": "203.0.113.9", "detection_count": 7,
        "first_detection_at": NOW, "last_detection_at": NOW,
    }]
    with _client(stub) as c:
        r = c.get(_drill_url("incidents", "severity", "high"))
    assert r.status_code == 200
    assert 'href="/incidents/42"' in r.text
    assert "Brute-force SSH" in r.text


def test_drilling_into_patches_links_the_plan(stub):
    stub.lists["_drill"] = [{
        "id": 3, "plan_id": 11, "status": "failed", "started_at": NOW,
        "duration_ms": 4200, "post_verification_passed": False,
        "rollback_reason": "health check a picat", "error": None,
        "risk_level": "medium", "asset_name": "nginx",
    }]
    with _client(stub) as c:
        r = c.get(_drill_url("patches", "status", "failed"))
    assert r.status_code == 200
    assert 'href="/patches/11"' in r.text
    assert "health check a picat" in r.text


def test_attacker_controlled_text_in_the_drill_down_is_escaped(stub):
    """Paths and usernames come off the wire. Jinja autoescaping is what keeps a
    crafted path from executing in the operator's browser — and this page is
    read precisely when someone is investigating a crafted path."""
    stub.lists["_drill"] = [{
        "ts": NOW, "source": "nginx", "action": "request", "src_ip": "203.0.113.9",
        "username": None, "http_method": "GET",
        "http_path": "/<script>alert(1)</script>", "http_status": 404,
        "http_host": "example.com", "geo_country": "DE", "geo_asn": 64512,
        "process": None,
    }]
    with _client(stub) as c:
        body = c.get(_drill_url("events", "source", "nginx", bucket="hour")).text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_an_unknown_breakdown_is_refused(stub):
    """The breakdown name is interpolated into SQL as an identifier. Anything
    outside the whitelist must be refused before it gets near the statement."""
    with _client(stub) as c:
        r = c.get(_drill_url("events", "source; DROP TABLE raw_events", "nginx"))
    assert r.status_code == 400


def test_an_unknown_category_value_is_refused_not_answered_with_an_empty_table(stub):
    """Answering a made-up source with "0 events" presents a guess as a fact."""
    with _client(stub) as c:
        r = c.get(_drill_url("events", "source", "not-a-collector"))
    assert r.status_code == 400


def test_a_start_that_is_not_a_bucket_boundary_is_refused(stub):
    """Without this, a hand-written query string picks its own range, and a
    five-year window over `raw_events` becomes a scan competing with detection
    for the same database."""
    from urllib.parse import urlencode
    odd = (reports.truncate(NOW, "day", tz_name=TZ) + timedelta(minutes=7)).isoformat()
    url = "/reports/drill?" + urlencode(
        {"kind": "events", "dim": "source", "bucket": "day", "value": "nginx",
         "start": odd})
    with _client(stub) as c:
        assert c.get(url).status_code == 400


def test_a_start_outside_the_charted_span_is_refused(stub):
    """A link from a chart that has since scrolled past that bucket. Refusing is
    what keeps the span, and therefore the query cost, bounded."""
    from urllib.parse import urlencode
    old = reports.truncate(NOW - timedelta(days=400), "day", tz_name=TZ).isoformat()
    url = "/reports/drill?" + urlencode(
        {"kind": "events", "dim": "source", "bucket": "day", "value": "nginx",
         "start": old})
    with _client(stub) as c:
        assert c.get(url).status_code == 400


def test_an_unparseable_start_is_refused(stub):
    with _client(stub) as c:
        r = c.get("/reports/drill?kind=events&dim=source&bucket=day&value=nginx&start=nope")
    assert r.status_code == 400


def test_drilling_a_long_bucket_says_which_window_it_actually_read(stub):
    """A year bucket is clamped before it reaches `raw_events`. The page must
    not present the tail of the year as if it were the whole year."""
    with _client(stub) as c:
        body = c.get(_drill_url("events", "source", "nginx", bucket="year")).text
    assert "S-a citit doar o parte din interval" in body
    assert "Fereastra citită efectiv" in body
    assert "fereastra maximă de detaliu" in body      # the cap, not retention


def _render_drill(**over):
    """The drill template on its own, so the two narrowing reasons can be driven
    at exact values. Through the app's own environment factory — a template
    rendered under different globals is a template that has not been tested."""
    from sentinel.web.jinja import build_env

    ctx = {
        "user": type("U", (), {"username": "operator", "role": "owner"})(),
        "csrf_token": "t", "active": "reports", "kind": "events", "dim": "source",
        "tz_name": TZ,
        "value": "nginx", "value_label": "nginx", "bucket": "month",
        "spec": reports.BUCKETS["month"],
        "bucket_from": datetime(2026, 8, 1, tzinfo=timezone.utc),
        "bucket_to": datetime(2026, 9, 1, tzinfo=timezone.utc),
        "raw_from": datetime(2026, 8, 25, tzinfo=timezone.utc),
        "rows": [], "limit": 200, "at_limit": False,
        "severity_ro": {}, "exec_status_ro": {}, "back": "/reports?bucket=month",
    }
    ctx.update(over)
    return build_env(TZ).get_template("report_drill.html").render(**ctx)


def test_a_window_narrowed_by_retention_does_not_blame_the_cap():
    """The two reasons have different remedies: a cap is fixed by choosing a
    smaller bucket, deleted partitions are not fixed at all. Telling someone to
    "choose a smaller bucket" for a month retention has already erased sends
    them looking for data that no longer exists.

    This is the branch that could not fire at all before: `truncated` was
    computed before retention was applied, so when the oldest partition fell
    inside the capped tail the window narrowed with no flag set."""
    html = _render_drill(window=reports.RawWindow(
        start=datetime(2026, 8, 25, tzinfo=timezone.utc),
        end=datetime(2026, 9, 1, tzinfo=timezone.utc),
        expired=False, capped=False, trimmed=True))
    assert "S-a citit doar o parte din interval" in html
    assert "ștearsă de retenție" in html
    assert "fereastra maximă de detaliu" not in html
    assert "alege un bucket mai mic" not in html
    # Momentul e absolut; scris in fusul paginii, 00:00 UTC e 03:00 la Bucuresti.
    # Asertiunea trece prin aceeasi functie ca sablonul, ca sa nu ramana un sir
    # care mai spune „00:00" dupa ce pagina a inceput sa scrie altceva.
    assert tz.fmt(datetime(2026, 8, 25, tzinfo=timezone.utc), "%d.%m.%Y %H:%M",
                  tz_name=TZ, with_zone=False) in html


def test_a_window_narrowed_only_by_the_cap_says_so_and_offers_the_remedy():
    html = _render_drill(window=reports.RawWindow(
        start=datetime(2026, 8, 30, tzinfo=timezone.utc),
        end=datetime(2026, 9, 1, tzinfo=timezone.utc),
        expired=False, capped=True, trimmed=False))
    assert "fereastra maximă de detaliu" in html
    assert "alege un bucket mai mic" in html
    assert "ștearsă de retenție" not in html


def test_a_window_that_was_not_narrowed_says_nothing_at_all():
    """The notice must be absent when it does not apply, or the operator learns
    to skip it."""
    html = _render_drill(window=reports.RawWindow(
        start=datetime(2026, 8, 1, tzinfo=timezone.utc),
        end=datetime(2026, 9, 1, tzinfo=timezone.utc),
        expired=False, capped=False, trimmed=False))
    assert "S-a citit doar o parte din interval" not in html


def test_drilling_a_bucket_whose_detail_expired_says_so(stub):
    """`raw_events` partitions are dropped on retention. An empty table there is
    "we deleted it", not "nothing happened", and the aggregate above still
    stands."""
    stub.vals["pg_inherits"] = date.today()      # nothing older than today survives
    with _client(stub) as c:
        body = c.get(_drill_url("events", "source", "nginx",
                                bucket="month", offset=0)).text
    assert "nu mai există" in body
    assert "Agregatul din grafic rămâne corect" in body


def test_an_expired_drill_down_reads_nothing_at_all(stub):
    """Saying "expired" while still running the query would keep the cost the
    check was meant to avoid."""
    stub.vals["pg_inherits"] = date.today()
    with _client(stub) as c:
        c.get(_drill_url("events", "source", "nginx", bucket="month", offset=0))
    assert not any("FROM raw_events" in s for s in stub.sql)


def test_the_drill_down_offers_no_way_to_change_anything(stub):
    """The web tier never reaches the executor. A report page that grew a button
    would be the first crack in that."""
    stub.lists["_drill"] = [{
        "id": 42, "severity": "high", "status": "open", "title": "x",
        "actor_key": None, "detection_count": 1,
        "first_detection_at": NOW, "last_detection_at": NOW,
    }]
    import re
    with _client(stub) as c:
        body = c.get(_drill_url("incidents", "severity", "high")).text
    # The sidebar's logout form is the only one allowed on the page.
    assert re.findall(r"<form[^>]*>", body) == [
        '<form method="post" action="/logout" class="inline">']
    assert "<button" not in body.replace(
        '<button type="submit" class="btn btn-quiet btn-sm btn-block">Ieșire</button>', "")


# ---------------------------------------------------------------------------
# Fusul: ajunge in SQL, si ajunge ca parametru
# ---------------------------------------------------------------------------
def test_the_page_binds_the_configured_zone_as_a_query_parameter(stub):
    """Fusul configurat trebuie sa ajunga chiar la baza, nu doar in etichete.

    Doua feluri de a livra o pagina care minte, amandoua verzi la un test de
    text: alinierea ramasa in UTC in timp ce etichetele sunt scrise local (bare
    decalate cu trei ore fata de propriile lor nume), sau numele zonei scris in
    textul instructiunii in loc sa fie legat. Aici se citeste valoarea legata.
    """
    with _client(stub) as c:
        assert c.get("/reports?bucket=day").status_code == 200
    bucketed = [(sql, a) for sql, a in stub.calls if "date_trunc(" in sql]
    assert len(bucketed) >= 3, f"doar {len(bucketed)} interogari cu date_trunc"
    for sql, a in bucketed:
        assert "AT TIME ZONE $2::text" in sql, f"zona nu e legata: {sql}"
        assert a[0] == "day" and a[1] == TZ, f"unitatea/zona legate gresit: {a[:2]}"


def test_the_hourly_chart_stays_aligned_in_utc(stub):
    """Decizia din `align_zone`, verificata pe drumul real.

    Ora nu se aliniaza in fusul configurat: in noaptea in care ceasul da inapoi
    exista doua ore locale „03:00", iar `GROUP BY` le-ar uni intr-o coloana si ar
    lasa vecina un zero care nu e zero.
    """
    with _client(stub) as c:
        assert c.get("/reports?bucket=hour").status_code == 200
    bucketed = [a for sql, a in stub.calls if "date_trunc(" in sql]
    assert bucketed, "nicio interogare cu date_trunc"
    for a in bucketed:
        assert a[0] == "hour" and a[1] == "UTC", f"ora aliniata in {a[1]!r}"


def test_the_page_says_which_zone_its_intervals_are_aligned_in(stub):
    """Cifra citita azi nu are voie sa fie comparata tacut cu una de ieri.

    Intervalele s-au mutat din UTC in fusul configurat, deci fiecare interval
    istoric s-a deplasat o data. Fara ca pagina sa spuna in ce fus e, operatorul
    ar pune „evenimente pe 27.08" de azi langa cifra notata saptamana trecuta si
    ar cauta o cauza pentru o diferenta care vine din alta margine de zi.

    Numele zonei, nu marcajul: `EEST` e adevarat doar jumatate de an, iar un
    grafic pe 30 de zile poate trece peste schimbarea ceasului.
    """
    with _client(stub) as c:
        body = c.get("/reports").text
    assert TZ in body, (
        f"pagina nu numeste fusul ({TZ}) in care isi aliniaza intervalele")
    # Si spune ca s-a mutat, o data, ca cifrele vechi sa nu fie comparate orbeste.
    assert "nu în UTC" in body


def test_the_reports_page_never_leaves_the_zone_to_the_default():
    """`analytics/reports.py` are fus IMPLICIT — depozitarea, UTC.

    Implicitul exista ca o functie chemata fara fus sa dea acelasi raspuns pe
    orice masina, nu ca sa fie folosit de pagina. Un apel din router care il
    uita ar desena o coloana aliniata in UTC langa una aliniata local, fara nimic
    care s-o spuna. Lista functiilor e DERIVATA din semnaturi, nu scrisa de mana:
    una noua cu `tz_name` intra automat sub garda.
    """
    import ast
    import inspect

    cu_fus = {name for name, fn in vars(reports).items()
              if inspect.isfunction(fn)
              and "tz_name" in inspect.signature(fn).parameters}
    assert len(cu_fus) >= 8, f"doar {sorted(cu_fus)} functii cu `tz_name` — scanarea e rupta"

    ruta = pathlib.Path(reports.__file__).parents[1] / "web" / "routers" / "reports.py"
    arbore = ast.parse(ruta.read_text(encoding="utf-8"))

    vazute = 0
    for nod in ast.walk(arbore):
        if not isinstance(nod, ast.Call) or not isinstance(nod.func, ast.Attribute):
            continue
        tinta = nod.func
        if not (isinstance(tinta.value, ast.Name) and tinta.value.id == "reports"):
            continue
        if tinta.attr not in cu_fus:
            continue
        vazute += 1
        assert any(k.arg == "tz_name" for k in nod.keywords), (
            f"`reports.{tinta.attr}` chemata din pagina fara `tz_name`, la linia "
            f"{nod.lineno} — ar alinia in UTC in timp ce restul paginii e local")
    assert vazute >= 6, (
        f"doar {vazute} apeluri gasite in {ruta.name}; expresia de cautare e "
        "rupta si garda s-ar sari in tacere")
