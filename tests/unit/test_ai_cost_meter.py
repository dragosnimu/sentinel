"""The AI cost counter in the left sidebar: cost to date and number of runs.

The operator asked for "un contor cu costul AI generat la zi si nr de rulari" in the navigation
column. What goes wrong for them if this regresses:

* **"Unknown" shown as "$0.00".** If the read fails, a counter that prints zero tells the operator
  the model has cost nothing, which is the one thing they opened the page to check. The failure
  state is its own text, and the page still renders (a cost counter must not 500 the incident list).
* **Two meanings of "this month".** The spend cap (`budget.spent_month`) decides whether the next
  model call happens; the counter reports the same period. If their predicates drift, the sidebar
  says $12 while the cap, which acts on the other number, is already refusing calls.
* **The counter on some pages only.** It lives in `base.html` and its data comes from
  `current_user`, the dependency every authenticated page already takes. Pinned end to end through
  the real application: a request goes in, the sidebar comes out.
* **A cost that rounds the first call away.** One triage call costs about $0.003; at two decimals
  that is "$0.00", i.e. "the model was never used".

What is NOT proved here: that the SQL (`count(*) FILTER (WHERE ...)`, `date_trunc`) is accepted by
PostgreSQL and returns what the fake returns. There is no PostgreSQL in this suite; the statement
is read-only and was run by hand against the production schema's `ai_usage` columns (see the report).
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

jinja2 = pytest.importorskip("jinja2")

from sentinel.ai import budget  # noqa: E402


def run(coro):
    return asyncio.run(coro)


class _FakeDB:
    def __init__(self, row=None, boom: Exception | None = None):
        self.row = row
        self.boom = boom
        self.sql: list[str] = []

    async def fetchrow(self, sql, *a):  # noqa: ANN001, ANN002, ANN202
        self.sql.append(sql)
        if self.boom:
            raise self.boom
        return self.row

    async def fetchval(self, sql, *a):  # noqa: ANN001, ANN002, ANN202
        self.sql.append(sql)
        return 0


ROW = {"runs": 813, "cost": "5.476300", "month_runs": 61, "month_cost": "0.193200"}


# ---------------------------------------------------------------- the numbers


def test_usage_totals_returns_numbers_not_driver_types():
    """asyncpg gives `numeric` as Decimal and counts as int; the template needs plain numbers.

    Eșecul pe care îl previne: `Decimal` ajunge în șablon, iar filtrul `usd` (sau o comparație)
    dă o eroare doar pe pagina reală, nu în teste cu valori simple.
    """
    from decimal import Decimal

    db = _FakeDB({"runs": 813, "cost": Decimal("5.476300"),
                  "month_runs": 61, "month_cost": Decimal("0.193200")})
    got = run(budget.usage_totals(db))
    assert got == {"runs": 813, "cost": 5.4763, "month_runs": 61, "month_cost": 0.1932}
    assert all(type(v) in (int, float) for v in got.values())


def test_the_counter_and_the_cap_use_the_same_month():
    """`spent_month` (the cap) and `usage_totals` (the counter) share ONE month predicate.

    Eșecul pe care îl previne: două predicate pentru „luna asta". Contorul ar arăta o sumă, iar
    plafonul — care decide dacă mai pleacă un apel — ar acționa pe alta.
    """
    db = _FakeDB(ROW)
    run(budget.usage_totals(db))
    run(budget.spent_month(db))
    totals_sql, cap_sql = db.sql[0], db.sql[1]
    assert budget.MONTH_START_SQL in totals_sql and budget.MONTH_START_SQL in cap_sql
    assert totals_sql.count(budget.MONTH_START_SQL) == 2, "runs and cost both use the month filter"
    assert "FROM ai_usage" in totals_sql


def test_the_month_predicate_is_the_start_of_the_calendar_month():
    """Fixează CE ESTE predicatul, nu doar că cele două apeluri îl împart.

    Eșecul pe care îl previne: `MONTH_START_SQL` devine `date_trunc('week', …)` (sau `'day'`,
    `'year'`) — cele două apeluri îl folosesc în continuare pe același, deci testul de mai sus
    rămâne verde — iar bara laterală scrie „luna aceasta" peste cheltuiala unei săptămâni, în timp
    ce plafonul lunar, care decide dacă mai pleacă un apel, se resetează luni. Etichetele „luna
    aceasta" din șabloane sunt promisiunea pe care predicatul trebuie s-o țină.
    """
    assert budget.MONTH_START_SQL == "date_trunc('month', CURRENT_DATE)"
    from pathlib import Path

    base = Path(__file__).resolve().parents[2] / "sentinel" / "web" / "templates" / "base.html"
    sidebar = base.read_text(encoding="utf-8")
    assert "luna aceasta" in sidebar, "positive control: the label this predicate answers for"


# ---------------------------------------------------------------- unknown is not zero


def test_a_failed_read_is_reported_as_unavailable_and_does_not_raise():
    """Eșecul pe care îl previne: contorul arată „$0.00" peste o bază care nu răspunde, sau
    excepția ajunge în pagină și lista de incidente dă 500 din cauza unui contor de cost."""
    from sentinel.web import deps

    got = run(deps.ai_usage_for_sidebar(_FakeDB(boom=RuntimeError("pool epuizat"))))
    assert got == {"ok": False}


def test_a_good_read_is_marked_ok_with_the_totals():
    from sentinel.web import deps

    got = run(deps.ai_usage_for_sidebar(_FakeDB(ROW)))
    assert got["ok"] is True and got["runs"] == 813 and got["month_runs"] == 61


# ---------------------------------------------------------------- the filters


@pytest.mark.parametrize("value,expected", [
    (None, "—"),            # unknown stays unknown
    (0, "$0.00"),           # a true zero
    (0.003, "<$0.01"),      # one triage call: must not round to "$0.00"
    (0.0049, "<$0.01"),
    (0.005, "$0.01"),
    (2.3174, "$2.32"),
    (5.4763, "$5.48"),
])
def test_usd_never_rounds_a_real_cost_down_to_zero(value, expected):
    from sentinel.web.jinja import usd_filter

    assert usd_filter(value) == expected


def test_pct01_keeps_a_missing_confidence_distinct_from_zero_percent():
    from sentinel.web.jinja import fraction_pct_filter

    assert fraction_pct_filter(None) == "—"
    assert fraction_pct_filter(0) == "0%"
    assert fraction_pct_filter(0.85) == "85%"
    assert fraction_pct_filter(0.6) == "60%"


# ---------------------------------------------------------------- the sidebar, rendered


def _page(ai_usage, *, with_request=True):
    from sentinel.web.jinja import build_env

    env = build_env("Europe/Bucharest")
    user = SimpleNamespace(username="op", role="owner")
    ctx = dict(user=user, active="incidents", csrf_token="t", version="1", rows=[],
               counts={"total": 0}, filter_status=None, sort="recent", sorts={}, status_ro={},
               can_act=False, msg=None, open_rules=[])
    if with_request:
        state = SimpleNamespace(**({"ai_usage": ai_usage} if ai_usage is not None else {}))
        ctx["request"] = SimpleNamespace(state=state, query_params={})
    return env.get_template("incidents.html").render(**ctx)


def _meter(html: str) -> str:
    m = re.search(r'<div class="ai-meter".*?</div>', html, flags=re.S)
    assert m, "the cost counter is not in the sidebar"
    return m.group(0)


def test_the_sidebar_shows_this_month_and_all_time_with_runs():
    """Eșecul pe care îl previne: contorul arată doar cost sau doar rulări, sau nu spune ce
    perioadă măsoară (operatorul ar compara „$0.19" cu „$5.48" fără să știe că sunt două luni)."""
    html = _page({"ok": True, "runs": 813, "cost": 5.4763, "month_runs": 61, "month_cost": 0.1932})
    side = html.split('<aside class="sidebar">')[1].split("</aside>")[0]
    meter = _meter(side)
    text = re.sub(r"<[^>]+>", " ", meter)
    text = " ".join(text.split())
    assert "$0.19" in text and "61 rulări" in text and "luna aceasta" in text
    assert "$5.48" in text and "813 rulări" in text and "de la început" in text
    assert "estimat" in text, "the figures are estimates from public pricing, not the invoice"


def test_the_sidebar_counter_uses_the_singular_for_one_run():
    html = _page({"ok": True, "runs": 1, "cost": 0.003, "month_runs": 1, "month_cost": 0.003})
    text = " ".join(re.sub(r"<[^>]+>", " ", _meter(html)).split())
    assert "1 rulare" in text and "1 rulări" not in text and "<$0.01" in text.replace("&lt;", "<")


def test_an_unreadable_counter_says_so_and_prints_no_dollar_figure():
    """Eșecul pe care îl previne: „$0.00" peste o citire eșuată."""
    html = _page({"ok": False})
    meter = _meter(html)
    assert "indisponibil" in meter
    assert "$" not in meter and "rulări" not in meter


def test_without_a_request_the_sidebar_has_no_counter_at_all():
    """A template rendered outside a request (the unit tests that render pages) must not crash or
    invent a counter."""
    html = _page(None, with_request=False)
    assert "ai-meter" not in html
    html2 = _page(None)  # a request whose state has no `ai_usage`
    assert "ai-meter" not in html2


def test_the_counter_lives_in_the_base_layout_once():
    """One place, so a new page cannot forget it."""
    from pathlib import Path

    templates = Path(__file__).resolve().parents[2] / "sentinel" / "web" / "templates"
    users = [p.name for p in templates.glob("*.html")
             if 'class="ai-meter"' in p.read_text(encoding="utf-8")]
    assert users == ["base.html"], users


# ---------------------------------------------------------------- end to end, through the real app


class _AppDB:
    """Enough of Database for an authenticated `/incidents` request through the real app."""

    def __init__(self, usage_row=None, usage_boom=None):
        self.usage_row, self.usage_boom = usage_row, usage_boom

    async def connect(self):  # noqa: ANN202
        return None

    async def close(self):  # noqa: ANN202
        return None

    async def healthy(self):  # noqa: ANN202
        return True

    async def size_bytes(self):  # noqa: ANN202
        return 1

    async def fetchval(self, sql, *a):  # noqa: ANN001, ANN002, ANN202
        return None

    async def fetchrow(self, sql, *a):  # noqa: ANN001, ANN002, ANN202
        if "FROM ai_usage" in sql:
            if self.usage_boom:
                raise self.usage_boom
            return self.usage_row
        return None

    async def fetch(self, sql, *a):  # noqa: ANN001, ANN002, ANN202
        return []

    async def execute(self, sql, *a):  # noqa: ANN001, ANN002, ANN202
        return "UPDATE 1"


def _authed_client(monkeypatch, db):
    from fastapi.testclient import TestClient

    from sentinel.config import Config, Secrets
    from sentinel.db.repo import sessions, users
    from sentinel.web import app as app_module
    from sentinel.web.security import COOKIE_NAME

    monkeypatch.setattr(app_module, "Database", lambda cfg: db)
    now = datetime.now(timezone.utc)
    session = sessions.Session(id="s1", user_id=1, pending_totp=False, csrf_token="c" * 16,
                               expires_at=now + timedelta(hours=1), created_at=now,
                               last_seen_at=now, ip="127.0.0.1")
    user = users.User(id=1, username="op", password_hash="x", password_algo="argon2",
                      totp_secret=None, totp_confirmed=True, totp_last_counter=None, role="owner",
                      failed_attempts=0, locked_until=None, disabled=False)

    async def get_by_token(_db, _token):  # noqa: ANN001, ANN202
        return session

    async def get_by_id(_db, _uid):  # noqa: ANN001, ANN202
        return user

    async def touch(_db, _sid):  # noqa: ANN001, ANN202
        return None

    monkeypatch.setattr(sessions, "get_by_token", get_by_token)
    monkeypatch.setattr(sessions, "touch", touch)
    monkeypatch.setattr(users, "get_by_id", get_by_id)
    cfg = Config()
    secrets = Secrets({"SENTINEL_SESSION_SECRET": "f" * 64})
    client = TestClient(app_module.create_app(cfg, secrets), base_url="https://testserver")
    client.cookies.set(COOKIE_NAME, "tok")
    return client


def test_a_real_request_to_an_authenticated_page_shows_the_counter(monkeypatch):
    """Eșecul pe care îl previne: contorul există în șablon, dar `current_user` nu-l hrănește (sau
    un router îl pierde), deci bara laterală e goală pe pagina reală. Se probează EFECTUL: o cerere
    prin aplicația adevărată, cu baza înlocuită, iese cu cifrele în bara laterală."""
    db = _AppDB(usage_row=ROW)
    with _authed_client(monkeypatch, db) as client:
        response = client.get("/incidents")
    assert response.status_code == 200
    text = " ".join(re.sub(r"<[^>]+>", " ", _meter(response.text)).split())
    assert "$0.19" in text and "61 rulări" in text and "$5.48" in text and "813 rulări" in text


def test_a_real_request_survives_a_broken_counter_and_says_unavailable(monkeypatch):
    db = _AppDB(usage_boom=RuntimeError("relation ai_usage does not exist"))
    with _authed_client(monkeypatch, db) as client:
        response = client.get("/incidents")
    assert response.status_code == 200, "a failing cost counter took the incident list down"
    meter = _meter(response.text)
    assert "indisponibil" in meter and "$" not in meter
