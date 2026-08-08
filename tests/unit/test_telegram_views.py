"""The dashboard, on a phone.

These commands render database rows into `parse_mode=HTML` messages. Almost
every field they touch — HTTP paths, usernames, user agents, IDS signature
names — is written by whoever is attacking the host, so the tests that matter
most here are the escaping ones.

The rest is about the three ways a chat message is not a web page: it has a hard
length limit, it has no columns, and it has no scrollbar.
"""
from __future__ import annotations

import asyncio
import inspect
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.telegram import views  # noqa: E402

NOW = datetime(2026, 8, 4, 12, 34, 56, tzinfo=timezone.utc)


class _Msg:
    def __init__(self):
        self.sent: list[str] = []

    async def reply_text(self, text, **kw):
        self.sent.append(text)


def _update():
    msg = _Msg()
    return SimpleNamespace(effective_message=msg, message=msg), msg


def _ctx(db, args=None):
    return SimpleNamespace(bot_data={"db": db, "cfg": SimpleNamespace()}, args=args or [])


def run(c):
    return asyncio.run(c)


# --- escaping ---------------------------------------------------------------
def test_an_http_path_cannot_inject_markup():
    """A request path is chosen entirely by the client. The alert is HTML."""
    line = views._format_event(
        {"ts": NOW, "source": "nginx", "action": "http",
         "src_ip": "203.0.113.9", "http_method": "GET",
         "http_path": "/<img src=x onerror=alert(1)>", "http_status": 404},
        with_ip=True)
    assert "<img" not in line
    assert "&lt;img" in line


def test_a_username_cannot_inject_markup():
    line = views._format_event(
        {"ts": NOW, "source": "sshd", "action": "auth_fail",
         "src_ip": "203.0.113.9", "username": "<b>root</b>"},
        with_ip=True)
    assert "<b>root</b>" not in line
    assert "&lt;b&gt;root" in line


def test_a_long_path_is_truncated_before_escaping():
    """Truncating after escaping can cut `&lt;` in half and leave `&l` — broken
    markup that Telegram rejects, turning one hostile request into a message
    that never arrives."""
    line = views._format_event(
        {"ts": NOW, "source": "nginx", "action": "http", "src_ip": "203.0.113.9",
         "http_method": "GET", "http_path": "<" * 200},
        with_ip=True)
    assert "&l;" not in line and "&" not in line.replace("&lt;", "")


def test_esc_handles_missing_values():
    assert views.esc(None) == "—"
    assert views.esc(0) == "0"


# --- the length limit -------------------------------------------------------
def test_a_long_list_is_cut_and_says_so():
    """Silently truncating is how an operator concludes there were four
    attackers when there were forty."""
    out = views.clamp([f"rând {i} " + "x" * 80 for i in range(200)])
    assert len(out) <= 4096
    assert "listă scurtată" in out
    assert "rânduri" in out


def test_a_short_list_is_untouched():
    out = views.clamp(["unu", "doi"])
    assert out == "unu\ndoi"
    assert "scurtată" not in out


def test_the_tail_survives_truncation():
    """The closing hint is the one line worth keeping when everything else is
    cut — it says what to type next."""
    out = views.clamp(["x" * 200 for _ in range(100)], tail="/ajutor")
    assert out.endswith("/ajutor")


# --- dashboard --------------------------------------------------------------
class _DashDB:
    """Enough of a database for the dashboard, with nothing in it."""

    async def fetchrow(self, *a, **k):
        return {"atacatori": 0, "ev": 0}

    async def fetchval(self, *a, **k):
        return 0

    async def fetch(self, *a, **k):
        return []

    async def healthy(self):
        return True


def test_dashboard_leads_with_the_verdict(monkeypatch):
    """Someone reading this at 3 a.m. should be able to stop after line one."""
    monkeypatch.setattr(views.insights_mod, "collect", _async([]))
    monkeypatch.setattr(views.insights_mod, "posture", _async(
        {"level": "good", "verdict": "Nimic de semnalat", "atacatori": 0,
         "evenimente": 0, "critice": 0, "avertismente": 0, "intruziuni": 0}))
    monkeypatch.setattr(views.aggregate, "kpis", _async(_KPI))
    monkeypatch.setattr(views.aggregate, "deltas", _async({}))
    monkeypatch.setattr(views.aggregate, "service_health", _async({"up": 3}))
    monkeypatch.setattr(views.aggregate, "top_attackers", _async([]))
    monkeypatch.setattr(views.aggregate, "by_country", _async([]))

    upd, msg = _update()
    run(views.cmd_dashboard(upd, _ctx(_DashDB())))
    first = msg.sent[0].splitlines()[0]
    assert "Nimic de semnalat" in first


def test_dashboard_shows_only_insights_worth_colouring(monkeypatch):
    """A phone has no room for the "everything is fine" cards, and reading them
    trains you to skim past the ones that matter."""
    from sentinel.analytics.insights import Insight

    found = [Insight("good", "Totul bine", "d"), Insight("critical", "Ceva rău", "d", "fă X")]
    monkeypatch.setattr(views.insights_mod, "collect", _async(found))
    monkeypatch.setattr(views.insights_mod, "posture", _async(
        {"level": "critical", "verdict": "Necesită atenție", "atacatori": 1,
         "evenimente": 9, "critice": 1, "avertismente": 0, "intruziuni": 0}))
    monkeypatch.setattr(views.aggregate, "kpis", _async(_KPI))
    monkeypatch.setattr(views.aggregate, "deltas", _async({}))
    monkeypatch.setattr(views.aggregate, "service_health", _async({}))
    monkeypatch.setattr(views.aggregate, "top_attackers", _async([]))
    monkeypatch.setattr(views.aggregate, "by_country", _async([]))

    upd, msg = _update()
    run(views.cmd_dashboard(upd, _ctx(_DashDB())))
    assert "Ceva rău" in msg.sent[0]
    assert "Totul bine" not in msg.sent[0]
    assert "fă X" in msg.sent[0]


_KPI = {"evenimente_24h": 10, "ostile_24h": 5, "atacatori_24h": 2,
        "incidente_deschise": 1, "incidente_grave": 0, "vuln_deschise": 0,
        "vuln_kev": 0, "blocate": 0}


def _async(value):
    async def _f(*a, **k):
        return value
    return _f


# --- vulnerabilities --------------------------------------------------------
_FINDING = {
    "id": 42, "cve": "CVE-2026-9538", "advisory_id": None,
    "title": "perl-Archive-Tar security update", "severity": "high",
    "cvss": 7.5, "epss": 0.12, "kev": False, "priority": 61,
    "package": "perl-Archive-Tar", "installed_version": "2.38-5",
    "fixed_version": "2.38-6.el9_8.2", "scanner": "dnf", "location": None,
    "status": "open", "last_seen": NOW, "asset_name": None,
}


def test_vulns_links_every_cve(monkeypatch):
    monkeypatch.setattr(views.findings_repo, "open_counts",
                        _async({"high": 1, "total": 1, "kev": 0}))
    monkeypatch.setattr(views.findings_repo, "list_open", _async([_FINDING]))
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None)))
    # dnf finding: Red Hat first, because backport status is the real question.
    assert "access.redhat.com/security/cve/CVE-2026-9538" in msg.sent[0]


def test_vulns_kev_filter_narrows(monkeypatch):
    rows = [_FINDING, {**_FINDING, "id": 43, "kev": True, "cve": "CVE-2021-44228"}]
    monkeypatch.setattr(views.findings_repo, "open_counts",
                        _async({"high": 2, "total": 2, "kev": 1}))
    monkeypatch.setattr(views.findings_repo, "list_open", _async(rows))
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None, ["kev"])))
    assert "#43" in msg.sent[0] and "#42" not in msg.sent[0]


def test_no_vulnerabilities_is_reported_as_good_news(monkeypatch):
    monkeypatch.setattr(views.findings_repo, "open_counts", _async({"total": 0}))
    monkeypatch.setattr(views.findings_repo, "list_open", _async([]))
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None)))
    assert "✅" in msg.sent[0] and "niciuna" in msg.sent[0]


def test_a_finding_without_a_fix_does_not_offer_a_patch_plan(monkeypatch):
    """The planner refuses these anyway; offering the command would spend a
    model call to be told no."""
    monkeypatch.setattr(views.findings_repo, "list_open",
                        _async([{**_FINDING, "fixed_version": None}]))
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, ["42"])))
    assert "/patch 42" not in msg.sent[0]
    assert "nu se poate genera" in msg.sent[0]


def test_vuln_detail_carries_all_three_sources(monkeypatch):
    monkeypatch.setattr(views.findings_repo, "list_open",
                        _async([{**_FINDING, "kev": True}]))
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, ["42"])))
    text = msg.sent[0]
    assert "access.redhat.com" in text and "nvd.nist.gov" in text and "cisa.gov" in text


def test_vuln_without_an_id_explains_itself(monkeypatch):
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, [])))
    assert "/vuln" in msg.sent[0]


# --- events -----------------------------------------------------------------
def test_events_filtered_by_ip_offers_the_block_command(monkeypatch):
    monkeypatch.setattr(views.events_repo, "summary", _async({"total": 0}))
    monkeypatch.setattr(views.events_repo, "recent", _async([
        {"ts": NOW, "source": "sshd", "action": "auth_fail",
         "src_ip": "203.0.113.9", "username": "root"}]))
    upd, msg = _update()
    run(views.cmd_events(upd, _ctx(None, ["203.0.113.9"])))
    assert "/block 203.0.113.9" in msg.sent[0]


def test_a_non_ip_argument_is_not_treated_as_a_filter(monkeypatch):
    """`/events '; DROP TABLE` must not reach a query as an address."""
    seen = {}

    async def _recent(db, **kw):
        seen.update(kw)
        return []

    monkeypatch.setattr(views.events_repo, "summary", _async({"total": 0}))
    monkeypatch.setattr(views.events_repo, "recent", _recent)
    upd, msg = _update()
    run(views.cmd_events(upd, _ctx(None, ["'; DROP TABLE raw_events --"])))
    assert seen["src_ip"] is None


@pytest.mark.parametrize("value,ok", [
    ("203.0.113.9", True), ("2001:db8::1", True),
    ("nu-i ip", False), ("", False), ("203.0.113.9; rm -rf /", False),
])
def test_ip_detection(value, ok):
    assert views._looks_like_ip(value) is ok


# --- registration -----------------------------------------------------------
def test_every_web_page_has_a_command():
    """The point of the exercise: nothing the dashboard shows should be
    reachable only from a browser."""
    from sentinel.telegram import bot

    src = inspect.getsource(bot.build_application)
    for name in ("dashboard", "incidente", "vulnerabilitati", "evenimente",
                 "servicii", "blocate", "patchuri"):
        assert f'"{name}"' in src, f"no command for {name}"


def test_commands_have_romanian_names():
    """The interface language is Romanian. `/incidents` working and
    `/incidente` not is the kind of detail that makes a tool feel foreign."""
    from sentinel.telegram import bot

    src = inspect.getsource(bot.build_application)
    for ro, en in (("incidente", "incidents"), ("servicii", "services"),
                   ("evenimente", "events"), ("rezolva", "resolve")):
        assert f'"{ro}"' in src and f'"{en}"' in src


def test_every_command_name_is_one_telegram_accepts():
    """Telegram allows [a-z0-9_] and 1-32 characters, and rejects the ENTIRE
    handler set if one name is invalid — so a single Romanian diacritic in an
    alias crash-loops the bot and takes down the emergency channel. That
    shipped: `vulnerabilități` stopped the service from starting at all."""
    import re

    from sentinel.telegram import bot

    src = inspect.getsource(bot.build_application)
    table = src[src.index("read_only = ["):src.index("# Inline confirm")]
    names = re.findall(r'\("([^"]+)"', table) + re.findall(r'"([^"]+)"\)', table)
    assert names, "no command names found — the extraction broke, not the code"
    for name in names:
        assert re.fullmatch(r"[a-z0-9_]{1,32}", name), \
            f"{name!r} is not a name Telegram will accept"


def test_help_lists_what_is_registered():
    """A help text that drifts from the handlers is worse than none."""
    from sentinel.telegram import bot

    registered = set(inspect.getsource(bot.build_application).split('"'))
    for line in views.HELP.splitlines():
        if not line.startswith("/"):
            continue
        name = line.split()[0].lstrip("/").split("&")[0].strip()
        assert name in registered, f"/{name} is in the help text but not registered"


def test_read_only_commands_are_separated_from_acting_ones():
    """Not cosmetic: the acting ones each re-check the operator role, and the
    split is what makes it obvious which ones must."""
    from sentinel.telegram import bot

    src = inspect.getsource(bot.build_application)
    assert "read_only = [" in src and "acting = [" in src

    # Felia se termină la linia care conține DOAR paranteza de închidere.
    #
    # Varianta anterioară tăia la primul `]` din text, deci un comentariu care
    # menționa `[a-z0-9_]` scurta lista la două intrări și testul cădea pentru
    # un cod perfect corect. Un test care se strică la un comentariu îl învață
    # pe următorul să nu comenteze.
    body = src.split("acting = [", 1)[1]
    acting = body.split("\n    ]", 1)[0]
    for name in ("block", "panic", "resolve"):
        assert f'"{name}"' in acting, f"/{name} nu mai e în lista care verifică rolul"
