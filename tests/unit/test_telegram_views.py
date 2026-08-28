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
from datetime import datetime, timedelta, timezone
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
    # `timezone` e in configuratia reala si e citita de fiecare afisare de
    # ora; o fixtura fara ea ar fi testat un obiect pe care procesul nu-l are.
    return SimpleNamespace(
        bot_data={"db": db, "cfg": SimpleNamespace(timezone="Europe/Bucharest")},
        args=args or [])


def run(c):
    return asyncio.run(c)


# --- escaping ---------------------------------------------------------------
def test_an_http_path_cannot_inject_markup():
    """A request path is chosen entirely by the client. The alert is HTML."""
    line = views._format_event(
        {"ts": NOW, "source": "nginx", "action": "http",
         "src_ip": "203.0.113.9", "http_method": "GET",
         "http_path": "/<img src=x onerror=alert(1)>", "http_status": 404},
        with_ip=True, tz_name="UTC")
    assert "<img" not in line
    assert "&lt;img" in line


def test_a_username_cannot_inject_markup():
    line = views._format_event(
        {"ts": NOW, "source": "sshd", "action": "auth_fail",
         "src_ip": "203.0.113.9", "username": "<b>root</b>"},
        with_ip=True, tz_name="UTC")
    assert "<b>root</b>" not in line
    assert "&lt;b&gt;root" in line


def test_a_long_path_is_truncated_before_escaping():
    """Truncating after escaping can cut `&lt;` in half and leave `&l` — broken
    markup that Telegram rejects, turning one hostile request into a message
    that never arrives."""
    line = views._format_event(
        {"ts": NOW, "source": "nginx", "action": "http", "src_ip": "203.0.113.9",
         "http_method": "GET", "http_path": "<" * 200},
        with_ip=True, tz_name="UTC")
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


# --- autoverificare ---------------------------------------------------------
# Panoul spunea „33 verificări" din `selfcheck_runs` și desena linia roșie din
# `selfcheck_state`. Cele două tabele au divergat, iar cusătura vizibilă a fost
# 33 față de 34: un rând pe care nicio rulare nu-l mai producea de 26 de ore
# ținea antetul roșu peste 317 rulări verzi. Un ecran care se contrazice singur
# e mai rău decât unul care tace.
class _SelfcheckDB:
    def __init__(self, rows, *, checks_run=99, duration_ms=710, previous_run=None):
        self.rows = rows
        self.runs = [{"started_at": NOW, "worst_status": "ok",
                      "checks_run": checks_run, "checks_bad": 0,
                      "duration_ms": duration_ms}]
        if previous_run is not None:
            self.runs.append({"started_at": NOW, "worst_status": "ok",
                              "checks_run": previous_run, "checks_bad": 0,
                              "duration_ms": duration_ms})

    async def fetch(self, sql, *a):
        if "selfcheck_state" in sql:
            return self.rows
        return self.runs if "selfcheck_runs" in sql else []


def _state_row(key, status, title, *, stale=False, detail="", since=None):
    return {"key": key, "status": status, "title": title, "detail": detail,
            "since": since or NOW, "stale": stale}


def _selfcheck(rows, **kw):
    upd, msg = _update()
    run(views.cmd_selfcheck(upd, _ctx(_SelfcheckDB(rows, **kw))))
    return msg.sent[0]


def test_selfcheck_counts_the_rows_it_shows(monkeypatch):
    """Antetul și corpul trebuie să vină din același loc.

    Cu numărul luat din tabela de rulări și rândurile din tabela de stare, cele
    două pot spune lucruri diferite despre același moment — și au făcut-o timp
    de o zi și două ore, fără ca nimic să semnaleze diferența."""
    monkeypatch.setattr(views, "_now", lambda: NOW)
    rows = [_state_row(f"ok:{i}", "ok", f"Verificarea {i}") for i in range(34)]
    text = _selfcheck(rows, checks_run=33)
    assert "34 verificări" in text
    assert "33 verificări" not in text
    assert "În regulă (34)" in text


def test_a_check_that_could_not_look_is_not_reported_as_fine(monkeypatch):
    """Un rând `unknown` nu apărea nici la defecte, nici la „În regulă" — deci
    nu apărea deloc, iar operatorul citea un panou care nu-l pomenea. O
    verificare care n-a putut citi ce-i trebuie nu e o verificare trecută."""
    monkeypatch.setattr(views, "_now", lambda: NOW)
    text = _selfcheck([
        _state_row("ok:1", "ok", "Baza de date"),
        _state_row("nft:table", "unknown", "Nu pot citi regulile nftables",
                   detail="nu știu dacă blocarea funcționează sau nu"),
    ])
    assert "Nu pot citi regulile nftables" in text
    assert "nu tot s-a putut verifica" in text
    assert "Totul funcționează" not in text
    assert "În regulă (1)" in text


def test_an_old_row_says_its_age_is_the_age_of_the_finding(monkeypatch):
    """„de 27h 54m" lângă „🔴 Toate sursele au amuțit" se citește ca durata
    penei. Era vechimea unui rând pe care nimeni nu-l mai reevalua."""
    monkeypatch.setattr(views, "_now", lambda: NOW)
    old = NOW - timedelta(hours=27, minutes=54)
    text = _selfcheck([
        _state_row("ok:1", "ok", "Baza de date"),
        _state_row("ingest:all", "down", "Toate sursele au amuțit",
                   stale=True, since=old),
    ])
    assert "constatare veche de 27h 54m" in text
    assert "ultima constatare, nu starea de acum" in text
    assert "1 verificări · " in text and "1 neevaluate" in text


def test_an_empty_state_table_is_not_good_news(monkeypatch):
    """Zero rânduri înseamnă că nu se știe nimic, nu că e totul bine."""
    monkeypatch.setattr(views, "_now", lambda: NOW)
    text = _selfcheck([])
    assert "Nu știu dacă Sentinel funcționează" in text
    assert "Totul funcționează" not in text


def test_fewer_checks_than_last_time_is_said_out_loud(monkeypatch):
    """Acoperire pierdută în tăcere.

    O sursă care tace peste fereastra de 30 de zile a colectorului iese din
    interogare, iar dacă rândul ei era verde nimic nu anunță retragerea: panoul
    numără pur și simplu o verificare mai puțin decât ieri. Măsurat pe gazdă,
    `su` are un singur eveniment vechi de 7 zile — deci se întâmplă, cu dată
    cunoscută, dacă nimeni nu rulează `su`."""
    monkeypatch.setattr(views, "_now", lambda: NOW)
    rows = [_state_row(f"ok:{i}", "ok", f"Verificarea {i}") for i in range(32)]
    text = _selfcheck(rows, checks_run=32, previous_run=33)
    assert "cu 1 verificări mai puțin" in text
    assert "(33 → 32)" in text


def test_the_same_number_of_checks_says_nothing(monkeypatch):
    """Linia de mai sus apare doar când numărul chiar scade. O notă la fiecare
    rulare ar fi zgomot pe care operatorul învață să-l sară."""
    monkeypatch.setattr(views, "_now", lambda: NOW)
    rows = [_state_row(f"ok:{i}", "ok", f"Verificarea {i}") for i in range(33)]
    assert "mai puțin" not in _selfcheck(rows, checks_run=33, previous_run=33)
    # Și nici când crește.
    assert "mai puțin" not in _selfcheck(rows, checks_run=33, previous_run=32)


# --- registration -----------------------------------------------------------
# Cele patru teste de mai jos citeau TEXTUL SURSĂ al lui `build_application`,
# fiindcă acolo stăteau tabelele de comenzi. De când din același tabel se derivă
# și meniul publicat la Telegram, tabelele sunt la nivel de modul, iar testele
# citesc structura — care e și ce se înregistrează de fapt. Un `'"nume"' in src`
# trecea oricum și dacă numele apărea doar într-un comentariu.
def _names() -> set[str]:
    from sentinel.telegram import bot

    return {n for c in bot.COMMANDS for n in c.names}


def test_every_web_page_has_a_command():
    """The point of the exercise: nothing the dashboard shows should be
    reachable only from a browser."""
    names = _names()
    for name in ("dashboard", "incidente", "vulnerabilitati", "evenimente",
                 "servicii", "blocate", "patchuri"):
        assert name in names, f"no command for {name}"


def test_commands_have_romanian_names():
    """The interface language is Romanian. `/incidents` working and
    `/incidente` not is the kind of detail that makes a tool feel foreign."""
    names = _names()
    for ro, en in (("incidente", "incidents"), ("servicii", "services"),
                   ("evenimente", "events"), ("rezolva", "resolve")):
        assert ro in names and en in names


# Validarea numelor de comenzi s-a mutat în
# `tests/security/test_telegram_command_names.py`.
#
# Testul care stătea aici extrăgea numele cu două expresii regulate —
# `\("([^"]+)"` pentru primul alias și `"([^"]+)"\)` pentru ultimul. Aliasul din
# MIJLOCUL unui tuplu de trei nu era prins de niciuna, iar acolo era exact
# `(("stiu", "știu", "ack"), ...)`: testul a trecut verde pe codul care a doborât
# botul pentru o zi. Docstring-ul lui afirma totuși că validează toate numele.
#
# Nu l-am reparat, l-am înlocuit. Două teste care afirmă același lucru, unul cu
# punct orb, sunt mai rele decât unul corect: al doilea dă încrederea pe care
# primul n-o merită. Cel nou citește AST-ul și acoperă și înregistrările directe
# prin `CommandHandler(...)`, în afara tabelelor.


def test_help_lists_what_is_registered():
    """A help text that drifts from the handlers is worse than none."""
    registered = _names()
    checked = 0
    for line in views.HELP.splitlines():
        if not line.startswith("/"):
            continue
        name = line.split()[0].lstrip("/").split("&")[0].strip()
        assert name in registered, f"/{name} is in the help text but not registered"
        checked += 1
    # Fără asta, o schimbare de format în HELP ar goli bucla și testul ar trece
    # verde fără să compare nimic — tiparul „listă parametrizată ieșită goală".
    assert checked >= 15, f"am verificat doar {checked} comenzi din textul de ajutor"


def test_read_only_commands_are_separated_from_acting_ones():
    """Not cosmetic: the acting ones each re-check the operator role, and the
    split is what makes it obvious which ones must."""
    from sentinel.telegram import bot

    read_only = {n for c in bot.READ_ONLY for n in c.names}
    acting = {n for c in bot.ACTING for n in c.names}

    assert read_only and acting
    for name in ("block", "unblock", "panic", "resolve", "rezolva", "stiu", "mute"):
        assert name in acting, f"/{name} nu mai e în lista care verifică rolul"
        assert name not in read_only, f"/{name} a ajuns printre comenzile de citire"
    # Fiecare comandă e într-una singură dintre liste, și amândouă ajung în tabel.
    assert not (read_only & acting)
    assert read_only | acting == {n for c in bot.COMMANDS for n in c.names}
