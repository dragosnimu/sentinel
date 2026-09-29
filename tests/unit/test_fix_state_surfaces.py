"""Ce spune botul despre o constatare „reparată, în așteptarea repornirii".

Eșecul prevenit: operatorul tastează `/planifica 41761` sau `/vuln 41761` pe una
dintre cele 491 de constatări și primește „nu mai e deschisă — un plan pentru ea
ar repara ceva ce scanarea nu mai vede". E fals: constatarea E deschisă, scanarea
o vede în fiecare noapte, gazda e expusă, iar reparația așteaptă o repornire. Un
răspuns fals de la canalul singurului om care poate acționa e mai rău decât tăcerea.

Constatarea rămâne `status = 'open'`. Botul deosebește starea prin indicatorul
`fix_pending_reboot`, calculat în SQL de `findings.pending_reboot_sql`.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.config import Config  # noqa: E402
from sentinel.db.repo import findings as findings_repo  # noqa: E402
from sentinel.patch import planner  # noqa: E402
from sentinel.telegram import bot, views  # noqa: E402

CHAT_ID = 1234567890  # substituent — vezi nota din tests/unit/test_telegram_errors.py
FINDING_ID = 41761


def run(c):
    return asyncio.run(c)


class _Msg:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict]] = []

    async def reply_text(self, text, **kw):
        self.sent.append((text, kw))


def _update():
    msg = _Msg()
    return SimpleNamespace(effective_chat=SimpleNamespace(id=CHAT_ID),
                           effective_message=msg, message=msg), msg


def _cfg() -> Config:
    cfg = Config()
    cfg.telegram.allowed_chat_ids = [CHAT_ID]
    return cfg


def _finding(**over):
    """Constatarea așa cum o întoarce `get_finding`: `open`, cu indicatorul pus."""
    row = {"id": FINDING_ID, "cve": "CVE-2025-39964", "title": "CVE-2025-39964 în kernel-core",
           "severity": "high", "cvss": None, "epss": None, "kev": True, "priority": 80,
           "package": "kernel-core", "installed_version": None,
           "fixed_version": "5.14.0-687.50.1.el9_8", "location": None,
           "ecosystem": "rpm", "scanner": "dnf", "status": "open",
           "fix_pending_reboot": True, "fix_installed": "5.14.0-687.51.1.el9_8",
           "fix_running": "5.14.0-687.46.1.el9_8", "fix_since": "2026-09-26",
           "asset_name": None}
    row.update(over)
    return row


def _serve(monkeypatch, row):
    async def _get(db, finding_id):
        return row if row["id"] == finding_id else None

    monkeypatch.setattr(findings_repo, "get_finding", _get)


@pytest.fixture
def cheie(monkeypatch):
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: SimpleNamespace(get=lambda k, d=None: "sk-test"))


def _no_model(monkeypatch) -> list:
    calls: list = []

    async def _generate(*a, **k):
        calls.append(a)
        return None, "nu s-ar fi ajuns aici"

    monkeypatch.setattr(planner, "generate", _generate)
    return calls


def _plan_request():
    ctx = SimpleNamespace(bot_data={"db": object(), "cfg": _cfg()},
                          args=[str(FINDING_ID)], bot=SimpleNamespace())
    update, msg = _update()
    run(bot.cmd_planifica(update, ctx))
    return msg.sent[0][0]


# --- /planifica ----------------------------------------------------------------------
def test_planifica_on_a_pending_finding_explains_and_pays_nothing(monkeypatch, cheie):
    """Refuzul spune de ce: reparația e instalată, o repornire o aplică, constatarea
    rămâne deschisă, Sentinel nu repornește — și NU pornește modelul.

    Ce se strică dacă ramura dispare: cererea ar continua spre model (un plan `dnf
    update` fără nimic de instalat, plătit) sau ar cădea pe „nu mai e deschisă", o
    afirmație falsă despre gazdă.
    """
    calls = _no_model(monkeypatch)
    _serve(monkeypatch, _finding())

    text = _plan_request()

    assert calls == [], "s-a plătit un apel la model pentru o constatare fără nimic de aplicat"
    assert "nu are nevoie de plan" in text
    assert "repornire" in text and "Sentinel nu repornește nimic" in text
    assert "rămâne deschisă" in text
    assert "nu mai e deschisă" not in text and "scanarea nu mai vede" not in text
    assert f"/vuln {FINDING_ID}" in text


def test_planifica_refuses_before_the_ecosystem_and_fix_checks(monkeypatch, cheie):
    """Refuzul „în așteptare” vine PRIMUL: un rând care așteaptă o repornire și n-are
    (încă) `fixed_version` ar primi altfel „nu are o versiune care o repară” — adevărat
    pe jumătate și fără ce contează, repornirea."""
    _no_model(monkeypatch)
    _serve(monkeypatch, _finding(fixed_version=None))

    text = _plan_request()

    assert "nu are nevoie de plan" in text and "repornire" in text


def test_a_resolved_finding_keeps_the_old_refusal(monkeypatch, cheie):
    """Un rând REZOLVAT (după repornire) păstrează în `raw` ultimul verdict, dar
    predicatul cere `open`, deci indicatorul e fals: refuzul rămâne „nu mai e
    deschisă”, adevărat pentru el. Ce se strică dacă botul ar deduce starea din
    altceva decât indicatorul: un rând închis ar mai spune „așteaptă o repornire”."""
    _no_model(monkeypatch)
    _serve(monkeypatch, _finding(status="resolved", fix_pending_reboot=False))

    text = _plan_request()

    assert "nu mai e deschisă" in text and "resolved" in text
    assert "repornire" not in text


def test_a_deferral_set_by_a_human_keeps_the_old_refusal(monkeypatch, cheie):
    """`deferred` pus de operator nu are legătură cu repornirea: explicația despre
    repornire ar fi falsă pentru el."""
    _no_model(monkeypatch)
    _serve(monkeypatch, _finding(status="deferred", fix_pending_reboot=False))

    text = _plan_request()

    assert "repornire" not in text
    assert "nu mai e deschisă" in text and "deferred" in text


def test_an_open_finding_is_still_planned_as_before(monkeypatch, cheie):
    """Ramura nouă nu are voie să înghită cazul obișnuit: o constatare `open` cu
    reparație neinstalată trece mai departe și pornește cererea către model."""
    async def _no_live(db, finding_id):
        return None

    started: list[int] = []

    async def _run_request(bot_, db, cfg, api_key, *, chat_id, finding):
        started.append(finding["id"])

    monkeypatch.setattr("sentinel.db.repo.patches.live_plan_for_finding", _no_live)
    monkeypatch.setattr(bot, "_run_plan_request", _run_request)
    bot._plan_requests.clear()
    _serve(monkeypatch, _finding(fix_pending_reboot=False))

    text = _plan_request()

    assert "nu are nevoie de plan" not in text
    assert "Cer un plan de remediere" in text
    bot._plan_requests.clear()


# --- /vuln ----------------------------------------------------------------------------------
def _vuln(monkeypatch, row) -> str:
    _serve(monkeypatch, row)
    update, msg = _update()
    ctx = SimpleNamespace(bot_data={"db": object(), "cfg": SimpleNamespace(timezone="UTC")},
                          args=[str(row["id"])])
    run(views.cmd_vuln(update, ctx))
    return msg.sent[0][0]


def test_vuln_says_the_fix_is_installed_and_offers_no_plan(monkeypatch):
    """Detaliul unei constatări în așteptare: explicația despre repornire, dovada
    (ce e pe disc, ce rulează, de când), fără „nu mai e deschisă” și fără oferta
    `/planifica`.

    Ce se strică: `/vuln` ar spune „ce urmează e ultima constatare, nu starea de
    acum” despre un rând care ESTE starea de acum — sau ar oferi un plan care nu
    are ce instala.
    """
    text = _vuln(monkeypatch, _finding())

    assert "reparația e deja instalată" in text and "Sentinel nu repornește nimic" in text
    assert "5.14.0-687.51.1.el9_8" in text and "5.14.0-687.46.1.el9_8" in text
    assert "2026-09-26" in text
    assert "Nu mai e deschisă" not in text
    assert "/planifica" not in text
    assert "singurul pas rămas e repornirea" in text


def test_vuln_on_a_resolved_finding_says_what_it_said_before(monkeypatch):
    text = _vuln(monkeypatch, _finding(status="resolved", fix_pending_reboot=False))

    assert "Nu mai e deschisă (stare: resolved)" in text
    assert "reparația e deja instalată" not in text


def test_vuln_on_an_open_finding_still_offers_the_plan(monkeypatch):
    text = _vuln(monkeypatch, _finding(fix_pending_reboot=False))

    assert f"/planifica {FINDING_ID}" in text
    assert "repornire" not in text


# --- /vulnerabilitati ----------------------------------------------------------------------------
class _List:
    """Doar ce cere `cmd_vulns`, cu rânduri fixe."""

    def __init__(self, rows):
        self.rows = rows

    def install(self, monkeypatch):
        async def list_open(db, **kw):
            return list(self.rows)

        async def open_counts(db, **kw):
            return {"high": len(self.rows), "total": len(self.rows),
                    "kev": sum(1 for r in self.rows if r.get("kev"))}

        async def by_scanner(db):
            return {"dnf": len(self.rows)}

        monkeypatch.setattr(findings_repo, "list_open", list_open)
        monkeypatch.setattr(findings_repo, "open_counts", open_counts)
        monkeypatch.setattr(findings_repo, "open_counts_by_scanner", by_scanner)


def _list(monkeypatch, rows) -> str:
    _List(rows).install(monkeypatch)
    update, msg = _update()
    ctx = SimpleNamespace(bot_data={"db": object(), "cfg": SimpleNamespace(timezone="UTC")},
                          args=[])
    run(views.cmd_vulns(update, ctx))
    return msg.sent[0][0]


def test_the_list_marks_the_rows_that_wait_for_a_reboot_and_explains_the_mark(monkeypatch):
    """Un KEV `open` fără plan și fără nicio marcă ar arăta ca o sarcină uitată. Marca
    🔁 pe rândul lui, plus legenda, spune că e cunoscut și ce mai rămâne de făcut.

    Ce se strică fără marcă: operatorul vede 7 KEV deschise, cinci dintre ele cu un
    `/planifica` care se va refuza, fără să știe de ce.
    """
    waiting = _finding(id=1, fix_pending_reboot=True)
    plain = _finding(id=2, kev=False, fix_pending_reboot=False, package="openssl")

    text = _list(monkeypatch, [waiting, plain])

    lines = text.splitlines()
    waiting_line = next(line for line in lines if "<b>#1</b>" in line)
    plain_line = next(line for line in lines if "<b>#2</b>" in line)
    assert "🔁" in waiting_line and "🔥" in waiting_line
    assert "🔁" not in plain_line
    assert "🔁 = reparația e instalată, așteaptă o repornire" in text


def test_the_legend_appears_only_when_a_row_needs_it(monkeypatch):
    """Fără niciun rând marcat, legenda ar fi zgomot în fiecare răspuns."""
    text = _list(monkeypatch, [_finding(id=2, fix_pending_reboot=False)])

    assert "🔁" not in text
