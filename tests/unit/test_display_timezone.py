"""Ora pe care o citește operatorul e ora lui, și spune care e.

Eșecurile pe care le previne fișierul ăsta, măsurate pe gazdă pe 28 august 2026,
cu `timezone: Europe/Bucharest` în configurație și UTC+3 în august:

  * **o fereastră de detecție mutată cu tot decalajul.** `ODD_HOURS =
    range(1, 6)` se compara cu ORA UTC, deci „orele nefirești" însemnau de fapt
    04:00–08:59 local. O logare la 08:54 era semnalată — un fals pozitiv
    evident, pe o alertă care nu poate fi tăcută niciodată — iar una la 03:00
    era 00:00 UTC, deci **nu** era semnalată deloc. Ora la care ar intra cineva
    pe furiș era singura care tăcea;
  * **ore afișate în alt fus decât cel în care trăiește operatorul,** de cele
    mai multe ori fără să spună asta. Trei ore diferență între ce scria mesajul
    și ce arăta `journalctl` înseamnă căutat în fereastra greșită.

Testele sunt împărțite în trei: mecanismul (`sentinel/util/tz.py`), efectul pe
fiecare cale care ajunge la om, și garda care nu lasă un loc nou să formateze
singur.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest

from sentinel.util import tz

REPO = Path(__file__).resolve().parents[2]
TEMPLATES = REPO / "sentinel" / "web" / "templates"
TZ = "Europe/Bucharest"

#: Aceeași zonă, două marcaje: UTC+3 în august, UTC+2 în decembrie.
VARA = datetime(2026, 8, 24, 5, 54, tzinfo=timezone.utc)     # 08:54 la București
IARNA = datetime(2026, 12, 24, 20, 30, tzinfo=timezone.utc)  # 22:30 la București


# ---------------------------------------------------------------------------
# Mecanismul
# ---------------------------------------------------------------------------
def test_a_moment_is_written_in_the_configured_zone():
    assert tz.fmt(VARA, tz.LONG, tz_name=TZ) == "2026-08-24 08:54 EEST"
    assert tz.fmt(IARNA, tz.LONG, tz_name=TZ) == "2026-12-24 22:30 EET"


def test_the_zone_marker_follows_daylight_saving_not_the_zone_name():
    """`Europe/Bucharest` e EET iarna și EEST vara.

    Un marcaj calculat o dată pentru zonă, nu pentru moment, ar fi greșit
    jumătate de an — și ar fi greșit tăcut, fiindcă ora afișată ar rămâne
    corectă. Aceeași grijă e scrisă în `telegram/quiet.py` despre motivul
    pentru care se folosește numele zonei IANA și nu un decalaj fix.
    """
    assert tz.label(VARA, TZ) == "EEST"
    assert tz.label(IARNA, TZ) == "EET"


def test_the_hour_of_the_day_is_the_local_one():
    """Funcția pe care se sprijină fereastra de ore nefirești.

    03:00 la București e 00:00 UTC. Citite din obiectul UTC, cele două ore sunt
    zero și trei, iar fereastra prinde exact pe cea greșită.
    """
    la_trei = datetime(2026, 8, 24, 3, 0, tzinfo=ZoneInfo(TZ)).astimezone(timezone.utc)
    assert la_trei.hour == 0, "fixtura nu mai demonstrează diferența"
    assert tz.hour(la_trei, TZ) == 3
    assert tz.hour(la_trei, "UTC") == 0


def test_an_unknown_zone_does_not_make_the_time_disappear(caplog):
    """Un fus care nu există e o greșeală de configurație, nu un motiv de tăcere.

    Se coboară zgomotos — o linie de eroare în jurnal — iar ora pleacă mai
    departe cu marcajul fusului în care a ieșit până la urmă. Un mesaj fără oră
    ar fi cea mai proastă dintre reacții: alarma ajunge, dar fără momentul care
    o face verificabilă.
    """
    with caplog.at_level(logging.ERROR, logger="sentinel.util.tz"):
        scris = tz.fmt(VARA, tz.LONG, tz_name="Europe/Nicaieri")

    assert any("unknown timezone" in r.getMessage() for r in caplog.records)
    assert "2026-08-24" in scris
    assert scris.split()[-1], "ora a ieșit fără niciun marcaj de fus"


def test_a_naive_datetime_is_read_as_utc_and_says_so(caplog):
    """Baza întoarce `timestamptz`, deci un moment naiv înseamnă că altceva e
    stricat. `.astimezone()` l-ar citi tăcut în ora procesului — corect pe
    gazdă, greșit oriunde altundeva, și fără nimic care să spună că s-a ghicit.
    """
    with caplog.at_level(logging.WARNING, logger="sentinel.util.tz"):
        scris = tz.fmt(datetime(2026, 12, 24, 20, 30), tz.LONG, tz_name=TZ)

    assert scris == "2026-12-24 22:30 EET"
    assert any("naive datetime" in r.getMessage() for r in caplog.records)


def test_an_unknown_moment_is_not_written_as_now():
    """„Nu se știe când" și „acum" sunt stări diferite, iar una scrisă în locul
    celeilalte e chiar tiparul după care e numit depozitul ăsta."""
    assert tz.fmt(None, tz_name=TZ) == "necunoscut"
    assert tz.fmt(None, tz_name=TZ, missing="permanent") == "permanent"


def test_the_quiet_hours_still_read_the_same_zone_function():
    """`host_zone_name` și `zone` s-au MUTAT din `telegram/quiet.py`, nu au fost
    copiate acolo.

    Două copii ale aceleiași reguli de fus se despart tăcut, iar cea care se
    desparte prima e cea pe care n-o testează nimeni. Testele lui `quiet`
    rulează pe funcția asta; aici se verifică doar că e chiar aceeași.
    """
    from sentinel.telegram import quiet

    assert quiet.zone is tz.zone
    assert quiet.host_zone_name is tz.host_zone_name


# ---------------------------------------------------------------------------
# Efectul pe fiecare cale
# ---------------------------------------------------------------------------
def test_the_odd_hour_window_is_judged_in_the_configured_zone():
    """Cele două capete ale defectului, într-un singur test.

    `ODD_HOURS` e `range(1, 6)` și trebuie să însemne 01:00–05:59 LOCAL. Citit
    pe ora UTC, cu București la UTC+3, însemna 04:00–08:59.
    """
    from sentinel.detect import logins

    def la(ora: int, minut: int = 0) -> datetime:
        return datetime(2026, 8, 24, ora, minut,
                        tzinfo=ZoneInfo(TZ)).astimezone(timezone.utc)

    assert tz.hour(la(3), TZ) in logins.ODD_HOURS, "03:00 local trebuie să fie o oră nefirească"
    assert tz.hour(la(8, 54), TZ) not in logins.ODD_HOURS, "08:54 local nu e o oră nefirească"
    # Și dovada că fixtura chiar prinde defectul vechi, nu doar regula nouă.
    assert tz.hour(la(3), "UTC") not in logins.ODD_HOURS
    assert tz.hour(la(8, 54), "UTC") in logins.ODD_HOURS


def test_the_login_alert_writes_the_local_hour():
    from sentinel.detect import logins

    text = logins.open_text({"username": "operator", "src_ip": "198.51.100.7",
                             "terminal": "/dev/pts/0", "opened_at": VARA},
                            [], tz_name=TZ)
    assert "2026-08-24 08:54 EEST" in text
    assert "05:54" not in text


def test_the_selfcheck_clock_writes_the_local_hour():
    from sentinel.selfcheck import checks

    assert checks._ceas(VARA, TZ) == "2026-08-24 08:54 EEST"
    assert checks._ceas(None, TZ) == "necunoscut"


def test_the_event_line_writes_the_local_hour():
    pytest.importorskip("telegram")
    from sentinel.telegram import views

    linie = views._format_event(
        {"ts": VARA, "source": "sshd", "action": "auth_fail"},
        with_ip=False, tz_name=TZ)
    assert "08:54:00 EEST" in linie


def test_the_behaviour_profile_writes_the_local_hour(monkeypatch):
    """Ramura pe care n-o atingea niciun test, și de aia merită una a ei.

    „Valori noi în ultimele 7 zile" apare doar când cel puțin o dimensiune s-a
    încălzit ȘI există rânduri recente — două condiții care nu se întâlnesc în
    nicio fixtură existentă. O primă versiune a schimbării ăsteia a citit acolo
    un `cfg` pe care funcția nu-l lega, adică `NameError` pe gazdă și „A apărut
    o eroare la procesarea comenzii." în chat, cu suita întreagă verde. Exact
    forma defectului pe care `_MUTE_HELP` și `_fmt_local` l-au avut înaintea ei
    în același pachet.
    """
    import asyncio

    pytest.importorskip("telegram")
    from sentinel.predict import behaviour as bh
    from sentinel.telegram import views

    class _DB:
        async def fetch(self, sql, *a):
            assert "behaviour_profiles" in sql, sql
            return [{"dimension": "user", "key": "operator", "first_seen": VARA}]

    trimis: list[str] = []

    class _Msg:
        async def reply_html(self, text, **kw):
            trimis.append(text)

    async def fake_status(db):
        return [{"dimension": "user", "label": "Conturi", "warm": True,
                 "distinct_keys": 3, "observations": 120, "days": 14.0,
                 "needs": None}]

    monkeypatch.setattr(bh, "status", fake_status)
    update = SimpleNamespace(effective_message=_Msg())
    ctx = SimpleNamespace(
        bot_data={"db": _DB(), "cfg": SimpleNamespace(timezone=TZ)}, args=[])

    asyncio.run(views.cmd_behaviour(update, ctx))
    assert trimis, "comanda nu a răspuns deloc"
    # Fără liniile noi, dinadins. Comanda asta are un defect SEPARAT și
    # cunoscut — pasează un `str` unde `clamp` așteaptă `list[str]`, deci
    # iterează caracter cu caracter și pune un `\n` între fiecare două. Nu e
    # reparat aici, și aserțiunea de mai jos e adevărată în ambele lumi:
    # ștergerea liniilor noi dă exact același șir și înainte, și după
    # reparație. Scrisă pe forma spartă, ar fi consolidat defectul; scrisă pe
    # cea întreagă, ar fi picat degeaba.
    assert "24.08 08:54 EEST" in trimis[0].replace("\n", ""), trimis[0][:200]


def test_the_user_table_writes_the_local_hour(capsys, monkeypatch):
    """`sentinel web --list-users` e citit de un om care compară cu panoul și cu
    `journalctl`, iar amândouă arată ora locală."""
    import asyncio

    from sentinel.config import Config
    from sentinel.services import web_service

    class _DB:
        async def fetch(self, sql, *a):
            return [{"username": "operator", "role": "owner", "totp_confirmed": True,
                     "disabled": False, "failed_attempts": 0, "locked_until": None,
                     "last_login_at": VARA, "last_ip": "198.51.100.7"}]

        async def close(self):
            return None

    async def fake_db(cfg):
        return _DB()

    monkeypatch.setattr(web_service, "_with_db", fake_db)
    asyncio.run(web_service._list_users(Config(timezone=TZ)))
    iesire = capsys.readouterr().out
    assert "2026-08-24 08:54 EEST" in iesire, iesire
    assert "05:54" not in iesire


def test_the_detect_daemon_hands_the_configured_zone_to_the_login_alerts():
    """Fereastra de ore nefirești se evaluează în fusul pe care i-l dă apelantul.

    Dacă daemonul l-ar lăsa `None`, s-ar folosi fusul GAZDEI — de obicei același
    și uneori nu, iar când nu e, fereastra se mută cu tot decalajul și nimic n-o
    spune. Toate testele de mai sus ar rămâne verzi: ele dau fusul explicit.
    Aserțiunea e pe ARGUMENTUL scris în sursă, nu pe prezența unui nume.
    """
    import ast

    sursa = (REPO / "sentinel" / "services" / "detect_service.py")
    arbore = ast.parse(sursa.read_text(encoding="utf-8"), filename=str(sursa))
    apeluri = [n for n in ast.walk(arbore)
               if isinstance(n, ast.Call)
               and isinstance(n.func, ast.Attribute)
               and n.func.attr == "announce_new_sessions"]
    assert len(apeluri) == 1, (
        f"{len(apeluri)} apeluri către `announce_new_sessions` în {sursa.name}; "
        "verificarea de mai jos acoperă unul singur")
    dat = {k.arg: ast.unparse(k.value) for k in apeluri[0].keywords}
    assert dat.get("tz_name") == "cfg.timezone", (
        f"daemonul dă `tz_name={dat.get('tz_name')}`, nu `cfg.timezone` — "
        "fereastra de ore nefirești s-ar evalua în fusul gazdei")


def test_the_web_filter_is_bound_to_the_configured_zone():
    """Filtrul e legat o dată, la construirea mediului, din `Config`.

    Un șablon nu poate uita fusul și nu poate folosi altul — care e exact ce se
    întâmpla când fiecare dintre cele douăzeci de locuri chema `strftime`
    singur.
    """
    from sentinel.web.jinja import build_env

    env = build_env(TZ)
    assert env.from_string("{{ m | ora }}").render(m=VARA) == "24.08 08:54 EEST"
    assert env.from_string("{{ m | ora('%H:%M', with_zone=False) }}"
                           ).render(m=VARA) == "08:54"
    assert env.from_string("{{ m | ora }}").render(m=None) == "—"


def test_the_application_binds_the_filter_to_its_own_config():
    """Mediul din `build_env` nu e cel pe care îl folosește procesul.

    Fără verificarea asta, tot ce e mai sus poate fi adevărat despre un mediu de
    test, iar panoul real să randeze în alt fus — sau să pice cu
    `TemplateAssertionError: no filter named 'ora'` la prima pagină cerută.
    """
    from sentinel.config import Config
    from sentinel.web.app import create_app

    app = create_app(config=Config(timezone=TZ),
                     secrets_store=SimpleNamespace(get=lambda k, d=None: None,
                                                   has=lambda k: False,
                                                   require=lambda k: ""))
    env = app.state.templates.env
    assert "ora" in env.filters, "panoul nu are filtrul; fiecare pagină cu o oră ar da 500"
    assert env.from_string("{{ m | ora }}").render(m=VARA) == "24.08 08:54 EEST"


# ---------------------------------------------------------------------------
# Garda
# ---------------------------------------------------------------------------
#: Șabloanele care încă își formatează singure momentele, și de ce.
#:
#: Paginile de rapoarte etichetează CAPETE DE GĂLEATĂ, nu momente: gălețile sunt
#: aliniate în UTC de `date_trunc(..., bucket AT TIME ZONE 'UTC')` din
#: `analytics/reports.py`. O galeată zilnică scrisă în ora locală ar spune
#: „27.08" despre un interval care începe la 03:00 și se termină la 03:00 —
#: adică ar face graficul să mintă mai rău decât o face acum, când scrie „UTC"
#: pe față. Mutarea granițelor gălaților e o schimbare de analitică, cu
#: corectitudinea ei proprie, și e o decizie a operatorului, nu una luată în
#: trecere aici.
SABLOANE_CU_FORMATARE_PROPRIE = {"reports.html", "report_drill.html"}


def test_no_template_formats_a_moment_by_itself():
    """Douăzeci de locuri care chemau `strftime`, toate în UTC, dintre care
    patru scriau „UTC" în text și restul nu scriau nimic.

    Un loc nou care formatează singur ar reintroduce exact asta, și ar face-o
    tăcut: pagina se randează, ora e greșită cu trei ore, nimic nu se plânge.
    """
    vinovate = sorted(p.name for p in TEMPLATES.glob("*.html")
                      if "strftime" in p.read_text(encoding="utf-8")
                      and p.name not in SABLOANE_CU_FORMATARE_PROPRIE)
    assert not vinovate, (
        f"șabloane care formatează singure un moment: {vinovate}. "
        "Folosește filtrul `| ora`, care scrie în fusul configurat și pune "
        "marcajul de fus.")


def test_the_guard_is_not_looking_at_an_empty_set():
    """Fără asta, testul de mai sus trece și dacă directorul de șabloane s-a
    mutat sau tiparul căutat nu mai există nicăieri — o listă parametrizată
    ieșită goală și sărită tăcut a costat deja o pană aici."""
    sabloane = list(TEMPLATES.glob("*.html"))
    assert len(sabloane) > 10, f"doar {len(sabloane)} șabloane găsite în {TEMPLATES}"
    assert any("| ora" in p.read_text(encoding="utf-8") for p in sabloane), (
        "niciun șablon nu folosește filtrul; ori s-a redenumit, ori nu e "
        "folosit nicăieri — în ambele cazuri garda de mai sus nu păzește nimic")
    for name in SABLOANE_CU_FORMATARE_PROPRIE:
        assert (TEMPLATES / name).exists(), (
            f"{name} e scutit de gardă și nu mai există; scutirea e acum o "
            "gaură fără motiv")
