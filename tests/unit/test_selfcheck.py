"""The self-check, and the failures it exists because of.

Two real outages motivate this file, and both are represented below as tests:

  * the ingest service stayed `active` with zero restarts while its journald
    reader returned nothing for 21 hours, and SSH authentication went unwatched;
  * after a reboot the nftables table simply did not exist, so seven recorded
    blocks were fiction and the next automatic block would have failed silently.

In both, `systemctl is-active` said everything was fine. So the tests that
matter here are about the checks that do not ask systemd.
"""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from sentinel.selfcheck import checks
from sentinel.selfcheck.checks import CheckResult, worst

NOW = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)


def run(c):
    return asyncio.run(c)


class _DB:
    def __init__(self, rows=None, val=None, row=None):
        self._rows, self._val, self._row = rows or [], val, row
        self.sql: list[str] = []

    async def fetch(self, sql, *a):
        self.sql.append(sql)
        return self._rows

    async def fetchval(self, sql, *a):
        self.sql.append(sql)
        return self._val

    async def fetchrow(self, sql, *a):
        self.sql.append(sql)
        return self._row

    async def execute(self, sql, *a):
        self.sql.append(sql)

    async def healthy(self):
        return True


def _cfg(**over):
    base = SimpleNamespace(
        ai=SimpleNamespace(enabled=True),
        # Ca pe `Config`-ul real. Constatarile care tiparesc un moment il scriu
        # in fusul configurat, si il citesc de aici — un dublu fara campul asta
        # ar fi facut verificarea sa pice pe altceva decat pe ce testeaza.
        timezone="Europe/Bucharest",
        telegram=SimpleNamespace(enabled=True, allowed_chat_ids=[1]),
        response=SimpleNamespace(auto_block=SimpleNamespace(enabled=False), admin_ip=""),
        # Ca pe `Config`-ul real: `check_ship_lag` citește `cfg.ship.enabled`
        # direct, nu printr-un `getattr` cu valoare de rezervă — vezi
        # `test_no_check_reads_a_config_field_that_does_not_exist` mai jos, care
        # există fiindcă un `getattr` a ținut o verificare moartă un an.
        ship=SimpleNamespace(enabled=False, url="", interval_s=60),
        # Idem pentru `check_beacon_delivery`. Fără câmpul ăsta, un test care
        # cheamă rularea ÎNTREAGĂ ar vedea grupul „beacon" raportat ca stricat,
        # iar cauza — un dublu de configurație rămas în urmă — n-are nicio
        # legătură cu gazda.
        beacon=SimpleNamespace(enabled=False, url="", interval_s=60),
        # `check_command_history_filter` citește cheia înapoi din
        # configurația încărcată. Lipsa secțiunii ar face grupul „history”
        # să pice în orice test care rulează trecerea întreagă, dintr-un
        # motiv care n-are nicio legătură cu gazda.
        history=SimpleNamespace(skip_command_accounts=[]),
    )
    for k, v in over.items():
        setattr(base, k, v)
    return base


# --- a silent collector is only a fault when the others are talking ---------
def _source(name: str, minutes: float):
    return {"source": name, "ultim": NOW - timedelta(minutes=minutes),
            "minute_tacere": minutes}


def test_a_collector_that_stopped_while_others_write_is_down():
    """The 21-hour blind spot. The service was active, had never restarted, and
    logged nothing; only the data showed it."""
    db = _DB(rows=[_source("sshd", 1260), _source("nginx", 2),
                   _source("suricata", 1), _source("auditd", 1)])
    results = run(checks.check_ingest_sources(db, _cfg()))
    sshd = next(r for r in results if r.key == "ingest:sshd")
    assert sshd.status == "down"
    assert "alte surse scriu" in sshd.detail


def test_a_quiet_night_is_not_an_outage():
    """Everything quiet together is a quiet host. Blaming each collector
    individually would be six alerts for one non-problem — and six false alerts
    is how a channel gets muted."""
    db = _DB(rows=[_source("sshd", 500), _source("nginx", 400),
                   _source("suricata", 380)])
    results = run(checks.check_ingest_sources(db, _cfg()))
    per_source = [r for r in results if r.key.startswith("ingest:") and r.key != "ingest:all"]
    assert all(not r.bad for r in per_source)
    # But it IS reported once, at the top: everything silent is not normal either.
    assert any(r.key == "ingest:all" and r.status == "down" for r in results)


def test_a_human_driven_source_is_never_an_alert():
    """`sudo` and `su` produce events only when a person acts. A server nobody
    logged into for a day emits zero sudo events, and that is the healthy state.

    This shipped with a 24h threshold and fired on the first quiet day —
    "SENTINEL NU FUNCȚIONEAZĂ COMPLET", advising a restart of a service that was
    working. No duration may reproduce that, so the test uses a year."""
    for name in ("sudo", "su"):
        db = _DB(rows=[_source(name, 60 * 24 * 365), _source("suricata", 1),
                       _source("nginx", 2)])
        r = next(x for x in run(checks.check_ingest_sources(db, _cfg()))
                 if x.key == f"ingest:{name}")
        assert r.status == "ok", f"{name} după un an de liniște: {r.detail}"
        assert not r.bad
        # Still visible to the operator — silenced, not hidden.
        assert "normal" in r.detail


def test_human_driven_sources_carry_no_threshold():
    """Belt and braces: the two sets must not overlap. A threshold left behind
    in SOURCE_MAX_SILENCE_MIN would be dead code that looks authoritative, and
    the next person to read it would reinstate the bug."""
    assert not (checks.HUMAN_DRIVEN & set(checks.SOURCE_MAX_SILENCE_MIN))


def test_the_shared_journald_reader_still_has_a_watched_source():
    """sudo and su are exempt because sshd proves the reader is alive — they all
    come from ONE reader with one _COMM match set. If sshd ever stopped being
    watched, or stopped sharing that reader, the exemption would silently become
    a blind spot."""
    from sentinel.services.ingest_service import JOURNALD_COMMS
    watched = set(checks.SOURCE_MAX_SILENCE_MIN) - checks.HUMAN_DRIVEN
    assert "sshd" in watched, "sshd nu mai e supravegheat; sudo/su rămân neacoperite"
    for comm in ("sudo", "su"):
        assert comm in JOURNALD_COMMS
    assert "sshd" in JOURNALD_COMMS, "sshd nu mai vine din același cititor"


def test_no_events_at_all_is_reported():
    db = _DB(rows=[])
    results = run(checks.check_ingest_sources(db, _cfg()))
    assert results[0].status == "down"


# --- the firewall table has to actually exist ------------------------------
def test_a_missing_nftables_table_is_down(monkeypatch):
    """The other real outage: Sentinel recorded seven active blocks and the
    kernel held none, for a day, with nothing said."""
    monkeypatch.setattr(checks, "_nft_table_present", lambda: (False, "absentă"))
    results = run(checks.check_enforcement(_DB(val=7), _cfg()))
    assert results[0].status == "down"
    assert "Nicio blocare nu are efect" in results[0].detail
    assert "force-step 29" in results[0].action


def test_kernel_and_database_disagreement_is_reported(monkeypatch):
    monkeypatch.setattr(checks, "_nft_table_present", lambda: (True, "table inet sentinel {}"))
    from sentinel.respond import actions
    monkeypatch.setattr(actions, "live_count", _async(0))
    results = run(checks.check_enforcement(_DB(val=7), _cfg()))
    count = next(r for r in results if r.key == "nft:count")
    assert count.status == "degraded"
    assert "7 în bază · 0 în nftables" in count.detail


def test_agreement_is_ok(monkeypatch):
    monkeypatch.setattr(checks, "_nft_table_present", lambda: (True, "table inet sentinel {}"))
    from sentinel.respond import actions
    monkeypatch.setattr(actions, "live_count", _async(7))
    results = run(checks.check_enforcement(_DB(val=7), _cfg()))
    assert next(r for r in results if r.key == "nft:count").status == "ok"


# Aici a stat `test_the_admin_address_missing_from_the_allowlist_is_flagged`,
# cu docstring-ul „The anti-lockout invariant, checked rather than assumed."
# Era presupus: verificarea citea `cfg.response.admin_ip`, câmp pe care
# `ResponseConfig` nu-l are, deci cheia `nft:allowlist` nu s-a emis niciodată în
# producție. Testul trecea fiindcă își fabrica un `SimpleNamespace(admin_ip=…)`
# pe care `Config`-ul real nu-l poate produce — un test verde peste cod mort,
# exact tiparul „aserțiune pe prezența unui nume, nu pe decizia luată din el".
#
# Verificarea a fost scoasă (vezi comentariul din `check_enforcement`), deci și
# testul. Testul de mai jos păzește ce a mai rămas: că un `Config` real chiar nu
# poate produce cheia — ca nimeni să nu reintroducă garda fără câmp.
def test_no_check_reads_a_config_field_that_does_not_exist():
    """Un `getattr(cfg.x, "y", None)` pe un câmp inexistent nu dă eroare: dă
    `None`, iar verificarea din spatele lui nu rulează niciodată. Așa a stat
    invariantul anti-lockout, nerulat și necontestat, cu un test verde peste el.

    Fiecare câmp de configurație citit de verificări trebuie să existe pe
    dataclass-ul real, nu doar pe obiectul fabricat de teste.

    Expresia s-a uitat până pe 15 august 2026 DOAR la `getattr(cfg.response, …)`.
    Consecința era cea obișnuită pentru o gardă îngustă: singura linie din
    `checks.py` care se potrivea cu tiparul păzit — `getattr(getattr(cfg,
    "beacon", None), "enabled", False)`, în `check_units` — era exact cea la care
    testul nu se uita. Acum se caută ambele forme, pe orice secțiune.
    """
    import inspect

    from sentinel.config import Config, ResponseConfig

    src = inspect.getsource(checks)
    cfg = Config()

    SECTIUNE = r"getattr\(\s*cfg\s*,\s*[\"'](\w+)[\"']"
    CAMP = r"getattr\(\s*cfg\.(\w+)\s*,\s*[\"'](\w+)[\"']"

    # Garda gărzii, și e obligatorie aici: azi `checks.py` nu mai are niciun
    # `getattr` pe `cfg`, deci ambele bucle de mai jos sunt goale. O expresie
    # stricată ar găsi tot nimic, buclele s-ar sări la fel, și testul ar trece
    # verde uitându-se la nimic — chiar tiparul „listă parametrizată ieșită goală
    # și sărită tăcut" din CLAUDE.md. Măsurat: mutația care strică expresia
    # trecea VERDE fără proba asta.
    #
    # Proba e o sursă fabricată care conține exact cele două forme. Dacă
    # expresiile încetează să le vadă, se vede aici, indiferent ce conține
    # `checks.py`.
    proba = ('if not getattr(cfg, "beacon", None):\n'
             '    x = getattr(cfg.response, "admin_ip", None)\n')
    assert re.findall(SECTIUNE, proba) == ["beacon"], \
        "expresia pentru `getattr(cfg, \"<secțiune>\")` nu mai vede forma"
    assert re.findall(CAMP, proba) == [("response", "admin_ip")], \
        "expresia pentru `getattr(cfg.<secțiune>, \"<câmp>\")` nu mai vede forma"

    # `getattr(cfg, "<secțiune>", …)` — secțiunea trebuie să existe pe `Config`.
    sectiuni = re.findall(SECTIUNE, src)
    for name in sectiuni:
        assert hasattr(cfg, name), (
            f"o verificare citește cfg.{name} printr-un getattr cu valoare de "
            f"rezervă, iar `Config` n-are secțiunea asta — deci rezerva e ce se "
            f"folosește, la fiecare rulare, tăcut")

    # `getattr(cfg.<secțiune>, "<câmp>", …)` — câmpul trebuie să existe pe ea.
    campuri = re.findall(CAMP, src)
    for sectiune, attr in campuri:
        assert hasattr(cfg, sectiune), f"cfg.{sectiune} nu există"
        assert hasattr(getattr(cfg, sectiune), attr), (
            f"o verificare citește {sectiune}.{attr}, care nu există pe "
            f"dataclass-ul real — verificarea din spatele lui nu rulează niciodată")

    # Numărul măsurat, ca lista să nu poată ieși goală în tăcere: o expresie
    # stricată n-ar mai găsi nimic, buclele de mai sus s-ar sări, iar testul ar
    # trece verde fără să se fi uitat la nimic. Exact felul de test care a costat
    # deja o pană aici. Azi `checks.py` nu mai are niciun `getattr` pe `cfg`;
    # dacă apare unul, numărul se ridică ODATĂ cu el.
    assert len(sectiuni) + len(campuri) == 0, (
        f"au apărut {len(sectiuni) + len(campuri)} citiri prin getattr pe `cfg` "
        f"({sectiuni}, {campuri}). Nu sunt interzise, dar numărul de aici e o "
        f"măsurătoare: ridică-l odată cu ele, ca bucla să nu se poată goli tăcut")

    # Și câmpul mort anume, ca reintroducerea lui să pice aici.
    assert not hasattr(ResponseConfig(), "admin_ip"), \
        "admin_ip a fost adăugat — atunci verificarea allowlist trebuie rescrisă și testată"
    assert hasattr(cfg, "response")


# --- the detection loop -----------------------------------------------------
def test_a_stalled_detector_is_down():
    """Ingesting into a table nobody reads is a convincing imitation of working:
    the event count rises and no incident is ever raised."""
    db = _DB(row={"cursor": "1", "updated_at": NOW, "minute": 90})
    assert run(checks.check_detection_loop(db))[0].status == "down"


def test_a_recent_detector_is_ok():
    db = _DB(row={"cursor": "1", "updated_at": NOW, "minute": 2})
    assert run(checks.check_detection_loop(db))[0].status == "ok"


# --- the alerting channel itself -------------------------------------------
def test_a_stopped_bot_is_down(monkeypatch):
    """If this is broken, nothing else the self-check finds can reach anyone."""
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "failed")
    result = run(checks.check_alerting(_DB(val=0), _cfg()))[0]
    assert result.status == "down"
    assert "nicio alertă nu poate ajunge" in result.detail


def test_a_running_bot_that_delivers_nothing_is_degraded(monkeypatch):
    """Running and failing to send is the same outcome as stopped."""
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "active")
    result = run(checks.check_alerting(_DB(val=12), _cfg()))[0]
    assert result.status == "degraded"


# --- isolation --------------------------------------------------------------
def test_a_crashing_check_does_not_stop_the_run(monkeypatch):
    """A self-check that goes quiet for the same reason everything else does is
    worthless. It has to report its own breakage."""
    async def _boom(db, cfg):
        raise RuntimeError("nft exploded")

    monkeypatch.setattr(checks, "CHECKS", (("enforcement", _boom),
                                           ("autonomy", checks.check_autonomy)))
    results = run(checks.run_all(_DB(), _cfg()))
    assert any(r.key == "selfcheck:enforcement" and r.status == "unknown" for r in results)
    assert any(r.key == "mode:autoblock" for r in results), "the run stopped early"


def test_worst_of_ranks_down_below_degraded():
    assert worst([CheckResult("a", "A", "ok"), CheckResult("b", "B", "down")]) == "down"
    assert worst([CheckResult("a", "A", "ok"), CheckResult("b", "B", "degraded")]) == "degraded"
    assert worst([CheckResult("a", "A", "ok")]) == "ok"
    assert worst([]) == "unknown"


# --- alerting policy --------------------------------------------------------
def test_the_alert_says_what_to_do():
    """A message that reports a fault without a next step is a message that
    turns into a support request."""
    from sentinel.selfcheck.runner import format_alert

    text = format_alert(
        [CheckResult("nft:table", "Tabela nftables lipsește", "down",
                     detail="absentă", action="deploy.sh --force-step 29")], [])
    assert "SENTINEL NU FUNCȚIONEAZĂ COMPLET" in text
    assert "force-step 29" in text


def test_degraded_alone_does_not_shout():
    from sentinel.selfcheck.runner import format_alert

    text = format_alert([CheckResult("x", "Ceva", "degraded", detail="d")], [])
    assert "NU FUNCȚIONEAZĂ COMPLET" not in text
    assert "degradat" in text


def test_recovery_is_announced():
    """Only telling people when things break trains them to assume the last
    message is still true."""
    from sentinel.selfcheck.runner import format_alert

    text = format_alert([], [CheckResult("x", "Colector sshd", "ok")])
    assert "Revenit la normal" in text and "Colector sshd" in text


def test_a_selfcheck_that_says_something_STOPPED_is_never_muted():
    """Jumatatea pentru care exista scutirea, si numai ea.

    Ținută până la 06:00, o veste care spune că o parte din agent s-a oprit ar
    face ca orele în care nu te uiți la telefon să fie exact orele în care nimeni
    nu se uită nici la server.

    `runner._announce` pune `critical` exact când vreun rezultat e `down`, deci
    severitatea POARTĂ deja distincția — nu mai e nevoie de o scutire pe fel.
    """
    from sentinel.telegram.quiet import passes_anyway

    assert passes_anyway("critical", "selfcheck"), (
        "o autoverificare care spune că ceva s-a OPRIT nu trece prin mute")


def test_a_selfcheck_that_only_says_DEGRADED_is_held():
    """Cealaltă jumătate, și motivul pentru care regula s-a îngustat.

    `degraded` înseamnă, prin definiția din `check_ship_lag`, „pe gazdă nu s-a
    oprit nimic; ce e în urmă e o copie din afara ei". Ținută sub scutirea făcută
    pentru o oprire reală, vestea aia a devenit exact ce scutirea voia să
    prevină: un canal care sună degeaba și pe care operatorul îl închide.

    Cerut de operator pe 24 august 2026, după câteva zile de „Sentinel
    funcționează degradat" primite în perioada de mute.

    Ținut NU e pierdut — vezi
    `test_a_held_notification_stays_queued_instead_of_being_marked_failed`.
    """
    from sentinel.telegram.quiet import passes_anyway

    assert not passes_anyway("high", "selfcheck"), (
        "un `degraded` trece prin mute, deci mute-ul nu înseamnă nimic pentru "
        "canalul care sună cel mai des")
    assert not passes_anyway(None, "selfcheck")


def test_a_dead_bot_escalates_to_a_direct_send():
    """A message about a dead bot, queued for that bot, is a message nobody
    reads. This is the only place in the codebase that sends outside the bot,
    and it exists because the alternative is silence that looks like health."""
    import inspect

    from sentinel.selfcheck import runner

    src = inspect.getsource(runner._announce)
    assert 'r.key.startswith("alert:")' in src
    assert "_send_direct" in src


def test_the_selfcheck_never_repairs_anything():
    """A self-check that fixes what it finds is one whose findings stop being
    read, and restarting a security daemon turns a visible fault into an
    intermittent one."""
    import ast
    from pathlib import Path

    # Checked at the CALL SITES, not by grepping for strings: the module is full
    # of `action="systemctl restart …"` telling the OPERATOR what to run, and a
    # text search cannot tell advice from execution.
    read_only_verbs = {"is-active", "show", "list", "status", "list-timers"}
    for name in ("checks.py", "runner.py"):
        path = (Path(__file__).resolve().parents[2] / "sentinel" / "selfcheck" / name)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            fname = getattr(fn, "id", None) or getattr(fn, "attr", None)
            if fname not in ("_systemctl", "run", "Popen", "check_output", "system"):
                continue
            literals = [a.value for a in ast.walk(node)
                        if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            for v in literals:
                assert v not in ("restart", "start", "stop", "reload", "enable",
                                 "disable", "add", "flush", "delete", "insert"), \
                    f"{name} executes a mutating command: {fname}({literals})"
            # `_systemctl` forwards *args, so where a verb IS given literally it
            # has to be one that only looks.
            if fname == "_systemctl" and literals:
                assert literals[0] in read_only_verbs, \
                    f"{name}: systemctl {literals[0]} is not read-only"


def _async(value):
    async def _f(*a, **k):
        return value
    return _f


# --- o constatare pe care nimeni n-o mai calculează -------------------------
#
# Pe 9 august 2026, la 07:00, toate sursele au tăcut și `ingest:all` s-a scris cu
# `down`. La 08:25 și-au revenit, deci verificarea a încetat s-o mai emită — și
# nimic nu împăca tabela de stare cu ce emisese rularea. Botul i-a arătat
# operatorului „🔴 Sentinel nu funcționează complet" încă 26 de ore, peste 317
# rulări verzi consecutive, cu vechimea rândului blocat prezentată drept durata
# unei pene.
#
# Testele de mai jos rulează scenariul real: cheia apare cu `down`, dispare din
# rularea următoare, iar operatorul trebuie să vadă verde. Și scenariul invers:
# aceeași cheie dispare fiindcă rularea s-a întrerupt, caz în care starea ei NU
# are voie să fie curățată.
class _StateDB:
    """`selfcheck_state` și `selfcheck_runs`, cât să se poată juca mai multe rulări.

    Reimplementează în Python semantica instrucțiunilor SQL — deci dovedește
    logica runner-ului, nu SQL-ul însuși. Ce nu poate arăta fișierul ăsta:
    dacă PostgreSQL acceptă `NOT (key = ANY($1::text[]))` și dacă migrația 0021
    se aplică. Alea se verifică pe o bază reală.
    """

    def __init__(self):
        self.state: dict[str, dict] = {}
        self.runs: list[dict] = []
        self.notifications: list[str] = []
        self.sql: list[tuple[str, tuple]] = []

    def _now(self):
        return datetime.now(timezone.utc)

    async def fetch(self, sql, *a):
        self.sql.append((sql, a))
        if "FROM selfcheck_state" in sql:
            return [dict(v) for v in self.state.values()]
        if "FROM selfcheck_runs" in sql:      # ORDER BY started_at DESC LIMIT 2
            return list(reversed(self.runs))[:2]
        return []

    async def fetchrow(self, sql, *a):
        self.sql.append((sql, a))
        if "FROM selfcheck_runs" in sql:
            return self.runs[-1] if self.runs else None
        return None

    async def fetchval(self, sql, *a):
        self.sql.append((sql, a))
        return 0

    async def execute(self, sql, *a):
        self.sql.append((sql, a))
        if "INSERT INTO selfcheck_state" in sql:
            key, status, title, detail, _facts, keep_since = a
            old = self.state.get(key)
            self.state[key] = {
                "key": key, "status": status, "title": title, "detail": detail,
                "since": old["since"] if (old and keep_since) else self._now(),
                "last_seen": self._now(), "stale": False,
                "last_alert_at": old["last_alert_at"] if old else None,
            }
        elif "DELETE FROM selfcheck_state" in sql:
            keep = set(a[0])
            for key in [k for k in self.state if k not in keep]:
                del self.state[key]
        elif "UPDATE selfcheck_state SET stale" in sql:
            keep = set(a[0])
            for key, row in self.state.items():
                if key not in keep:
                    row["stale"] = True
        elif "UPDATE selfcheck_state SET last_alert_at" in sql:
            for key in a[0]:
                if key in self.state:
                    self.state[key]["last_alert_at"] = self._now()
        elif "INSERT INTO selfcheck_runs" in sql:
            duration_ms, worst_status, checks_run, checks_bad = a
            self.runs.append({
                "started_at": self._now(), "worst_status": worst_status,
                "checks_run": checks_run, "checks_bad": checks_bad,
                "duration_ms": duration_ms})
        elif "INSERT INTO notifications" in sql:
            self.notifications.append(a[-1])

    async def healthy(self):
        return True


def _outcome(results, failed=()):
    async def _run_groups(db, cfg):
        return checks.RunOutcome(list(results), tuple(failed))
    return _run_groups


_LIVE = CheckResult("ingest:suricata", "Colector „suricata”", "ok",
                    detail="ultimul eveniment acum 1 min")
_ALL_QUIET = CheckResult("ingest:all", "Toate sursele au amuțit", "down",
                         detail="cea mai recentă acum 94 min")


def _panel(db) -> str:
    """Ce vede operatorul la /selfcheck, din aceleași rânduri."""
    pytest.importorskip("telegram")
    from types import SimpleNamespace as NS

    from sentinel.telegram import views

    sent: list[str] = []

    class _Msg:
        async def reply_text(self, text, **kw):
            sent.append(text)

    msg = _Msg()
    run(views.cmd_selfcheck(NS(effective_message=msg, message=msg),
                            NS(bot_data={"db": db}, args=[])))
    return sent[0]


def test_a_finding_the_check_stopped_producing_stops_being_red(monkeypatch):
    """Scenariul real, cap-coadă.

    O cheie condiționată apare cu `down`, condiția dispare, deci verificarea nu
    o mai emite. Fără reconciliere rândul rămâne `down` pentru totdeauna și
    panoul îi spune operatorului că agentul de securitate e stricat, cât timp
    nimeni nu șterge rândul cu mâna. A durat 26 de ore și 317 rulări verzi.
    """
    from sentinel.selfcheck import runner

    db = _StateDB()

    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, _ALL_QUIET]))
    run(runner.run_and_alert(db, _cfg()))
    assert db.state["ingest:all"]["status"] == "down"
    assert "nu funcționează complet" in _panel(db)

    # Sursele revin: verificarea nu mai are ce emite pentru cheia asta.
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE]))
    run(runner.run_and_alert(db, _cfg()))
    assert "ingest:all" not in db.state, "restul rămâne și ține panoul roșu"

    # A treia rulare: operatorul vede verde.
    summary = run(runner.run_and_alert(db, _cfg()))
    assert summary["worst"] == "ok"
    panel = _panel(db)
    assert "Totul funcționează" in panel
    assert "Toate sursele au amuțit" not in panel


def test_a_key_that_disappears_because_a_feature_was_turned_off_recovers_too(monkeypatch):
    """`ingest:all` a fost prinsă fiindcă a ținut 26 de ore. Una care se stinge
    repede ar fi invizibilă — de exemplu `unit:sentinel-ai.service`.

    `check_units` sare peste unitatea AI când `ai.enabled` e fals. Ordinea reală
    care doare: unitatea intră în `down`, operatorul dezactivează stratul AI ca
    să oprească zgomotul, cheia nu se mai emite — și panoul rămâne roșu pentru o
    unitate pe care nimeni n-o mai pornește, la nesfârșit."""
    from sentinel.selfcheck import runner

    db = _StateDB()
    other = CheckResult("unit:sentinel-web.service", "Serviciul sentinel-web", "ok")
    ai_down = CheckResult("unit:sentinel-ai.service", "Serviciul sentinel-ai",
                          "down", detail="stare: failed · reporniri: 12")

    monkeypatch.setattr(runner, "run_groups", _outcome([other, ai_down]))
    run(runner.run_and_alert(db, _cfg()))
    assert "nu funcționează complet" in _panel(db)

    # `ai.enabled = false` — check_units nu mai emite cheia deloc.
    monkeypatch.setattr(runner, "run_groups", _outcome([other]))
    run(runner.run_and_alert(db, _cfg()))
    assert "unit:sentinel-ai.service" not in db.state
    assert "Totul funcționează" in _panel(db)


# --- verificări care nu emit nimic când n-au putut să se uite ---------------
def test_an_unreadable_install_tree_is_unknown_not_silence(monkeypatch, tmp_path):
    """`step_package` din install.sh face `rm -rf` apoi `cp -r`, iar timerul de
    autoverificare bate la 5 minute în tot acest timp. `rglob("*.py")` poate ieși
    gol sau poate cursa un fișier care dispare.

    Verificarea returna `[]` — nicio cheie, nicio excepție — deci rularea se
    raporta COMPLETĂ, iar runner-ul ștergea constatarea `code:current` și îi
    spunea operatorului că nu se mai raportează. Constatarea aia e „servicii
    rulează cod vechi", adevărată tocmai în minutele din jurul unei instalări."""
    lib = tmp_path / "lib" / "sentinel"
    lib.mkdir(parents=True)

    def _explode(*a, **k):
        raise OSError("No such file or directory")

    monkeypatch.setattr(checks.Path, "rglob", _explode)
    monkeypatch.setattr(checks, "Path", lambda *a: lib)

    results = run(checks.check_running_code_is_current())
    assert [r.key for r in results] == ["code:current"]
    assert results[0].status == "unknown"
    assert not results[0].bad


def test_an_unreadable_proc_stat_is_unknown_not_silence(monkeypatch, tmp_path):
    """A doua ieșire tăcută din aceeași funcție, pe cealaltă ramură.

    Fără `btime` nu se poate converti momentul pornirii unui serviciu din
    monotonic în timp real, deci întrebarea „a pornit înainte sau după
    instalare?" n-are răspuns. Un `return []` aici raporta din nou o rulare
    completă fără cheia `code:current`, iar constatarea era ștearsă."""
    import builtins

    lib = tmp_path / "lib" / "sentinel"
    lib.mkdir(parents=True)
    (lib / "x.py").write_text("# cod", encoding="utf-8")
    monkeypatch.setattr(checks, "Path", lambda *a: lib)
    # Un serviciu chiar a pornit, deci bucla ajunge la citirea lui /proc/stat.
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "123456789")

    real_open = builtins.open

    def _no_proc(path, *a, **k):
        if str(path) == "/proc/stat":
            raise OSError("Permission denied")
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", _no_proc)

    results = run(checks.check_running_code_is_current())
    assert [r.key for r in results] == ["code:current"]
    assert results[0].status == "unknown"
    assert "/proc/stat" in results[0].detail


def test_a_missing_install_tree_stays_silent(monkeypatch, tmp_path):
    """Singura tăcere rămasă, și singura sigură: pe o gazdă fără arbore instalat
    cheia nu s-a emis niciodată, deci nu există constatare de retras."""
    monkeypatch.setattr(checks, "Path", lambda *a: tmp_path / "nu-exista")
    assert run(checks.check_running_code_is_current()) == []


def test_an_unreadable_ruleset_still_reports_the_blocklist_comparison(monkeypatch):
    """Aceeași regulă, celălalt loc unde se aplica: când regulile nftables nu se
    pot citi, `check_enforcement` ieșea devreme și nu mai emitea `nft:count`.

    Rularea rămâne completă (nimeni n-a ridicat), deci o constatare adevărată —
    „blocklistul din bază nu corespunde cu kernelul" — era ștearsă fiindcă
    verificarea n-a putut să se uite."""
    monkeypatch.setattr(checks, "_nft_table_present",
                        lambda: (None, "Operation not permitted"))
    monkeypatch.setenv("INVOCATION_ID", "test")
    results = run(checks.check_enforcement(_DB(val=7), _cfg()))
    keys = {r.key for r in results}
    assert keys == {"nft:table", "nft:count"}
    assert all(r.status == "unknown" for r in results)
    assert all(not r.bad for r in results)


def test_the_operator_is_told_the_red_line_is_gone(monkeypatch):
    """Operatorul a primit „🔴 Toate sursele au amuțit". Dacă nimeni nu-i spune
    că nu mai e cazul, ultimul mesaj rămâne adevărul lui — iar panoul, reparat,
    contrazice în tăcere alerta.

    Mesajul spune exact cât se știe: verificarea nu mai produce constatarea. Nu
    „revenit la normal" — o cheie poate dispărea și fiindcă verificarea nu o mai
    acoperă (o unitate dezactivată în config, o sursă ieșită din fereastra de 30
    de zile), iar diferența nu se poate stabili de aici."""
    from sentinel.selfcheck import runner

    db = _StateDB()
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, _ALL_QUIET]))
    run(runner.run_and_alert(db, _cfg()))
    db.notifications.clear()

    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE]))
    summary = run(runner.run_and_alert(db, _cfg()))

    assert summary["withdrawn"] == ["ingest:all"]
    assert db.notifications, "nimeni nu i-a spus operatorului"
    text = db.notifications[-1]
    assert "Toate sursele au amuțit" in text
    assert "Nu se mai raportează" in text
    assert "Revenit la normal" not in text, "afirmă mai mult decât se știe"


def test_a_withdrawn_ok_row_is_not_announced(monkeypatch):
    """Un rând care era deja verde și dispare nu e o veste. Un mesaj pentru
    fiecare non-eveniment e felul în care canalul ajunge să nu mai fie citit."""
    from sentinel.selfcheck import runner

    db = _StateDB()
    extra = CheckResult("unit:sentinel-ai.service", "Serviciul sentinel-ai", "ok")
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, extra]))
    run(runner.run_and_alert(db, _cfg()))
    db.notifications.clear()

    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE]))
    summary = run(runner.run_and_alert(db, _cfg()))
    assert "unit:sentinel-ai.service" not in db.state
    assert summary["withdrawn"] == []
    assert not db.notifications


def test_an_interrupted_run_does_not_clean_up_state(monkeypatch):
    """Celălalt sens al aceleiași greșeli. O cheie poate lipsi dintr-o rulare și
    fiindcă grupul care o produce a crăpat — atunci ștergerea ar transforma o
    verificare stricată într-un buletin de sănătate curat. Exact schimbul pe
    care întreg pachetul ăsta există ca să-l împiedice."""
    from sentinel.selfcheck import runner

    db = _StateDB()
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, _ALL_QUIET]))
    run(runner.run_and_alert(db, _cfg()))
    db.notifications.clear()

    # Grupul „ingest" crapă: nu emite nicio cheie a lui, doar propriul eșec.
    broken = CheckResult("selfcheck:ingest", "Verificarea „ingest” a eșuat", "unknown",
                         detail="connection reset")
    monkeypatch.setattr(runner, "run_groups", _outcome([broken], failed=("ingest",)))
    summary = run(runner.run_and_alert(db, _cfg()))

    assert "ingest:all" in db.state, "starea a fost curățată de o rulare incompletă"
    assert db.state["ingest:all"]["status"] == "down"
    assert db.state["ingest:all"]["stale"] is True
    assert summary["withdrawn"] == []
    assert summary["incomplete"] == ["ingest"]
    assert not db.notifications, "o rulare întreruptă nu anunță nicio revenire"


def test_a_kept_row_is_shown_as_a_finding_not_as_an_outage(monkeypatch):
    """„de 27h 54m" lângă un titlu care descrie o pană curentă se citește ca
    durata penei. Era vechimea rândului blocat.

    Un rând păstrat peste o rulare întreruptă e ultima constatare cunoscută, nu
    starea de acum, iar panoul trebuie să spună asta cu cuvinte."""
    from sentinel.selfcheck import runner

    db = _StateDB()
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, _ALL_QUIET]))
    run(runner.run_and_alert(db, _cfg()))

    broken = CheckResult("selfcheck:ingest", "Verificarea „ingest” a eșuat", "unknown")
    monkeypatch.setattr(runner, "run_groups", _outcome([broken], failed=("ingest",)))
    run(runner.run_and_alert(db, _cfg()))

    panel = _panel(db)
    assert "Neevaluate la ultima rulare" in panel
    assert "constatare veche de" in panel
    assert "ultima constatare, nu starea de acum" in panel
    # Nu dispare din verdict: ultimul lucru știut e că era stricat.
    assert "nu funcționează complet" in panel
    # Iar verificarea care a crăpat e vizibilă, nu tăcută.
    assert "a eșuat" in panel


def test_the_next_complete_run_finally_clears_what_the_crash_preserved(monkeypatch):
    """Altfel „păstrează la rulare incompletă" ar fi doar o altă cale către un
    rând care nu moare niciodată."""
    from sentinel.selfcheck import runner

    db = _StateDB()
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, _ALL_QUIET]))
    run(runner.run_and_alert(db, _cfg()))
    broken = CheckResult("selfcheck:ingest", "Verificarea „ingest” a eșuat", "unknown")
    monkeypatch.setattr(runner, "run_groups", _outcome([broken], failed=("ingest",)))
    run(runner.run_and_alert(db, _cfg()))
    assert db.state["ingest:all"]["stale"] is True

    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE]))
    run(runner.run_and_alert(db, _cfg()))
    assert "ingest:all" not in db.state
    assert "Totul funcționează" in _panel(db)


def test_a_run_that_produced_nothing_deletes_nothing(monkeypatch):
    """Zero rezultate nu e dovadă că totul e în regulă, e dovadă că nimic n-a
    rulat. Reconcilierea pe o listă goală ar goli toată tabela — versiunea cea
    mai zgomotoasă a bug-ului pe care fișierul ăsta îl repară."""
    from sentinel.selfcheck import runner

    db = _StateDB()
    monkeypatch.setattr(runner, "run_groups", _outcome([_LIVE, _ALL_QUIET]))
    run(runner.run_and_alert(db, _cfg()))

    monkeypatch.setattr(runner, "run_groups", _outcome([]))
    run(runner.run_and_alert(db, _cfg()))
    assert set(db.state) == {"ingest:suricata", "ingest:all"}


def test_a_crashed_group_is_named_by_the_run(monkeypatch):
    """Reconcilierea se sprijină pe „rularea a văzut tot". Dacă `run_groups` ar
    raporta o rulare crăpată drept completă, ștergerea ar porni exact în cazul
    în care nu are voie."""
    async def _boom(db, cfg):
        raise RuntimeError("nft exploded")

    monkeypatch.setattr(checks, "CHECKS", (("enforcement", _boom),
                                           ("autonomy", checks.check_autonomy)))
    outcome = run(checks.run_groups(_DB(), _cfg()))
    assert outcome.failed_groups == ("enforcement",)
    assert outcome.complete is False
    assert any(r.key == "mode:autoblock" for r in outcome.results), "rularea s-a oprit"

    monkeypatch.setattr(checks, "CHECKS", (("autonomy", checks.check_autonomy),))
    assert run(checks.run_groups(_DB(), _cfg())).complete is True


def _service_log(monkeypatch, summary):
    """Rulează `sentinel selfcheck` cu un rezumat dat și întoarce (nivel, mesaj)."""
    from sentinel.services import selfcheck_service as svc

    class _FakeDB:
        def __init__(self, *a, **k):
            pass

        async def connect(self):
            pass

        async def close(self):
            pass

    async def _fake_run(db, cfg, *, quiet=False):
        return summary

    seen: list[tuple[str, str]] = []
    monkeypatch.setattr(svc, "get_config", lambda: _cfg())
    monkeypatch.setattr(svc, "Database", _FakeDB)
    monkeypatch.setattr(svc, "run_and_alert", _fake_run)
    monkeypatch.setattr(svc.log, "warning", lambda m, **k: seen.append(("warning", m)))
    monkeypatch.setattr(svc.log, "info", lambda m, **k: seen.append(("info", m)))
    run(svc._main(True, False))
    return seen


_CLEAN = {"worst": "ok", "checks": 33, "bad": [], "new": [], "recovered": [],
          "withdrawn": [], "incomplete": [], "duration_ms": 710}


def test_an_incomplete_run_is_not_logged_as_clean(monkeypatch):
    """O rulare în care un grup a crăpat nu găsește defecte fiindcă nu s-a
    uitat, iar `worst()` clasează `unknown` deasupra lui `degraded`, deci codul
    de ieșire e 0 și systemd e mulțumit.

    Se loga „selfcheck clean", la INFO — exact cuvântul pe care operatorul îl
    caută, pus pe singura rulare care n-a dovedit nimic, invizibilă la
    `journalctl -p warning`."""
    seen = _service_log(monkeypatch, {**_CLEAN, "worst": "unknown",
                                      "incomplete": ["enforcement"]})
    assert seen == [("warning", "selfcheck found problems")]


def test_a_complete_clean_run_is_still_logged_as_clean(monkeypatch):
    """Reversul: dacă ORICE rulare s-ar loga ca problemă, avertismentul n-ar mai
    însemna nimic."""
    assert _service_log(monkeypatch, _CLEAN) == [("info", "selfcheck clean")]


def test_a_timer_whose_state_cannot_be_read_stays_on_the_list(monkeypatch):
    """`systemctl` care nu răspunde (lipsă, eroare, timeout de 10s) returnează
    un șir gol. Verificarea sărea peste cheie — iar de când o cheie absentă
    dintr-o rulare completă e ștearsă, o singură sondă lentă ar retrage o
    constatare `down` și i-ar spune operatorului că nu mai e raportată.

    „Nu se știe" și „e bine" sunt stări diferite."""
    monkeypatch.setattr(checks, "_systemctl", lambda *a: "")
    results = run(checks.check_timers(_cfg()))
    assert results, "timerele au dispărut din rulare"
    assert {r.status for r in results} == {"unknown"}
    assert all(not r.bad for r in results)
    assert "nu am putut citi" in results[0].detail


# --- the unit ---------------------------------------------------------------
def test_the_timer_starts_soon_after_boot():
    """Both real outages were post-reboot states. Waiting five minutes to learn
    the machine came back wrong is four minutes too many."""
    from pathlib import Path

    timer = (Path(__file__).resolve().parents[2] / "deploy" / "systemd"
             / "sentinel-selfcheck.timer").read_text(encoding="utf-8")
    assert "OnBootSec=" in timer
    assert "OnUnitActiveSec=5min" in timer


def test_the_unit_can_read_the_ruleset_but_not_change_it():
    """Reading nftables needs NET_ADMIN. Bounded to exactly that: changing the
    ruleset is the executor's job and nobody else's."""
    from pathlib import Path

    unit = (Path(__file__).resolve().parents[2] / "deploy" / "systemd"
            / "sentinel-selfcheck.service").read_text(encoding="utf-8")
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in unit
    assert "User=sentinel" in unit
    # Findings are not failures of this unit.
    assert "SuccessExitStatus=0 1 2" in unit


def test_the_anti_lockout_watchdog_was_left_alone():
    """It is root, dependency-free, and must stay tiny. Merging the self-check
    into it would make the one component that has to work when everything else
    has failed depend on everything else."""
    from pathlib import Path

    unit = (Path(__file__).resolve().parents[2] / "deploy" / "systemd"
            / "sentinel-watchdog.service").read_text(encoding="utf-8")
    assert "selfcheck" not in unit
    assert "User=root" in unit


def test_being_unable_to_read_the_ruleset_is_not_the_same_as_it_missing(monkeypatch):
    """Opposite conclusions. "Table missing" means the host is unprotected; "I
    was not allowed to look" means the check is broken. Reporting the first when
    the second is true is a false alarm about the most serious thing this file
    can say — and a channel that cries wolf about total loss of protection is a
    channel that stops being read."""
    monkeypatch.setattr(checks, "_nft_table_present",
                        lambda: (None, "Operation not permitted (you must be root)"))
    # Sub systemd, unde sfatul despre capabilitate e cel corect. Varianta
    # rulată manual e verificată separat, mai jos.
    monkeypatch.setenv("INVOCATION_ID", "test")
    result = run(checks.check_enforcement(_DB(val=0), _cfg()))[0]
    assert result.status == "unknown"
    assert "nu știu dacă blocarea funcționează" in result.detail
    assert "CAP_NET_ADMIN" in result.action


def test_a_service_running_older_code_than_is_installed_is_flagged(monkeypatch, tmp_path):
    """A deploy copies files; only a restart makes a process use them. When
    those come apart, the fix is on disk and the bug is in memory, and "is this
    fixed on the server?" has no answer you can trust.

    Found the hard way: the installer restarted two of six units."""
    import inspect

    src = inspect.getsource(checks.check_running_code_is_current)
    assert "ActiveEnterTimestampMonotonic" in src
    assert "systemctl restart" in src          # the action tells you the fix
    assert "code:current" in src


def test_the_installer_restarts_every_service():
    """Two of six is a partial upgrade that reports success."""
    from pathlib import Path

    install = (Path(__file__).resolve().parents[2] / "deploy"
               / "install.sh").read_text(encoding="utf-8")
    order = install.split("local -a order=(", 1)[1].split(")", 1)[0]
    for unit in ("sentinel-executor", "sentinel-web", "sentinel-ingest",
                 "sentinel-detect", "sentinel-telegram"):
        assert unit in order, f"{unit} is never restarted by a deploy"


# --- boot reconciliation ----------------------------------------------------
def test_reconcile_calls_block_with_the_signature_that_exists():
    """A keyword that does not exist raises at the moment it is needed — which
    for `--reapply` is after a reboot, when nobody is watching."""
    import inspect

    from sentinel.respond import actions, reconcile as rec

    params = inspect.signature(actions.block).parameters
    src = inspect.getsource(rec.reconcile)
    for kw in ("ttl=", "reason=", "by="):
        assert kw in src
        assert kw.rstrip("=") in params


def test_reconcile_corrects_the_database_not_the_kernel_by_default():
    """The kernel is the truth about what is blocked; after a reboot that truth
    is "nothing". Re-applying by default would quietly remove the escape hatch
    the whole design leans on."""
    import inspect

    from sentinel.respond import reconcile as rec

    src = inspect.getsource(rec.reconcile)
    # The default branch runs from `if not reapply:` to its own `return`.
    # Splitting on `for row in missing:` would not work — the default branch
    # opens with one of those too.
    default = src.split("if not reapply:", 1)[1].split("return result", 1)[0]
    assert "mark_unblocked" in default
    assert "actions.block" not in default


def test_the_release_is_written_down_with_a_reason():
    """An attacker who was blocked and is now not is a fact worth finding later."""
    import inspect

    from sentinel.respond import reconcile as rec

    assert "repornire" in inspect.getsource(rec.reconcile)


def test_the_executor_recreates_the_table_before_accepting_work():
    """Every block against a missing table fails. Recreating it after the socket
    opens would leave a window where blocking silently does nothing."""
    from pathlib import Path

    src = (Path(__file__).resolve().parents[2] / "executor"
           / "sentinel_executor.py").read_text(encoding="utf-8")
    body = src.split("def main(", 1)[1]
    assert body.index("ensure_table()") < body.index("socket.socket")


def test_the_executor_restores_the_allowlist_but_not_the_blocklist():
    """A table with drop rules and no allowlist is how you firewall your own
    address. A table WITH the blocklist restored is how a reboot stops being an
    escape from a self-inflicted block."""
    from pathlib import Path

    commands = (Path(__file__).resolve().parents[2] / "executor"
                / "commands.py").read_text(encoding="utf-8")
    body = commands.split("def ensure_table", 1)[1].split("\ndef ", 1)[0]
    assert "NFT_ALLOWLIST_FILE" in body
    # Strip the docstring as well as the comments: it EXPLAINS that blocks are
    # not restored, so a naive text search finds the word it is looking for in
    # the sentence promising the opposite.
    code = body.split('"""')[2] if body.count('"""') >= 2 else body
    code = "\n".join(l for l in code.splitlines() if not l.strip().startswith("#"))
    assert "blocklist" not in code.lower(), "the blocklist is being restored"


# --- un mesaj care nu trimite operatorul pe pistă greșită ------------------
def test_nft_check_distinguishes_a_hand_run_from_a_misconfigured_unit(monkeypatch):
    """Capabilitățile vin de la unitate, nu de la utilizator.

    `sudo -u sentinel sentinel selfcheck --print` nu primește CAP_NET_ADMIN
    oricât de corectă ar fi unitatea. Mesajul vechi trimitea operatorul să
    verifice un fișier care era deja bun — iar cine e trimis de două ori după
    un non-problem se oprește din citit ieșirea.
    """
    import asyncio as _a
    from types import SimpleNamespace
    from sentinel.selfcheck import checks as c

    monkeypatch.setattr(c, "_nft_table_present", lambda: (None, "Operation not permitted"))
    cfg = SimpleNamespace(response=SimpleNamespace(admin_ip=None))

    monkeypatch.delenv("INVOCATION_ID", raising=False)
    hand = _a.run(c.check_enforcement(None, cfg))[0]
    assert "Rulat manual" in hand.detail
    assert "systemctl start sentinel-selfcheck" in (hand.action or "")

    monkeypatch.setenv("INVOCATION_ID", "abc123")
    unit = _a.run(c.check_enforcement(_DB(val=0), _cfg()))[0]
    assert "Rulat manual" not in unit.detail
    assert "AmbientCapabilities" in (unit.action or "")

    # În ambele cazuri starea rămâne „nu știu" — a nu putea citi regulile NU e
    # o dovadă că blocarea funcționează.
    assert hand.status == unit.status == "unknown"


def test_a_direct_alert_telegram_refused_is_not_logged_as_delivered(monkeypatch, caplog):
    """The escalation path exists for the moment the bot is dead. Until now it
    logged "selfcheck alerted directly" after any POST that did not raise — so
    a 400 ("chat not found", "bot was blocked by the user") produced the same
    line as a delivered message.

    That is the last channel there is, reporting success it did not have. The
    operator would read one warning about a dead bot and believe they had been
    told; nothing else would ever mention it again.

    The fake asserts Telegram's contract: 200 + {"ok": true, "result":
    {"message_id": N}} is delivery, a 4xx with {"ok": false, "description": …}
    is not.
    """
    import asyncio as _a
    import logging

    import httpx

    from sentinel import config as config_mod
    from sentinel.config import Secrets
    from sentinel.selfcheck import runner

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read().decode("utf-8")
        if '"chat_id": 222' in body or '"chat_id":222' in body:
            return httpx.Response(400, json={"ok": False,
                                             "description": "Bad Request: chat not found"})
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 3}})

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda **kw: real_client(transport=transport, **kw))
    monkeypatch.setattr(config_mod, "get_secrets",
                        lambda: Secrets({"TELEGRAM_BOT_TOKEN": "fixture-token"}))

    cfg = SimpleNamespace(telegram=SimpleNamespace(allowed_chat_ids=[111, 222]))
    with caplog.at_level(logging.INFO, logger="sentinel.selfcheck.runner"):
        _a.run(runner._send_direct(cfg, "botul nu răspunde"))

    levels = {r.levelno: r.getMessage() for r in caplog.records}
    assert logging.ERROR in levels, "the refused chat was never reported"
    assert "did not reach every chat" in levels[logging.ERROR]
    assert logging.WARNING in levels, "the chat that DID receive it went unreported"


# ---------------------------------------------------------------------------
# Filtrul de istoric: „configurat" și „în vigoare" sunt afirmații diferite
# ---------------------------------------------------------------------------
def _cu_uid(monkeypatch, uid_of):
    """Rezolvarea conturilor, cu o bază de conturi fabricată.

    Gazda de test nu are `sentinel-deploy` în `/etc/passwd`, iar pe Windows nu
    există `pwd` deloc — deci fără injecția asta testele ar proba platforma pe
    care rulează, nu decizia verificării.
    """
    from sentinel.config import resolve_skip_command_accounts as real

    monkeypatch.setattr(checks, "resolve_skip_command_accounts",
                        lambda n: real(n, uid_of=uid_of))


def _istoric(**over):
    """Un `cfg` cu secțiunea `history`, plus dublul de bază pentru efect."""
    return _cfg(history=SimpleNamespace(**over))


@pytest.fixture(autouse=True)
def _config_intr_un_loc_care_nu_exista(monkeypatch, tmp_path):
    """`sentinel.yaml.new` se caută lângă configurația încărcată.

    Pe o mașină pe care fișierul ăla chiar există — gazda —, testele care nu-l
    fabrică singure ar citi starea gazdei și ar pica sau ar trece în funcție de
    ea. Toate pornesc de la „nu există", iar cine are nevoie de el îl scrie.
    """
    monkeypatch.setattr(checks, "CONFIG_PATH", tmp_path / "sentinel.yaml")


def _felie(username, fara_terminal, cu_terminal=0, ora=0):
    """Comenzile unui cont într-o ORĂ, despărțite după terminal.

    Se dau ca grupuri, nu ca rânduri, ca un test să poată descrie 174 839 de
    comenzi fără să le construiască. Cine le numără cum e treaba dublului, iar
    el CITEȘTE regula din instrucțiunea primită — vezi `_HistDB.fetch`.

    `ora` e câte ore în urmă e găleata. Gruparea pe oră e chiar unitatea în care
    s-au măsurat și furtuna de deploy, și munca de om.
    """
    inceput = NOW - timedelta(hours=ora)
    return {"username": username,
            "ora": inceput.replace(minute=0, second=0, microsecond=0),
            "fara_terminal": fara_terminal,
            "cu_terminal": cu_terminal,
            "oldest": inceput - timedelta(minutes=59),
            "newest": inceput}


class _HistDB(_DB):
    """Dublu care răspunde la CELE DOUĂ interogări ale verificării.

    Se cere textul instrucțiunii, nu doar rezultatul: verificarea trebuie să
    întrebe despre rândurile care N-AR TREBUI SĂ EXISTE, nu despre configurație.
    Parametrii se rețin, fiindcă o fereastră schimbată tăcut e chiar felul în
    care verificarea ar înceta să vadă un deploy fără ca nimic să pice.

    Regula de terminal NU e reimplementată din memorie: se citește din chiar
    instrucțiunea dată, cu chiar tiparul trimis ca parametru. O interogare care
    ar pierde `FILTER`-ul ar număra și comenzile tastate de un om — și ar
    răspunde exact ca dublul care „știe" răspunsul bun.
    """

    def __init__(self, *, total=0, interzise=0, newest=None, felie=None):
        super().__init__()
        self.total, self.interzise, self.newest = total, interzise, newest
        self.felie = felie if felie is not None else []
        self.params: list[tuple] = []

    async def fetch(self, sql, *a):
        self.sql.append(sql)
        self.params.append(a)
        assert "FROM session_commands" in sql, sql
        assert "ORDER BY ts DESC" in sql, sql
        assert "LIMIT $1" in sql, sql
        # Felia se ia după `ts DESC` ÎNAINTE de orice filtrare pe `tty`: predicatul
        # de terminal n-are voie să apară în `WHERE`-ul CTE-ului (înainte de
        # `LIMIT`), altfel costul ar depinde de câte comenzi cu terminal are gazda,
        # iar felia n-ar mai fi mărginită prin construcție. Mutat acolo, testul
        # ăsta pică; lăsat în `FILTER`-ul de după CTE, trece.
        assert "tty IS NULL OR tty !~" not in sql.split("LIMIT $1")[0], sql

        tipar = a[2]
        are_filtru = "FILTER (WHERE tty IS NULL OR tty !~ $3)" in sql
        # Și gruparea se citește din instrucțiune: fără ora din `GROUP BY`,
        # serverul întoarce O SINGURĂ găleată pe cont, adică totalul lui pe toată
        # felia. Dublul trebuie să facă la fel, altfel testul care spune «o zi
        # întinsă nu e o furtună» ar trece peste chiar interogarea care nu mai
        # poate deosebi ziua de rafală.
        pe_ora = "GROUP BY 1, 2" in sql
        randuri: dict[tuple, dict] = {}
        for g in self.felie:
            comenzi = [(None, g["fara_terminal"]), ("pts0", g["cu_terminal"])]
            total = sum(n for _, n in comenzi)
            fara = (sum(n for tty, n in comenzi
                        if tty is None or not re.match(tipar, tty))
                    if are_filtru else total)
            cheie = (g["username"], g["ora"]) if pe_ora else (g["username"],)
            r = randuri.setdefault(cheie, {
                "username": g["username"], "ora": g["ora"], "total": 0,
                "fara_terminal": 0, "oldest": g["oldest"], "newest": g["newest"]})
            r["total"] += total
            r["fara_terminal"] += fara
            r["oldest"] = min(r["oldest"], g["oldest"])
            r["newest"] = max(r["newest"], g["newest"])
        return list(randuri.values())

    async def fetchrow(self, sql, *a):
        self.sql.append(sql)
        self.params.append(a)
        assert "FROM session_commands" in sql, sql
        assert "tty IS NULL OR tty !~" in sql, sql
        # `newest` trebuie să fie `max(ts)` peste RÂNDURILE INTERZISE, nu peste
        # toate: un `max(ts)` nefiltrat ar aluneca pe o comandă tastată legitim și
        # ar data „acum" un set de rânduri interzise vechi, acuzând filtrul pentru
        # ce a scris procesul dinainte.
        assert "max(ts) FILTER" in sql, sql
        return {"total": self.total, "interzise": self.interzise,
                "newest": self.newest}


def test_an_empty_history_section_is_reported_as_dropping_nothing():
    """Lista goală, pe o gazdă unde nimic n-o contrazice, e o stare VALIDĂ.

    O gazdă care păstrează tot istoricul e implicitul livrat, nu o defecțiune —
    deci nu are voie să iasă roșu. Ce s-a schimbat pe 25 august 2026 e că `ok`-ul
    ăsta nu mai vine din configurație: se dă numai după ce datele au fost
    întrebate și n-au arătat nicio furtună, și după ce s-a verificat că nu zace
    un `sentinel.yaml.new` care cere altceva.
    """
    r = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=[])))[0]
    assert r.status == "ok", "lista goală raportată ca defect"
    assert r.key == "history:filter"
    assert "gol" in r.detail
    assert "datele n-o contrazic" in r.detail, (
        "`ok`-ul nu spune pe ce se sprijină, deci nu se poate deosebi de unul "
        "dat înainte de orice întrebare pusă bazei")


def test_an_unmerged_new_file_makes_the_empty_filter_a_finding(tmp_path, monkeypatch):
    """Starea reală a gazdei pe 25 august 2026, raportată `ok` de prima scriere.

    `/etc/sentinel/sentinel.yaml` era din 20 august și NU avea secțiunea
    `history:`; lângă el stăteau `sentinel.yaml.new` și `inventory.yaml.new` din
    25 august, neîmbinate. Verificarea ieșea pe ramura «listă goală» și întorcea
    `ok` înainte de orice SQL — deci verificarea scrisă tocmai ca să deosebească
    intenția de efect nu deosebea «am ales să nu arunc nimic» de «nimeni n-a
    îmbinat fișierul», iar în tabelă erau 1 266 de rânduri interzise.

    Discriminatorul e chiar fișierul: dacă `.new` cere conturi pe care
    configurația încărcată nu le are, filtrul pe care operatorul crede că l-a
    pornit nu rulează nicăieri.
    """
    monkeypatch.setattr(checks, "CONFIG_PATH", tmp_path / "sentinel.yaml")
    (tmp_path / "sentinel.yaml.new").write_text(
        "history:\n  skip_command_accounts:\n    - sentinel-deploy\n",
        encoding="utf-8")

    r = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=[])))[0]
    assert r.status == "degraded", "configurația neîmbinată a trecut drept aleasă"
    assert "sentinel-deploy" in r.detail
    assert "sentinel.yaml.new" in r.detail
    assert "diff" in r.action, "operatorul nu primește pasul care arată diferența"
    assert r.facts["unmerged_accounts"] == ["sentinel-deploy"]


def test_a_new_file_that_says_the_same_thing_is_not_a_finding(tmp_path, monkeypatch):
    """Instalatorul scrie `.new` la FIECARE rulare, îmbinat sau nu.

    Dacă simpla lui prezență ar fi un defect, verificarea ar fi roșie permanent
    pe orice gazdă livrată de două ori — iar o constatare care nu se stinge
    niciodată e cum ajunge operatorul să nu mai citească niciuna.
    """
    monkeypatch.setattr(checks, "CONFIG_PATH", tmp_path / "sentinel.yaml")
    (tmp_path / "sentinel.yaml.new").write_text(
        "history:\n  skip_command_accounts:\n    - sentinel-deploy\n"
        "web:\n  port: 8443\n", encoding="utf-8")

    _cu_uid(monkeypatch, lambda _n: 1002)
    r = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=["sentinel-deploy"])))[0]
    assert r.status == "ok", r.detail


def test_a_stale_new_file_does_not_call_a_hand_merged_filter_unmerged(
        tmp_path, monkeypatch):
    """Reacția firească la constatarea de deasupra n-are voie s-o facă permanentă.

    Operatorul citește «configurația filtrului n-a fost îmbinată», deschide
    `/etc/sentinel/sentinel.yaml` și adaugă contul de mână. Atât trebuia făcut, și
    filtrul chiar rulează după repornire. Dar `.new` rămâne pe disc așa cum era —
    pe gazdă e cel din 25 august 2026, fără secțiunea `history:` deloc.

    Comparate pe EGALITATE, cele două fișiere ar face constatarea roșie pentru
    totdeauna, cu un text care spune exact pe dos: că filtrul nu e îmbinat,
    tocmai când el e cel care rulează. Iar o constatare care nu se stinge
    niciodată e cum ajunge operatorul să nu mai citească niciuna — și ar lua cu
    ea furtunile adevărate, care se raportează sub aceeași cheie.
    """
    monkeypatch.setattr(checks, "CONFIG_PATH", tmp_path / "sentinel.yaml")
    # Un `.new` dinaintea filtrului: valid, doar că nu știe de `history:`.
    (tmp_path / "sentinel.yaml.new").write_text(
        "web:\n  port: 8443\n", encoding="utf-8")

    _cu_uid(monkeypatch, lambda _n: 1002)
    r = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=["sentinel-deploy"])))[0]
    assert r.status == "ok", r.detail
    assert r.facts["unmerged_new"] is True, (
        "cazul n-a mai trecut prin ramura care citește `.new`, deci nu probează "
        "nimic despre comparația dintre cele două fișiere")
    assert r.facts["unmerged_missing"] == []

    # Celălalt sens, în același test, ca reparația să nu poată fi «nu mai compar
    # deloc»: un cont cerut de `.new` și absent din cea încărcată rămâne roșu,
    # chiar dacă încărcată numește alte conturi.
    (tmp_path / "sentinel.yaml.new").write_text(
        "history:\n  skip_command_accounts:\n    - sentinel-deploy\n"
        "    - altcineva\n", encoding="utf-8")
    r2 = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=["sentinel-deploy"])))[0]
    assert r2.status == "degraded", r2.detail
    assert r2.facts["unmerged_missing"] == ["altcineva"]
    assert "altcineva" in r2.detail


def test_a_new_file_that_cannot_be_read_is_unknown_not_ok(tmp_path, monkeypatch):
    """„Nu pot citi" și „nu e nimic acolo" nu au voie să arate la fel.

    Un `.new` cu drepturi greșite sau cu YAML stricat lasă întrebarea «filtrul
    încărcat e cel scris de instalator?» fără răspuns. Raportat `ok`, ar fi exact
    tiparul din `CLAUDE.md`: un mecanism care confirmă că n-a găsit nimic, când
    de fapt n-a putut să se uite.
    """
    monkeypatch.setattr(checks, "CONFIG_PATH", tmp_path / "sentinel.yaml")
    (tmp_path / "sentinel.yaml.new").write_text(
        "history:\n  skip_command_accounts:\n   - a\n  - b\n", encoding="utf-8")

    r = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=[])))[0]
    assert r.status == "unknown", r.detail
    assert "sentinel.yaml.new" in r.detail


def test_a_storm_on_an_account_outside_the_filter_is_a_finding():
    """Întrebarea pusă DATELOR, care nu depinde de ce a tastat cineva.

    Măsurat pe gazdă: `scripts/deploy.sh` cerea `--user`, deci deploy-urile
    rulau sub contul de logare al operatorului și scriau 174 839, 456 133 și
    2 158 596 de comenzi fără terminal pe oră sub numele lui. Contul ăla NU e în
    filtru și nici nu poate fi — sub el rulează și diagnosticele lui.

    Nicio verificare pe configurație n-ar fi văzut asta: configurația era
    perfect corectă, doar că deploy-ul nu rula sub contul pe care îl numea. Aici
    se întreabă cine scrie, nu ce s-a configurat, deci se vede la fel de bine o
    invocație cu contul vechi, un cont nou apărut sau o secțiune neîmbinată.
    """
    # O oră de deploy, sub cea mai săracă măsurată (174 839), plus o oră liniștită
    # a aceluiași cont: rafala NU are voie să se dilueze în medie.
    db = _HistDB(felie=[_felie("operator", 174_839, cu_terminal=200, ora=1),
                        _felie("operator", 40, ora=0),
                        _felie("root", 0, cu_terminal=30, ora=0)])
    r = run(checks.check_command_history_filter(
        db, _istoric(skip_command_accounts=[])))[0]

    assert r.status == "degraded", r.detail
    # Cu ghilimelele din mesaj: „operator" e și un cuvânt care apare prin
    # texte, iar o căutare simplă ar putea trece fără ca numele contului să fie
    # spus vreodată.
    assert "„operator”" in r.detail, r.detail
    assert r.facts["top_account"] == "operator"
    assert r.facts["top_peak_hour"] == 174_839, (
        "ora de vârf s-a pierdut într-o medie peste toată felia")
    assert any("ORDER BY ts DESC" in s for s in db.sql), (
        "verificarea n-a întrebat datele deloc")

    # Contra-proba pentru chiar mecanismul de mai sus: aceleași 174 879 de
    # comenzi, dar întinse peste 24 de ore de rutină, NU sunt o furtună. Fără
    # cazul ăsta, un prag pus pe TOTAL în loc de pe oră ar trece neobservat.
    intinse = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("operator", 7_286, ora=h) for h in range(24)]),
        _istoric(skip_command_accounts=[])))[0]
    assert intinse.status == "ok", intinse.detail


def test_a_slice_full_of_typed_commands_is_not_a_storm():
    """Regula e despre comenzile FĂRĂ terminal, și numai despre ele.

    Cineva care compilează la tastatură produce zeci de mii de `execve` într-o
    oră, toate cu `pts0`. Numărate ca automatizare, ar da o constatare roșie
    pentru munca omului — și, mai rău, ar cere ștergerea exact a istoricului care
    are valoare de securitate. Filtrul viu le păstrează; verificarea trebuie să
    se uite la aceleași rânduri ca el.
    """
    r = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("om", 0, cu_terminal=60_000, ora=0)]),
        _istoric(skip_command_accounts=[])))[0]
    assert r.status == "ok", r.detail
    assert r.facts["top_peak_hour"] == 0
    assert "niciuna fără terminal" in r.detail


def test_the_storm_is_attributed_to_the_burst_not_to_the_biggest_total():
    """Contul cu cele mai multe rânduri nu e neapărat cel care face rău.

    Pe gazdă, contul de logare al operatorului are 2,79 milioane de comenzi fără
    terminal adunate în luni de zile, iar contul de automatizare are 1 365. Un
    „cel mai activ" ales după TOTAL ar numi mereu primul cont și ar raporta
    liniștit ritmul lui — adică o rafală de deploy pe alt cont ar trece
    neobservată exact fiindcă victoria la total e deja luată.

    Ce contează e ora de vârf: cine a scris cele mai multe într-o oră.
    """
    felie = [_felie("om", 3_000, cu_terminal=50, ora=h) for h in range(20)]
    felie.append(_felie("automat", 25_000, ora=0))
    r = run(checks.check_command_history_filter(
        _HistDB(felie=felie), _istoric(skip_command_accounts=[])))[0]

    assert r.facts["top_account"] == "automat", (
        "contul numit e cel cu totalul cel mai mare, nu cel care a făcut rafala")
    assert r.facts["top_peak_hour"] == 25_000
    assert r.status == "degraded", r.detail


def test_a_day_of_human_diagnostics_is_not_a_storm():
    """Contra-cazul, și e cel care decide dacă alerta merită citită.

    Măsurat pe gazdă după migrarea pe contul de deploy: operatorul a scris 2 438
    de comenzi fără terminal într-o oră, apoi 355 — `ssh gazdă 'ceva'` n-are
    terminal, deci diagnosticul de la distanță arată exact ca o automatizare, în
    formă, și diferă doar în ritm. Un prag care ar semnala asta ar da o
    constatare la fiecare zi de lucru, iar un canal care se plânge zilnic degeaba
    nu mai e citit când se plânge de un deploy adevărat.
    """
    r = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("operator", 2_438, cu_terminal=120, ora=1),
                       _felie("operator", 355, cu_terminal=20, ora=0)]),
        _istoric(skip_command_accounts=[])))[0]
    assert r.status == "ok", r.detail
    assert "2438" in r.detail.replace(" ", "") or "2 438" in r.detail


def test_the_report_says_how_far_back_the_sample_could_see():
    """O felie de 20 000 de comenzi nu e o fereastră de 48 de ore.

    Interogarea e mărginită dinadins — rulează la 5 minute pe o tabelă de
    milioane de rânduri —, deci pe o gazdă vorbăreață ea vede ultimele minute,
    nu ultimele două zile. Spus «în ultimele 48 de ore n-am văzut nimic», ăsta ar
    fi un raport mai tare decât măsurătoarea din spatele lui: exact felul în care
    un instrument de monitorizare începe să mintă fără să greșească un număr.
    """
    plina = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("cineva", 0, cu_terminal=checks.HISTORY_SAMPLE,
                              ora=0)]),
        _istoric(skip_command_accounts=[])))[0]
    assert plina.facts["sample_capped"] is True
    assert "cele mai recente" in plina.detail
    assert f"{checks.HISTORY_WINDOW_H} de ore" not in plina.detail, (
        "raportul pretinde fereastra întreagă peste o felie care n-a atins-o")

    scurta = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("cineva", 0, cu_terminal=12, ora=0)]),
        _istoric(skip_command_accounts=[])))[0]
    assert scurta.facts["sample_capped"] is False
    assert f"{checks.HISTORY_WINDOW_H} de ore" in scurta.detail

    # Și cazul care contează cel mai mult, fiindcă e cel de pe o gazdă vie: felia
    # e plină ȘI are comenzi fără terminal, doar că într-un ritm de om. Aici se
    # tipărește ritmul, iar odată cu el trebuie să se vadă pe ce interval a fost
    # măsurat — altfel „~995/h" citit lângă „ultimele 48 de ore" descrie o gazdă
    # care n-a fost măsurată.
    plina_cu_comenzi = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("cineva", (checks.HISTORY_SAMPLE - 100) // 24,
                              cu_terminal=5, ora=h) for h in range(24)]),
        _istoric(skip_command_accounts=[])))[0]
    assert plina_cu_comenzi.status == "ok", plina_cu_comenzi.detail
    assert plina_cu_comenzi.facts["sample_capped"] is True
    assert "cele mai recente" in plina_cu_comenzi.detail
    assert f"{checks.HISTORY_WINDOW_H} de ore" not in plina_cu_comenzi.detail


def test_the_window_and_the_sample_are_what_the_query_receives():
    """Cele două numere care decid dacă verificarea poate vedea ceva.

    Schimbat tăcut din 48 în 1, `HISTORY_WINDOW_H` ar lăsa suita verde și ar face
    ca starea cea mai importantă — un deploy care scrie sub contul greșit — să nu
    mai fie prinsă aproape niciodată: un deploy nu rulează în fiecare oră. Nimic
    nu-l lega de vreun test până acum.
    """
    db = _HistDB(felie=[])
    run(checks.check_command_history_filter(
        db, _istoric(skip_command_accounts=[])))

    assert db.params, "interogarea de date n-a fost făcută deloc"
    limita, ore, tipar = db.params[0]
    assert limita == checks.HISTORY_SAMPLE
    assert ore == checks.HISTORY_WINDOW_H
    assert tipar == checks.REAL_TTY_SQL, (
        "felia folosește alt tipar de terminal decât filtrul viu")

    # Și valorile în sine, cu motivul lor: o fereastră de o oră n-ar prinde
    # niciun deploy, iar o felie de câteva sute n-ar deosebi o furtună de zgomot.
    assert checks.HISTORY_WINDOW_H >= 24, (
        "fereastra a coborât sub o zi; un deploy nu rulează zilnic")
    assert checks.HISTORY_SAMPLE >= 3 * checks.HISTORY_STORM_PER_H, (
        "felia nu e mult mai mare decât pragul, iar ora se numără din chiar ea: "
        "o furtună tăiată de granița dintre două ore ar sta sub prag în amândouă "
        "gălețile, adică cea mai violentă ar fi cea mai ușor de ratat")
    assert checks.HISTORY_STORM_PER_H > 2_438, (
        "pragul ar semnala cea mai încărcată oră de muncă omenească măsurată")
    assert checks.HISTORY_STORM_PER_H < 174_839, (
        "pragul ar rata cea mai săracă oră de deploy măsurată")


def test_the_storm_threshold_fires_exactly_at_the_boundary():
    """`>=` sau `>` pe prag decide dacă ora care atinge fix pragul e o furtună.

    Pragul e ales ca media geometrică între cea mai săracă oră de deploy și cea
    mai bogată oră de om, tocmai ca granița să cadă între ele. O oră care e FIX
    pe prag e ritm de automatizare, nu de om, deci comparația trebuie să fie
    inclusivă (`>=`). Schimbată tăcut în `>`, ora de la fix prag ar trece drept
    normală și un deploy care nimerește exact pragul n-ar mai fi raportat — iar
    testele care doar fixează constanta n-ar prinde-o, fiindcă valoarea nu s-a
    schimbat, doar comparația care o alimentează.
    """
    la_prag = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("automat", checks.HISTORY_STORM_PER_H, ora=0)]),
        _istoric(skip_command_accounts=[])))[0]
    assert la_prag.status == "degraded", (
        "ora care atinge fix pragul a trecut drept normală: `>` în loc de `>=` "
        "ratează exact granița")
    assert la_prag.facts["top_peak_hour"] == checks.HISTORY_STORM_PER_H

    sub_prag = run(checks.check_command_history_filter(
        _HistDB(felie=[_felie("automat", checks.HISTORY_STORM_PER_H - 1, ora=0)]),
        _istoric(skip_command_accounts=[])))[0]
    assert sub_prag.status == "ok", sub_prag.detail


def test_a_configured_account_that_does_not_exist_is_degraded(monkeypatch):
    """Un cont scris greșit dă un filtru care nu potrivește niciodată nimic.

    `is_dropped_command` compară pe egalitate exactă. Secțiunea arată
    configurată, tabela crește cu 405 777 de rânduri la fiecare deploy, și nimic
    nu spune nimic. Exact starea pe care verificarea asta există s-o facă
    vizibilă.
    """
    _cu_uid(monkeypatch, lambda _n: None)
    r = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=["nu-exista"])))[0]
    assert r.status == "degraded"
    assert "nu-exista" in r.detail


def test_an_unreadable_account_database_is_unknown_not_ok(monkeypatch):
    """„Nu știu" și „e în regulă" nu au voie să arate la fel.

    Fără baza de conturi nu se pot afla uid-urile, iar rândurile scrise cu `auid`
    numeric — 87 935 pe gazdă — scapă filtrului. Raportat `ok`, reconcilierea din
    runner ar șterge o constatare reală și i-ar arăta operatorului o revenire
    care nu s-a întâmplat.
    """
    def orb(_n):
        raise OSError("nu se poate citi /etc/passwd")

    _cu_uid(monkeypatch, orb)
    r = run(checks.check_command_history_filter(
        _HistDB(), _istoric(skip_command_accounts=["sentinel-deploy"])))[0]
    assert r.status == "unknown"
    assert "nu știu" in r.detail.lower() or "nu pot" in r.detail.lower()


def test_a_row_the_rule_forbids_means_the_filter_is_not_in_effect(monkeypatch):
    """Faptul, nu intenția — dar numai un rând scris DUPĂ ce filtrul putea acționa.

    `docs/ISTORIC-SESIUNI.md` propunea

        journalctl -u sentinel-ingest | grep commands_skipped

    care potrivea ÎNTOTDEAUNA: `commands_skipped` e mereu în `extra`, iar
    `JSONFormatter` scrie și zerourile. Nu deosebea «am aruncat 405 777 de
    rânduri» de «secțiunea n-a fost îmbinată niciodată».

    Ce deosebește cele două e un rând pe care regula îl interzice, scris DUPĂ ce
    filtrul putea acționa. Un `max(ts)` nefolosit făcea verificarea să acuze
    filtrul și pentru rânduri vechi: reprodus pe gazdă (2026-08-26), 1 871 de
    rânduri `sentinel-deploy` scrise ÎNAINTE ca filtrul să existe rămâneau în
    fereastra de 48h; după ce operatorul adăuga contul și repornea, panoul
    devenea roșu ~48h cu două cauze false și o acțiune care nu arăta nimic, și
    îngropa sub aceeași cheie furtunile adevărate. Cel mai devreme moment în care
    filtrul putea acționa e ultima pornire a serviciului de ingestie.
    """
    _cu_uid(monkeypatch, lambda _n: 998)

    async def pornit_acum_2h(_unit):
        return NOW - timedelta(hours=2)
    monkeypatch.setattr(checks, "_service_started_at", pornit_acum_2h)

    # Nou: cea mai recentă comandă interzisă e de acum 5 minute, DUPĂ pornire —
    # filtrul rula deja când a fost scrisă, deci chiar nu e în vigoare.
    db = _HistDB(total=405_777, interzise=405_777,
                 newest=NOW - timedelta(minutes=5))
    r = run(checks.check_command_history_filter(
        db, _istoric(skip_command_accounts=["sentinel-deploy"])))[0]

    assert r.status == "degraded", r.detail
    assert "nu e în vigoare" in r.title
    assert "405777" in r.detail.replace(" ", "") or "405 777" in r.detail
    assert r.facts["rows_forbidden"] == 405_777
    assert any("session_commands" in s for s in db.sql), (
        "verificarea n-a întrebat tabela deloc: ar raporta despre configurație, "
        "nu despre efect")

    # Vechi: aceleași rânduri interzise, dar cea mai recentă e de acum 40 de ore —
    # ÎNAINTE de ultima pornire a filtrului. Le-a scris procesul dinainte; a le
    # numi „filtrul nu e în vigoare" e acuzația care aprindea panoul degeaba.
    db_vechi = _HistDB(total=405_777, interzise=405_777,
                       newest=NOW - timedelta(hours=40))
    rv = run(checks.check_command_history_filter(
        db_vechi, _istoric(skip_command_accounts=["sentinel-deploy"])))[0]

    assert rv.status != "degraded", rv.detail
    assert "nu e în vigoare" not in rv.title
    assert "nu e în vigoare" not in rv.detail
    # Faptul, dat operatorului: data celui mai recent rând interzis apare, ca s-o
    # poată lega de momentul îmbinării.
    # În fusul CONFIGURAT, cu marcajul lui: operatorul verifică momentul ăsta în
    # `journalctl`, care îi arată ora locală. Dat în UTC, l-ar trimite să caute
    # cu trei ore alături.
    assert checks._ceas(NOW - timedelta(hours=40), "Europe/Bucharest") in rv.detail
    assert rv.facts["newest_forbidden"] == (NOW - timedelta(hours=40)).isoformat()


def test_an_active_storm_outside_the_filter_is_not_swallowed_by_old_rows(monkeypatch):
    """O furtună ACTIVĂ pe alt cont nu are voie să stea sub verdele dat rândurilor vechi.

    B1 a stins un roșu fals: rânduri interzise VECHI ale contului configurat
    (scrise înainte ca filtrul să existe) rămân în fereastra de 48h și, singure,
    dau acum `ok`. Dar ramura aia întoarce `ok` ÎNAINTE de ramura de furtună de
    dedesubt — deci în cele ~48h cât rândurile vechi zac, o furtună reală de
    automatizare pe un cont din AFARA filtrului, sub aceeași cheie `history:filter`,
    e înghițită și panoul rămâne verde. Exact cazul din
    `test_a_storm_on_an_account_outside_the_filter_is_a_finding`, dar cu rânduri
    interzise vechi prezente simultan: un deploy rulat pe contul de logare al
    operatorului nu produce niciun semnal.
    """
    _cu_uid(monkeypatch, lambda _n: 998)

    async def pornit_acum_2h(_unit):
        return NOW - timedelta(hours=2)
    monkeypatch.setattr(checks, "_service_started_at", pornit_acum_2h)

    # Contul configurat: 1 871 de rânduri interzise, cea mai recentă de acum 40 de
    # ore — ÎNAINTE de pornire, deci singure ar da `ok` (cazul B1). SIMULTAN,
    # contul `operator`, din afara filtrului, scrie 174 839 de comenzi fără
    # terminal într-o oră: furtună activă, peste prag.
    db = _HistDB(total=1_871, interzise=1_871, newest=NOW - timedelta(hours=40),
                 felie=[_felie("operator", 174_839, cu_terminal=200, ora=1),
                        _felie("operator", 40, ora=0)])
    r = run(checks.check_command_history_filter(
        db, _istoric(skip_command_accounts=["sentinel-deploy"])))[0]

    assert r.status == "degraded", r.detail
    assert "„operator”" in r.detail, r.detail
    assert r.facts["top_account"] == "operator"
    assert r.facts["top_peak_hour"] == 174_839
    assert "din afara filtrului" in r.title, (
        "furtuna de pe contul neconfigurat a fost raportată ca altceva, sau "
        "verdele rândurilor vechi a acoperit-o")


def test_old_forbidden_rows_without_a_storm_stay_ok(monkeypatch):
    """Non-regresie B1: rânduri interzise vechi rămân `ok`, cu sau fără furtună.

    Garda adăugată deasupra n-are voie să reînvie roșul fals pe care B1 l-a
    stins. Două sub-cazuri:

    1. un cont din afara filtrului prezent dar SUB prag (nu e furtună), plus
       rânduri interzise vechi ale contului configurat → `ok`;
    2. mai tare: chiar o furtună VECHE pe CONTUL configurat însuși (toate
       rândurile de dinaintea pornirii) trebuie să rămână `ok`. Contul filtrului
       nu are voie să cadă prin la ramura de furtună, care l-ar acuza cu «n-ar fi
       trebuit scrise» — exact roșul fals pentru rânduri vechi. Fără clauza
       `top.username not in skip.matches` din gardă, sub-cazul ăsta devine roșu.
    """
    _cu_uid(monkeypatch, lambda _n: 998)

    async def pornit_acum_2h(_unit):
        return NOW - timedelta(hours=2)
    monkeypatch.setattr(checks, "_service_started_at", pornit_acum_2h)

    # Sub-cazul 1: cont din afara filtrului, sub prag.
    db = _HistDB(total=1_871, interzise=1_871, newest=NOW - timedelta(hours=40),
                 felie=[_felie("operator", checks.HISTORY_STORM_PER_H - 1, ora=1)])
    r = run(checks.check_command_history_filter(
        db, _istoric(skip_command_accounts=["sentinel-deploy"])))[0]

    assert r.status == "ok", r.detail
    assert "nu e în vigoare" not in r.title
    assert "nu e în vigoare" not in r.detail

    # Sub-cazul 2: furtună VECHE pe chiar contul configurat (toate rândurile
    # dinaintea pornirii de acum 2h — ora 41 e cu mult înainte).
    db2 = _HistDB(total=174_879, interzise=174_879, newest=NOW - timedelta(hours=40),
                  felie=[_felie("sentinel-deploy", 174_839, ora=41)])
    r2 = run(checks.check_command_history_filter(
        db2, _istoric(skip_command_accounts=["sentinel-deploy"])))[0]

    assert r2.facts["top_account"] == "sentinel-deploy"
    assert r2.status == "ok", r2.detail
    assert "n-ar fi trebuit scrise" not in r2.detail, (
        "furtuna VECHE a contului configurat a căzut prin la ramura de furtună și "
        "a reînviat roșul fals pentru rânduri de dinaintea filtrului")


def test_the_numeric_spelling_is_part_of_what_the_check_looks_for(monkeypatch):
    """Verificarea trebuie să caute AMBELE ortografii ale contului.

    Dacă ar întreba doar despre nume, cele 87 935 de rânduri scrise cu `auid`
    numeric n-ar apărea în numărătoare — iar verificarea ar raporta `ok` peste
    exact golul pe care există s-o umple.
    """
    _cu_uid(monkeypatch, lambda _n: 998)
    db = _HistDB()
    r = run(checks.check_command_history_filter(
        db, _istoric(skip_command_accounts=["sentinel-deploy"])))[0]

    assert r.status == "ok"
    assert sorted(r.facts["matches"]) == ["998", "sentinel-deploy"]


def test_no_rows_at_all_is_not_reported_as_proof_that_the_filter_works(monkeypatch):
    """Zero rânduri interzise într-o fereastră fără niciun deploy arată exact ca
    zero rânduri interzise pe o gazdă care aruncă cum trebuie.

    Verificarea nu are voie să spună «filtrul funcționează» despre asta. Spune ce
    a văzut — nimic — și că nimic nu e o dovadă.
    """
    _cu_uid(monkeypatch, lambda _n: 998)
    r = run(checks.check_command_history_filter(
        _HistDB(total=0, interzise=0),
        _istoric(skip_command_accounts=["sentinel-deploy"])))[0]

    assert r.status == "ok"
    assert "NU e o dovadă" in r.detail, (
        "verificarea pretinde că filtrul aruncă, pe o fereastră în care n-a "
        "văzut niciun rând")


def test_the_history_check_is_registered_in_the_run():
    """O verificare care nu e în `CHECKS` nu rulează niciodată.

    E chiar felul de defect pe care fișierul ăsta îl păzește peste tot: cod
    corect, testat, și niciodată chemat.
    """
    assert "history" in [nume for nume, _ in checks.CHECKS]


# --- ship_lag: prag de vârstă pe flux + detector de înțepenire ---------------
#
# Două pene stau în spatele acestor teste. Prima: `session_commands`, fluxul cu
# cel mai mare volum, rămâne normal în urmă mai mult decât restul, iar la 15
# minute producea o constatare pe funcționarea sănătoasă — zgomot pe care
# operatorul învață să-l ignore. A doua, cea care a durat ore: cursorul lui NU
# avansa deloc (un WAF refuza loturile), iar a aștepta pragul de vârstă ridicat
# înainte de a alarma ar fi lăsat oprirea nevăzută ore în șir. Cele două sunt
# diagnostice diferite și au chei diferite.
from sentinel.report.shipper import StreamLag


class _StallDB:
    """`collector_cursors` cât să se joace mai multe rulări ale detectorului.

    Reimplementează în Python semantica upsertului pe cheia `ship:<flux>:stall`,
    deci dovedește logica detectorului — starea ținută între rulări —, nu SQL-ul.
    Un `_DB` care întoarce o singură valoare canonică pentru orice `fetchrow` nu
    poate arăta ce vede detectorul: că VALOAREA cursorului e neschimbată de la
    rularea trecută. Fără o stare care evoluează, testul de non-regresie (un flux
    care se scurge normal) și cel de înțepenire ar arăta identic.
    """

    def __init__(self):
        self.store: dict[str, dict] = {}

    async def fetchrow(self, sql, *a):
        return self.store.get(a[0])

    async def execute(self, sql, *a):
        name, cursor, events = a[0], a[1], a[2]
        self.store[name] = {"cursor": cursor, "events_seen": events}

    async def fetchval(self, sql, *a):
        return None


def _ship_cfg():
    return _cfg(ship=SimpleNamespace(enabled=True, url="https://agg.invalid",
                                     interval_s=60))


def _patch_ship(monkeypatch, lags):
    """Fă `check_ship_lag` să vadă exact `lags` și o cheie de expediere prezentă."""
    from sentinel.report import shipper

    async def fake_lag(db, streams=None):
        return list(lags)

    monkeypatch.setattr(shipper, "lag", fake_lag)
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: SimpleNamespace(has=lambda n: True))


def _sc_lag(cursor, pending, oldest_min, stream="session_commands"):
    """Un flux append-only (cursor pe `id`): `clock_ahead_s`/`trigger` = None."""
    return StreamLag(stream=stream, cursor=cursor, floor=None, pending=pending,
                     oldest_pending_min=oldest_min)


def _key(results, key):
    for r in results:
        if r.key == key:
            return r
    return None


def test_session_commands_thirty_minutes_behind_but_advancing_is_not_a_finding(monkeypatch):
    """Zgomotul din care s-a cerut pragul de 6h.

    `session_commands` are cel mai mare volum și rămâne legitim în urmă cu minute.
    Sub pragul lui de 6h, cu un cursor care AVANSEAZĂ la fiecare rundă, nu e nici
    înțepenit, nici „rămas în urmă" — la 15 minute ar fi produs o constatare pe
    funcționarea normală, iar o alarmă pe normal e una peste care operatorul
    învață să treacă și atunci nu mai vede nici restanța adevărată.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    for cursor in (100, 130):
        _patch_ship(monkeypatch, [_sc_lag(cursor, pending=5, oldest_min=30)])
        results = run(checks.check_ship_lag(db, cfg))

    assert not any(r.key.endswith(":stall") for r in results), (
        "un flux care se scurge normal a fost numit înțepenit")
    r = _key(results, "ship:lag:session_commands")
    assert r is not None and r.status == "ok", (
        "30 de minute a fost raportat ca restanță, deși pragul lui e de 6 ore")


def test_session_commands_seven_hours_behind_is_an_age_finding(monkeypatch):
    """Peste 6h, restanța lui `session_commands` E o constatare.

    Ridicarea pragului la 6 ore nu are voie să însemne „niciodată": o copie
    externă rămasă în urmă cu 7 ore e incompletă și trebuie spus. Cursorul
    avansează — deci e vârstă, nu înțepenire.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    for cursor in (100, 130):
        _patch_ship(monkeypatch, [_sc_lag(cursor, pending=5, oldest_min=420)])
        results = run(checks.check_ship_lag(db, cfg))

    assert not any(r.key.endswith(":stall") for r in results)
    r = _key(results, "ship:lag:session_commands")
    assert r is not None and r.status == "degraded"
    assert "rămas în urmă" in r.title


def test_a_cursor_frozen_for_three_runs_with_pending_rows_is_a_stall(monkeypatch):
    """Pana reală: cursorul nu mai înaintează DELOC, deși există rânduri.

    A aștepta pragul de vârstă (6h) pentru asta e greșit — oprirea trebuie prinsă
    în minute. Constatarea are cheie DISTINCTĂ de cea de vârstă, ca mesajul să
    spună „nu mai înaintează", nu „a rămas în urmă": sunt diagnostice diferite,
    cu acțiuni diferite. Restanța e sub pragul de 6h (30 min), deci ce prinde
    aici e înțepenirea, nu vârsta.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    results = []
    for _ in range(3):
        _patch_ship(monkeypatch, [_sc_lag(200, pending=5, oldest_min=30)])
        results = run(checks.check_ship_lag(db, cfg))

    stall = _key(results, "ship:lag:session_commands:stall")
    assert stall is not None and stall.status == "degraded", (
        "cursorul înghețat 3 rulări cu rânduri în așteptare nu a fost prins")
    assert "nu mai înaintează" in stall.detail
    assert _key(results, "ship:lag:session_commands") is None, (
        "a raportat si constatarea de varsta pe un flux sub pragul de 6h")


def test_a_cursor_that_advances_a_little_each_run_is_never_a_stall(monkeypatch):
    """Non-regresia critică: o restanță care se scurge NU e o înțepenire.

    Miezul reparației. `updated_at` e scris necondiționat de expeditor la fiecare
    upsert, deci un detector clădit pe el ar numi înțepenit orice flux care e doar
    în urmă. Semnalul e VALOAREA cursorului: dacă avansează — chiar și cu puțin,
    chiar rămânând mereu în urmă — fluxul se mișcă și nu e blocat.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    saw_stall = False
    for cursor in (100, 101, 102, 103, 104):
        _patch_ship(monkeypatch, [_sc_lag(cursor, pending=5, oldest_min=400)])
        results = run(checks.check_ship_lag(db, cfg))
        if any(r.key.endswith(":stall") for r in results):
            saw_stall = True

    assert not saw_stall, (
        "un flux al cărui cursor avansează la fiecare rundă a fost numit înțepenit")
    assert _key(results, "ship:lag:session_commands").status == "degraded"


def test_another_stream_keeps_the_fifteen_minute_age_threshold(monkeypatch):
    """Harta de excepții nu are voie să slăbească restul fluxurilor.

    Pragul de 6h e DOAR pentru `session_commands`. Un alt flux în urmă cu 20 de
    minute rămâne o constatare la 15 minute — altfel ridicarea pragului pentru
    unul singur ar fi înmuiat tăcut sensibilitatea tuturor.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    for cursor in (100, 130):
        _patch_ship(monkeypatch,
                    [_sc_lag(cursor, pending=5, oldest_min=20, stream="incidents")])
        results = run(checks.check_ship_lag(db, cfg))

    r = _key(results, "ship:lag:incidents")
    assert r is not None and r.status == "degraded", (
        "20 de minute pe un flux obișnuit nu a mai fost o constatare — harta de "
        "excepții a slăbit pragul altui flux decât cel numit")
    assert not any(x.key.endswith(":stall") for x in results)


def test_the_stall_counter_resets_when_the_cursor_moves_again(monkeypatch):
    """Un flux care se dezgheață nu rămâne marcat înțepenit.

    Fără reset, un flux care s-a mișcat greu o rundă-două și apoi și-a revenit ar
    fi ținut o constatare aprinsă pe o problemă care a trecut — exact felul de
    alarmă care sună degeaba. Cursorul înghețat 2 rulări, apoi se mișcă: contorul
    revine la zero, fără constatare.
    """
    db = _StallDB()
    cfg = _ship_cfg()
    for _ in range(2):
        _patch_ship(monkeypatch, [_sc_lag(300, pending=5, oldest_min=30)])
        run(checks.check_ship_lag(db, cfg))
    assert db.store["ship:session_commands:stall"]["events_seen"] >= 1

    _patch_ship(monkeypatch, [_sc_lag(305, pending=5, oldest_min=30)])
    results = run(checks.check_ship_lag(db, cfg))

    assert not any(r.key.endswith(":stall") for r in results), (
        "un flux care a înaintat din nou e încă raportat înțepenit")
    assert db.store["ship:session_commands:stall"]["events_seen"] == 0, (
        "contorul de rulări-fără-mișcare nu a revenit la zero după ce cursorul s-a mișcat")
