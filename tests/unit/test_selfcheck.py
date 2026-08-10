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
        telegram=SimpleNamespace(enabled=True, allowed_chat_ids=[1]),
        response=SimpleNamespace(auto_block=SimpleNamespace(enabled=False), admin_ip=""),
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
    dataclass-ul real, nu doar pe obiectul fabricat de teste."""
    import inspect

    from sentinel.config import Config, ResponseConfig

    src = inspect.getsource(checks)
    for attr in re.findall(r"getattr\(\s*cfg\.response\s*,\s*[\"'](\w+)[\"']", src):
        assert hasattr(ResponseConfig(), attr), \
            f"check_enforcement citește response.{attr}, care nu există în ResponseConfig"
    # Și câmpul mort anume, ca reintroducerea lui să pice aici.
    assert not hasattr(ResponseConfig(), "admin_ip"), \
        "admin_ip a fost adăugat — atunci verificarea allowlist trebuie rescrisă și testată"
    assert hasattr(Config(), "response")


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


def test_selfcheck_alerts_are_never_muted():
    """Holding this until 06:00 would mean the hours you stop watching your
    phone are the hours nobody watches the server either."""
    from sentinel.telegram.quiet import passes_anyway

    assert passes_anyway("high", "selfcheck")
    assert passes_anyway(None, "selfcheck")


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
