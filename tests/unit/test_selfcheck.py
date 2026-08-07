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


def test_the_admin_address_missing_from_the_allowlist_is_flagged(monkeypatch):
    """The anti-lockout invariant, checked rather than assumed."""
    monkeypatch.setattr(checks, "_nft_table_present",
                        lambda: (True, "table inet sentinel { }"))
    from sentinel.respond import actions
    monkeypatch.setattr(actions, "live_count", _async(0))
    cfg = _cfg(response=SimpleNamespace(
        auto_block=SimpleNamespace(enabled=True), admin_ip="203.0.113.7"))
    results = run(checks.check_enforcement(_DB(val=0), cfg))
    assert any(r.key == "nft:allowlist" and r.bad for r in results)


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
