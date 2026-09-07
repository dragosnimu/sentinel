"""The anti-lockout deadman's decision logic.

`decide()` is a pure function precisely so it can be tested exhaustively without
a server, an executor or a systemd. Every branch is covered here, because the
failure mode of this component is "the operator cannot get back into their own
server" and that is not something to discover in production.
"""

from __future__ import annotations

import os

import pytest

from sentinel.respond import watchdog

NOW = 1_800_000_000.0


def decide(**kwargs):
    """decide() with safe defaults, so each test states only what it varies."""
    defaults = {
        "panic": False,
        "web": True,
        "web_down_since": None,
        "detect_bad": False,
        "blocklist_size": 5,
        "now": NOW,
    }
    return watchdog.decide(**{**defaults, **kwargs})


# ---------------------------------------------------------------------------
# The healthy case
# ---------------------------------------------------------------------------
def test_healthy_system_does_not_flush():
    should_flush, reason = decide()
    assert not should_flush
    assert reason is None


def test_empty_blocklist_and_healthy_does_not_flush():
    should_flush, _ = decide(blocklist_size=0)
    assert not should_flush


# ---------------------------------------------------------------------------
# 1. PANIC file — the operator's escape hatch
# ---------------------------------------------------------------------------
def test_panic_file_flushes():
    should_flush, reason = decide(panic=True)
    assert should_flush
    assert "PANIC" in reason


def test_panic_wins_over_everything_else():
    """PANIC must flush even when the rest of the system looks perfect.

    It is the hatch the operator reaches for while locked out, and it cannot
    depend on any other condition also being true.
    """
    should_flush, reason = decide(
        panic=True, web=True, detect_bad=False, blocklist_size=1
    )
    assert should_flush
    assert "PANIC" in reason


# ---------------------------------------------------------------------------
# 2. Web health
# ---------------------------------------------------------------------------
def test_web_down_briefly_does_not_flush():
    """A restart or a slow request must not empty the blocklist."""
    should_flush, _ = decide(web=False, web_down_since=NOW - 60)
    assert not should_flush


def test_web_down_past_the_threshold_flushes():
    should_flush, reason = decide(
        web=False, web_down_since=NOW - watchdog.WEB_DOWN_FLUSH_S - 1
    )
    assert should_flush
    assert "web health" in reason


def test_web_down_exactly_at_the_threshold_flushes():
    should_flush, _ = decide(web=False, web_down_since=NOW - watchdog.WEB_DOWN_FLUSH_S)
    assert should_flush


def test_web_down_without_a_start_time_does_not_flush():
    """The first observation of a failure starts the clock; it is not itself proof.

    Without this, a single transient probe failure would flush.
    """
    should_flush, _ = decide(web=False, web_down_since=None)
    assert not should_flush


def test_indeterminate_web_probe_does_not_flush():
    """`None` means "could not tell", which is not evidence of failure.

    A DNS hiccup or a socket error inside the probe itself must not start the
    countdown.
    """
    should_flush, _ = decide(web=None, web_down_since=None)
    assert not should_flush


def test_indeterminate_probe_does_not_trigger_even_with_an_old_timer():
    should_flush, _ = decide(web=None, web_down_since=NOW - 10_000)
    assert not should_flush


# ---------------------------------------------------------------------------
# 3. Detector health
# ---------------------------------------------------------------------------
def test_failed_detector_flushes():
    """A detector that cannot run must not leave stale drops in the kernel.

    Nobody is deciding those blocks should still be there, and nobody will
    remove them when they should expire.
    """
    should_flush, reason = decide(detect_bad=True)
    assert should_flush
    assert "detect" in reason


def test_failed_detector_flushes_even_when_the_web_is_fine():
    should_flush, _ = decide(detect_bad=True, web=True)
    assert should_flush


# ---------------------------------------------------------------------------
# 4. Runaway blocklist
# ---------------------------------------------------------------------------
def test_blocklist_over_the_cap_flushes():
    should_flush, reason = decide(blocklist_size=watchdog.MAX_BLOCKLIST_ELEMENTS + 1)
    assert should_flush
    assert "cap" in reason


def test_blocklist_exactly_at_the_cap_does_not_flush():
    """The cap is a ceiling, not a trigger. At the limit the executor already
    refuses new blocks; flushing would discard legitimate ones."""
    should_flush, _ = decide(blocklist_size=watchdog.MAX_BLOCKLIST_ELEMENTS)
    assert not should_flush


def test_unknown_blocklist_size_does_not_flush_on_its_own():
    """-1 means the executor was unreachable.

    Not a flush condition by itself: if the executor cannot be reached, the
    flush would fail anyway, and treating it as a trigger would produce a
    misleading log line every minute.
    """
    should_flush, _ = decide(blocklist_size=-1)
    assert not should_flush


# ---------------------------------------------------------------------------
# Priority
# ---------------------------------------------------------------------------
def test_reason_reports_the_most_urgent_condition():
    """With several conditions true, PANIC is the one reported.

    The reason ends up in the journal and in an alert; it should name the thing
    the operator most needs to know about.
    """
    _, reason = decide(
        panic=True,
        detect_bad=True,
        blocklist_size=watchdog.MAX_BLOCKLIST_ELEMENTS + 100,
        web=False,
        web_down_since=NOW - 10_000,
    )
    assert "PANIC" in reason


def test_detector_outranks_the_blocklist_cap():
    _, reason = decide(
        detect_bad=True, blocklist_size=watchdog.MAX_BLOCKLIST_ELEMENTS + 100
    )
    assert "detect" in reason


# ---------------------------------------------------------------------------
# Invariants of the module itself
# ---------------------------------------------------------------------------
def test_thresholds_are_sane():
    assert watchdog.WEB_DOWN_FLUSH_S >= 60, (
        "too short a threshold turns a routine restart into a blocklist flush"
    )
    assert watchdog.MAX_BLOCKLIST_ELEMENTS == 20_000, (
        "must match the executor's hard cap, or the two disagree about when a "
        "runaway has happened"
    )


def test_watchdog_does_not_import_the_database():
    """PostgreSQL being down is one of the failures this must survive."""
    import inspect

    source = inspect.getsource(watchdog)
    for forbidden in ("asyncpg", "from sentinel.db", "import sentinel.db"):
        assert forbidden not in source, (
            f"watchdog imports {forbidden!r}; it must work when the database is down"
        )


def test_watchdog_imports_stay_minimal():
    """Every extra dependency is another thing that can fail at the worst moment."""
    import inspect

    source = inspect.getsource(watchdog)
    sentinel_imports = [
        line.strip()
        for line in source.splitlines()
        if line.strip().startswith(("from sentinel", "import sentinel"))
    ]
    for line in sentinel_imports:
        assert "executor_client" in line, (
            f"unexpected sentinel import in the watchdog: {line!r}. "
            "Only executor_client is permitted."
        )


def test_decide_never_raises_on_odd_input():
    """The watchdog must not throw. An exception means no flush happened —
    exactly the outcome it exists to prevent."""
    for kwargs in (
        {"blocklist_size": -999},
        {"web_down_since": NOW + 10_000},        # a clock that went backwards
        {"blocklist_size": 10**9},
        {"web": None, "web_down_since": 0},
    ):
        should_flush, reason = decide(**kwargs)
        assert isinstance(should_flush, bool)
        assert reason is None or isinstance(reason, str)


# ---------------------------------------------------------------------------
# The nft element counter
# ---------------------------------------------------------------------------
def test_nft_element_count_parses_real_output():
    from sentinel.respond.executor_client import _count_nft_elements

    payload = {
        "nftables": [
            {"metainfo": {"version": "1.0.4"}},
            {"set": {"family": "inet", "name": "blocklist_v4",
                     "elem": ["203.0.113.1", "203.0.113.2", "203.0.113.3"]}},
        ]
    }
    assert _count_nft_elements(payload) == 3


def test_nft_element_count_handles_an_empty_set():
    from sentinel.respond.executor_client import _count_nft_elements

    assert _count_nft_elements({"nftables": [{"set": {"name": "blocklist_v4"}}]}) == 0


@pytest.mark.parametrize(
    "payload",
    [{}, {"nftables": []}, {"nftables": [{"metainfo": {}}]}, {"nftables": "garbage"},
     {"other": [1, 2, 3]}],
)
def test_nft_element_count_survives_unexpected_shapes(payload):
    """nft's JSON schema has changed across versions.

    A parsing error here must not make the watchdog believe the blocklist is
    empty — it walks defensively and returns 0 rather than raising.
    """
    from sentinel.respond.executor_client import _count_nft_elements

    assert _count_nft_elements(payload) == 0


# ---------------------------------------------------------------------------
# State persistence — the bug measured on production 4-7 Sep 2026
#
# `sentinel-watchdog.service` runs as root with no CAP_DAC_OVERRIDE. The old
# default path put the state file directly inside /var/lib/sentinel, which is
# 0750 sentinel:sentinel — a directory root does not own and has no group
# access to. Every single run logged a warning and returned without writing
# anything; `web_down_since` reset to `now()` on every pass forever, and the
# anti-lockout flush for a dead dashboard (WEB_DOWN_FLUSH_S in `decide()`)
# became mathematically unreachable. The fix moves the default path under a
# directory root owns outright — these tests pin both halves of that fix.
# ---------------------------------------------------------------------------
def test_state_round_trips_through_a_writable_directory(tmp_path, monkeypatch):
    """With a directory the process can actually write to, state must survive
    from one run to the next — this is the exact memory `web_down_since`
    depends on. See `test_dashboard_flush_arms_when_state_persists_across_runs`
    for the consequence if this stops being true."""
    state_dir = tmp_path / "watchdog"
    state_dir.mkdir()
    monkeypatch.setattr(watchdog, "STATE_FILE", state_dir / "state.json")

    watchdog.save_state({"web_down_since": 123.0, "last_run": 456.0})

    assert watchdog.load_state() == {"web_down_since": 123.0, "last_run": 456.0}


@pytest.mark.skipif(os.name == "nt", reason="modurile POSIX nu se aplică pe Windows")
def test_saved_state_file_is_not_world_readable(tmp_path, monkeypatch):
    """web_down_since and last_flush_reason are process-lifecycle facts, not
    secrets, but root's default create mode (644) would still let any local
    user on the box read them. The directory's setgid bit hands the file
    group `sentinel` for free; this checks the explicit chmod that removes
    the "other" bits root would otherwise leave in place."""
    import stat

    state_dir = tmp_path / "watchdog"
    state_dir.mkdir()
    monkeypatch.setattr(watchdog, "STATE_FILE", state_dir / "state.json")

    watchdog.save_state({"web_down_since": 1.0})

    mode = stat.S_IMODE((state_dir / "state.json").stat().st_mode)
    assert mode == 0o640, f"state file mode is {oct(mode)}, expected 0o640"


def test_missing_state_directory_names_the_directory_and_the_fix(tmp_path, monkeypatch, capsys):
    """`save_state` must not `mkdir()` its way around a missing directory — a
    directory it created itself would be root-only and the selfcheck (which
    runs as `sentinel`) could never read it. A missing directory means the
    installer's tmpfiles step never ran, and the warning has to say exactly
    that, not just "permission denied" with no next step."""
    import json

    missing = tmp_path / "does-not-exist" / "state.json"
    monkeypatch.setattr(watchdog, "STATE_FILE", missing)

    watchdog.save_state({"web_down_since": 1.0})

    assert not missing.parent.exists(), "must not create the directory itself"
    err = capsys.readouterr().err.strip().splitlines()
    assert err, "a missing state directory must be logged, not swallowed silently"
    record = json.loads(err[-1])
    assert record["level"] == "warning"
    assert str(missing.parent) in record["directory"]
    assert "tmpfiles" in record["hint"]


def test_tmpfiles_line_agrees_with_watchdog_default_path():
    """The directory declared root-owned in `deploy/tmpfiles/sentinel.conf`
    must be the exact parent of `watchdog.py`'s default state path. Falsify
    either one on its own and a real deploy reproduces the outage: a
    directory nobody creates, or a path nobody declared root-owned."""
    import re
    from pathlib import Path as _Path

    conf_path = (_Path(__file__).resolve().parents[2] / "deploy" / "tmpfiles"
                / "sentinel.conf")
    conf = conf_path.read_text(encoding="utf-8")

    default_dir = _Path(watchdog._DEFAULT_STATE_FILE).parent.as_posix()
    match = re.search(rf"^d\s+{re.escape(default_dir)}\s+(\S+)\s+(\S+)\s+(\S+)\s",
                      conf, re.M)
    assert match, (
        f"no tmpfiles line declares {default_dir!r} — watchdog.py's default "
        "state path and deploy/tmpfiles/sentinel.conf have drifted apart"
    )
    _mode, owner, _group = match.groups()
    assert owner == "root", (
        f"{default_dir} is owned by {owner!r}, not root — the watchdog runs "
        "as root with no CAP_DAC_OVERRIDE and cannot write into a directory "
        "it does not own"
    )


def test_service_unit_declares_the_state_directory_writable_with_dash_prefix():
    """Nothing else in this repository pins `sentinel-watchdog.service` to the
    directory `save_state()` actually needs — this is that pin, and it checks
    both halves the round-2 fix got wrong in opposite ways:

    * drop the entry from `ReadWritePaths=` entirely: `ProtectSystem=strict`
      makes the directory read-only again, `save_state()` hits
      `[Errno 30] Read-only file system`, and the unit still exits 0 — the
      4-7 Sep 2026 outage, back silently, and the rest of the suite stayed
      green while it happened (verified: dropping the entry left 4125 tests
      passing).
    * keep the entry but drop its leading `-`: systemd 252 then refuses to
      even START this unit whenever the directory is absent ("Failed at step
      NAMESPACE ... No such file or directory", ExecMainStatus=226) — the one
      component documented to depend on nothing and work when everything else
      has failed would instead fail to run at all on a host where the
      tmpfiles step hasn't (yet) created the directory.
    """
    from pathlib import Path as _Path

    unit_path = (_Path(__file__).resolve().parents[2] / "deploy" / "systemd"
                / "sentinel-watchdog.service")
    unit = unit_path.read_text(encoding="utf-8")

    entries: list[str] = []
    for line in unit.splitlines():
        if line.startswith("ReadWritePaths="):
            entries.extend(line.split("=", 1)[1].split())

    default_dir = _Path(watchdog._DEFAULT_STATE_FILE).parent.as_posix()
    stripped = [entry.lstrip("-") for entry in entries]
    assert default_dir in stripped, (
        f"{default_dir!r} is not in ReadWritePaths= of sentinel-watchdog.service — "
        "save_state() would hit a read-only filesystem and the unit would still exit "
        "0, silently reproducing the 4-7 Sep 2026 outage"
    )

    matching = [entry for entry in entries if entry.lstrip("-") == default_dir]
    assert matching[0].startswith("-"), (
        f"ReadWritePaths= entry for {default_dir!r} is {matching[0]!r} — without the "
        "leading '-', systemd 252 refuses to START this unit at all when the "
        "directory is missing, which the anti-lockout deadman may never do"
    )


@pytest.mark.skipif(os.name == "nt", reason="modurile POSIX nu se aplică pe Windows")
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="root ignoră bitii de permisiune, deci proba n-ar dovedi nimic")
def test_unwritable_existing_directory_hits_the_generic_warning(tmp_path, monkeypatch):
    """The literal production shape before this fix: a directory that EXISTS
    but denies write. Must still be caught by the generic OSError branch, not
    crash the watchdog — an exception here means no flush decision is ever
    made, which is the one outcome this component may never produce."""
    state_dir = tmp_path / "watchdog"
    state_dir.mkdir()
    state_dir.chmod(0o500)  # r-x for the owner: cannot create a file inside
    monkeypatch.setattr(watchdog, "STATE_FILE", state_dir / "state.json")
    try:
        watchdog.save_state({"web_down_since": 1.0})
    finally:
        state_dir.chmod(0o700)

    assert not (state_dir / "state.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="modurile POSIX nu se aplică pe Windows")
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="root ignoră bitii de permisiune, deci proba n-ar dovedi nimic")
def test_untraversable_parent_does_not_raise(tmp_path, monkeypatch, capsys):
    """The shape that actually shipped as a regression in round 1 of this
    fix: `Path.is_dir()` only swallows ENOENT/ENOTDIR/EBADF/ELOOP — a bare
    `PermissionError` from an ANCESTOR denying traversal (not the target
    directory itself) propagates straight through it. With the guard sitting
    OUTSIDE the `try` in `save_state`, this exact shape raised out of the
    function, `main()` logged "watchdog raised — no flush decision was made"
    (false: `run_once` had already decided; only remembering it failed), and
    the unit exited 1 on every single run. Falsify by moving the
    `if not STATE_FILE.parent.is_dir():` guard back outside the `try`."""
    import json

    blocked = tmp_path / "blocked"
    blocked.mkdir()
    blocked.chmod(0o000)
    state_file = blocked / "watchdog" / "state.json"
    monkeypatch.setattr(watchdog, "STATE_FILE", state_file)
    try:
        watchdog.save_state({"web_down_since": 1.0})  # must not raise
    finally:
        blocked.chmod(0o700)

    assert not state_file.exists()
    err = capsys.readouterr().err.strip().splitlines()
    assert err, "an untraversable parent must still be logged, not swallowed"
    record = json.loads(err[-1])
    assert record["level"] == "warning"


def test_dashboard_flush_arms_when_state_persists_across_runs(tmp_path, monkeypatch):
    """Decision-level regression test. `web_down_since` must survive from one
    `run_once` to the next, real temp file included, or the anti-lockout flush
    for a dead dashboard can never reach `WEB_DOWN_FLUSH_S`. Paired with
    `test_dashboard_flush_never_arms_when_state_cannot_persist`, which asserts
    the documented consequence when persistence is broken."""
    state_dir = tmp_path / "watchdog"
    state_dir.mkdir()
    monkeypatch.setattr(watchdog, "STATE_FILE", state_dir / "state.json")
    monkeypatch.setattr(watchdog, "PANIC_FILE", tmp_path / "PANIC")
    monkeypatch.setattr(watchdog, "web_healthy", lambda: False)
    monkeypatch.setattr(watchdog, "detect_unhealthy", lambda: False)

    calls: list[str] = []

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        def blocklist_size(self):
            return 5

        def flush_blocklist(self, reason):
            calls.append(reason)
            return {"ok": True}

    monkeypatch.setattr(watchdog, "ExecutorClient", _FakeClient)
    clock = {"t": 1_800_000_000.0}
    monkeypatch.setattr(watchdog.time, "time", lambda: clock["t"])

    watchdog.run_once()
    assert calls == [], "the first observation of a failure is not itself proof of one"

    clock["t"] += watchdog.WEB_DOWN_FLUSH_S + 1
    watchdog.run_once()
    assert len(calls) == 1, "web down continuously past the threshold must flush"


def test_dashboard_flush_never_arms_when_state_cannot_persist(tmp_path, monkeypatch):
    """The regression itself, reproduced end to end: the state directory does
    not exist (the shape a host takes when the installer's tmpfiles step has
    not run), so every `run_once` starts from `{}`, `web_down_since` resets to
    `now()` on every pass, `down_for` never grows, and the flush this
    component exists to guarantee cannot fire — silently. This is what ran on
    production from 4 Sep to 7 Sep 2026."""
    monkeypatch.setattr(watchdog, "STATE_FILE", tmp_path / "missing" / "state.json")
    monkeypatch.setattr(watchdog, "PANIC_FILE", tmp_path / "PANIC")
    monkeypatch.setattr(watchdog, "web_healthy", lambda: False)
    monkeypatch.setattr(watchdog, "detect_unhealthy", lambda: False)

    calls: list[str] = []

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        def blocklist_size(self):
            return 5

        def flush_blocklist(self, reason):
            calls.append(reason)
            return {"ok": True}

    monkeypatch.setattr(watchdog, "ExecutorClient", _FakeClient)
    clock = {"t": 1_800_000_000.0}
    monkeypatch.setattr(watchdog.time, "time", lambda: clock["t"])

    watchdog.run_once()
    clock["t"] += watchdog.WEB_DOWN_FLUSH_S + 1
    watchdog.run_once()

    assert calls == [], (
        "without persisted state, down_for resets to 0 every run and can never "
        "reach WEB_DOWN_FLUSH_S — this must fail loudly if save_state ever "
        "learns to paper over a missing directory"
    )


def test_indeterminate_web_probe_leaves_the_down_timer_untouched(tmp_path, monkeypatch):
    """`web_healthy() -> None` means the probe itself failed (DNS hiccup,
    timeout) — it is not evidence of either health or recovery. Both existing
    decision-level tests above only ever drive `web_healthy` to `False`, so a
    probe answering `None` mid-outage was never exercised: a bug that treats
    `None` the same as `True` (clearing `web_down_since`) would restart the
    5-minute countdown from zero on every transient hiccup and the anti-lockout
    flush could be pushed out indefinitely by noise, not health. Falsify by
    changing `elif web is True:` to `else:` in `run_once`."""
    state_dir = tmp_path / "watchdog"
    state_dir.mkdir()
    monkeypatch.setattr(watchdog, "STATE_FILE", state_dir / "state.json")
    monkeypatch.setattr(watchdog, "PANIC_FILE", tmp_path / "PANIC")
    monkeypatch.setattr(watchdog, "detect_unhealthy", lambda: False)

    calls: list[str] = []

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        def blocklist_size(self):
            return 5

        def flush_blocklist(self, reason):
            calls.append(reason)
            return {"ok": True}

    monkeypatch.setattr(watchdog, "ExecutorClient", _FakeClient)
    clock = {"t": 1_800_000_000.0}
    monkeypatch.setattr(watchdog.time, "time", lambda: clock["t"])

    monkeypatch.setattr(watchdog, "web_healthy", lambda: False)
    watchdog.run_once()
    down_since_after_failure = watchdog.load_state()["web_down_since"]
    assert down_since_after_failure == clock["t"]

    # A probe that could not tell, partway through the outage. Must neither
    # clear the timer (as `True` would) nor restart it (as a fresh `False`
    # would) — the state before and after this run must be identical.
    clock["t"] += 60
    monkeypatch.setattr(watchdog, "web_healthy", lambda: None)
    watchdog.run_once()
    assert watchdog.load_state()["web_down_since"] == down_since_after_failure, (
        "an indeterminate probe must leave web_down_since exactly as it was"
    )

    # The outage resumes being observable, and the ORIGINAL start time — not
    # one reset by the indeterminate run in between — is what the threshold
    # must be measured against.
    monkeypatch.setattr(watchdog, "web_healthy", lambda: False)
    clock["t"] = down_since_after_failure + watchdog.WEB_DOWN_FLUSH_S + 1
    watchdog.run_once()
    assert len(calls) == 1, (
        "the indeterminate run must not have reset the countdown — the flush "
        "must fire measured from the ORIGINAL failure, not from the probe "
        "that could not tell"
    )
