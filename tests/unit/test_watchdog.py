"""The anti-lockout deadman's decision logic.

`decide()` is a pure function precisely so it can be tested exhaustively without
a server, an executor or a systemd. Every branch is covered here, because the
failure mode of this component is "the operator cannot get back into their own
server" and that is not something to discover in production.
"""

from __future__ import annotations

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
