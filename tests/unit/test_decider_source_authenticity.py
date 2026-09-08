"""F3: a spoofable Suricata alert must not auto-block an innocent address, and
the decider must never touch this host's own DNS resolver.

Both guards protect the same kind of mistake: acting on an address the
detection cannot actually vouch for. `source_is_authentic` covers an alert
with no TCP protocol among its evidence — UDP, ICMP, GRE, IP-in-IP, SCTP, or
anything else an off-path attacker can put in a packet's source field freely,
no handshake required; `_is_configured_resolver` covers the resolver this
host itself asks, which a rule could name by coincidence (its own DNS traffic
tripping a signature) with no attacker involved at all.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.respond import decider

_REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.security


def run(c):
    return asyncio.run(c)


def _cfg(*, enabled=True, min_severity="high"):
    return SimpleNamespace(response=SimpleNamespace(auto_block=SimpleNamespace(
        enabled=enabled, min_severity=min_severity, max_per_minute=60,
        max_elements=20000, skip_known_scanners=True, allow_cidr_blocks=False,
        default_ttl_s=86400, max_active_cidrs=20)))


def _spec(*, actor_key="203.0.113.9", severity="high", rule_id="ids.suricata",
          evidence=None):
    return SimpleNamespace(
        actor_key=actor_key, src_ip=actor_key, rule_id=rule_id,
        severity=severity, evidence=evidence or {})


class _StubDB:
    """`flags` never gates these tests (always clean); `tcp_seen` answers the
    corroboration query. `is_active=True` short-circuits enforcement to
    'blocked' without a real executor call — same trick `test_decider.py`
    uses for every test past guard 7. Records every `(src_ip, window_min)`
    pair passed to the TCP-corroboration query in `tcp_query_args`, so a test
    can pin the exact window the decider asked about, not merely that some
    query ran — see `test_tcp_corroboration_query_uses_the_evidence_window`."""

    def __init__(self, *, tcp_seen=False, is_active=False):
        self.tcp_seen = tcp_seen
        self._is_active = is_active
        self.tcp_query_args: list[tuple] = []

    async def fetchrow(self, sql, *args):
        if "is_allowlisted, is_known_scanner" in sql:
            return {"is_allowlisted": False, "is_known_scanner": False, "reputation": []}
        return None

    async def fetchval(self, sql, *args):
        if "source IN ('nginx', 'sshd')" in sql:
            self.tcp_query_args.append(args)
            return 1 if self.tcp_seen else None
        if "AND active LIMIT 1" in sql:
            return 1 if self._is_active else None
        if "WHERE active" in sql and "created_by" not in sql:
            return 0
        if "created_by LIKE 'auto:%'" in sql:
            return 0
        return 0

    async def execute(self, sql, *args):
        return "UPDATE 1"


# --- source_is_authentic ----------------------------------------------------
def test_udp_only_alert_without_corroboration_is_refused():
    """The exact production shape: a single severity-1 signature over UDP,
    nothing else seen from that source. Must not arm — the source is not
    verified to be real."""
    db = _StubDB(tcp_seen=False)
    spec = _spec(evidence={"protocols": ["UDP"], "window_min": 10})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "skipped:spoofable_source"


def test_udp_only_alert_with_tcp_corroboration_is_blocked():
    """Same UDP-only alert, but the source also produced a real TCP exchange
    (an nginx request, an sshd line) in the same window: the address is
    verified reachable, so the block proceeds."""
    db = _StubDB(tcp_seen=True, is_active=True)
    spec = _spec(evidence={"protocols": ["UDP"], "window_min": 10})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "blocked"


def test_icmp_only_alert_without_corroboration_is_refused():
    db = _StubDB(tcp_seen=False)
    spec = _spec(evidence={"protocols": ["ICMP"], "window_min": 10})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "skipped:spoofable_source"


def test_mixed_udp_and_tcp_evidence_is_not_spoofable():
    """One TCP-sourced hit among the alerts for this source is enough on its
    own: the decider must not throw that evidence away just because most of
    the hits were UDP."""
    db = _StubDB(tcp_seen=False, is_active=True)  # no corroboration needed: evidence has TCP
    spec = _spec(evidence={"protocols": ["TCP", "UDP"], "window_min": 10})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "blocked"


def test_missing_protocol_evidence_is_treated_as_spoofable():
    """Unknown must never read as safe — evidence with no `protocols` key at
    all (an older row, a rule that forgot to set it) is refused exactly like
    UDP/ICMP-only, not waved through."""
    db = _StubDB(tcp_seen=False)
    spec = _spec(evidence={})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "skipped:spoofable_source"


# --- protocol check is a positive TCP proof, not an allowlist of spoofable
# names (R4) -----------------------------------------------------------------
# Before this fix, `_is_spoofable_evidence` asked "is every protocol present a
# KNOWN-spoofable one (UDP/ICMP/ICMP6/ICMPV6)?" — an allowlist of the
# untrusted side. Production logged severity-2 Suricata alerts over GRE (156
# of them) and IP-in-IP (14), and neither name was in that allowlist, so
# `protocols <= _SPOOFABLE_PROTOCOLS` was False for both — read as "not proven
# spoofable" and therefore treated as AUTHENTIC, with zero TCP corroboration.
# Any transport this allowlist had not anticipated auto-armed for free. Each
# test below pins one such protocol (plus SCTP and an ICMPv6 spelling) and
# asserts it is refused exactly like UDP/ICMP, never waved through.
def test_gre_only_alert_without_corroboration_is_refused():
    db = _StubDB(tcp_seen=False)
    spec = _spec(evidence={"protocols": ["GRE"], "window_min": 10})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "skipped:spoofable_source"


def test_ip_in_ip_only_alert_without_corroboration_is_refused():
    db = _StubDB(tcp_seen=False)
    spec = _spec(evidence={"protocols": ["IP-in-IP"], "window_min": 10})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "skipped:spoofable_source"


def test_ipv6_icmp_only_alert_without_corroboration_is_refused():
    """Suricata's own event log spells this `IPv6-ICMP`, not `ICMPV6` — the
    exact spelling the old allowlist did not contain."""
    db = _StubDB(tcp_seen=False)
    spec = _spec(evidence={"protocols": ["IPv6-ICMP"], "window_min": 10})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "skipped:spoofable_source"


def test_sctp_only_alert_without_corroboration_is_refused():
    db = _StubDB(tcp_seen=False)
    spec = _spec(evidence={"protocols": ["SCTP"], "window_min": 10})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "skipped:spoofable_source"


def test_tcp_present_among_other_protocols_is_authentic():
    """The positive proof, stated directly: TCP present anywhere in the list
    is enough on its own, whatever else is mixed in."""
    db = _StubDB(tcp_seen=False, is_active=True)  # no corroboration needed
    spec = _spec(evidence={"protocols": ["GRE", "TCP"], "window_min": 10})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "blocked"


def test_tcp_protocol_casing_is_authentic():
    """`'Tcp'` (mixed case) must count exactly like `'TCP'` — falsifies the
    case-normalisation the same way as the lower-case test below, from the
    opposite direction."""
    db = _StubDB(tcp_seen=False, is_active=True)
    spec = _spec(evidence={"protocols": ["Tcp"]})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "blocked"


def test_lowercase_tcp_protocol_is_still_authentic():
    """Suricata's own protocol strings are upper-case, but nothing guarantees
    every future writer of `evidence["protocols"]` keeps that convention —
    pins that `.upper()` is actually applied, not merely present in the
    source, by using a value the code would fail on if that call were ever
    silently removed."""
    db = _StubDB(tcp_seen=False, is_active=True)
    spec = _spec(evidence={"protocols": ["tcp"]})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "blocked"


def test_tcp_corroboration_query_uses_the_evidence_window_not_a_hardcoded_one():
    """The rule (`detect/rules.suricata_alert`) and this guard must search the
    SAME window for TCP corroboration — a hard-coded or scaled window here
    would silently make the guard too strict (missing corroboration that
    landed just outside the rule's actual window) or too loose (accepting
    traffic from outside it). Pins the literal value the decider sends to the
    query, not merely that some query runs — a stray `* 1000` on the window
    argument must fail this."""
    db = _StubDB(tcp_seen=False)
    spec = _spec(evidence={"protocols": ["UDP"], "window_min": 37})
    run(decider._decide(db, _cfg(), spec, 1))
    assert db.tcp_query_args, "the TCP-corroboration query was never issued"
    _src_ip, window_min = db.tcp_query_args[-1]
    assert window_min == 37


def test_guard_does_not_apply_to_non_suricata_rules():
    """`ssh_bruteforce`/`web_enumeration` evidence never carries `protocols`
    and never needs to — an sshd or nginx event cannot exist without a real
    TCP handshake in the first place. This guard must not accidentally start
    gating them too."""
    db = _StubDB(tcp_seen=False, is_active=True)
    spec = _spec(rule_id="auth.ssh_bruteforce", evidence={})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "blocked"


def test_disabled_auto_block_observes_a_spoofable_alert_not_skips():
    """Same convention as every other pre-enable guard: while disabled, the
    outcome is uniformly 'observed', not a guard-specific skip reason."""
    db = _StubDB(tcp_seen=False)
    spec = _spec(evidence={"protocols": ["UDP"]})
    assert run(decider._decide(db, _cfg(enabled=False), spec, 1)) == "observed"


def test_below_severity_gate_short_circuits_before_the_guard_runs():
    """A low-severity Suricata detection never reaches source_is_authentic at
    all — it is already 'observed' from the severity gate, not from this
    guard, and must not perform a DB query it does not need."""
    db = _StubDB(tcp_seen=False)
    spec = _spec(severity="low", evidence={"protocols": ["UDP"]})
    assert run(decider._decide(db, _cfg(min_severity="high"), spec, 1)) == "observed"


# --- never-block resolvers ---------------------------------------------------
@pytest.fixture(autouse=True)
def _reset_resolver_cache():
    """The cache is module-level and time-based; each test needs it primed
    (or emptied) from a known state, not whatever a previous test left.

    Resets to `None`, not `0.0` — a `0.0` sentinel compared against
    `time.monotonic()` (seconds since boot) is itself the R3 bug: it made the
    cache look "already loaded" until the host's uptime passed an hour. See
    `_resolvers_cache`'s comment in `decider.py`."""
    decider._resolvers_cache["loaded_at"] = None
    decider._resolvers_cache["addrs"] = frozenset()
    yield
    decider._resolvers_cache["loaded_at"] = None
    decider._resolvers_cache["addrs"] = frozenset()


def test_resolvers_cache_loaded_at_is_none_at_pristine_import():
    """`_reset_resolver_cache` above resets `loaded_at` to `None` before
    EVERY test in this file runs — which means a regression of the R3 bug
    (the module-level initial value reverted from `None` back to `0.0`) is
    invisible to every other test here: the autouse fixture overwrites the
    real starting value before any of them ever look at it. This test
    imports `decider` fresh in a subprocess, before that fixture (or
    anything else) has touched the module, and checks the value the module
    itself set at import time — the only vantage point from which a
    freshly-started `sentinel-detect` is actually observed: `0.0` would make
    guard 2 a no-op for the host's first hour of uptime after every deploy
    or restart, exactly the bug the R3 fix closed (see the comment on
    `_resolvers_cache` in decider.py)."""
    code = (
        "from sentinel.respond import decider\n"
        "import sys\n"
        "sys.exit(0 if decider._resolvers_cache['loaded_at'] is None else 1)\n"
    )
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-B", "-c", code],
        cwd=str(_REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        "decider._resolvers_cache['loaded_at'] was not None at pristine "
        f"import (returncode={result.returncode}, stdout={result.stdout!r}, "
        f"stderr={result.stderr!r})"
    )


def test_read_configured_resolvers_parses_nameserver_lines(tmp_path):
    """Pins the actual `/etc/resolv.conf` parsing: only `nameserver` lines,
    one address each — a directive whose second token merely LOOKS like an
    address (a `sortlist`/`domain`-style line) must not be picked up, or a
    resolv.conf with such a line would silently over-protect an address
    nobody configured as a resolver."""
    conf = tmp_path / "resolv.conf"
    conf.write_text(
        "# generated by NetworkManager\n"
        "nameserver 198.51.100.53\n"
        "nameserver 2001:db8::53\n"
        "search example.com\n"
        "sortlist 203.0.113.5\n",
        encoding="utf-8",
    )
    addrs = decider._read_configured_resolvers(str(conf))
    assert addrs == {"198.51.100.53", "2001:db8::53"}
    assert "203.0.113.5" not in addrs


def test_read_configured_resolvers_missing_file_is_empty_not_raising(tmp_path):
    """A host without the file (container, sandbox) must not crash the
    decider — this guard narrows what is protected, it never widens what is
    blockable, so an absent file is silently zero resolvers."""
    missing = tmp_path / "does-not-exist.conf"
    assert decider._read_configured_resolvers(str(missing)) == frozenset()


# --- resolver cache loads on first call, refreshes hourly (R3) -------------
def test_configured_resolvers_loads_on_first_call_regardless_of_uptime(monkeypatch, tmp_path):
    """Before the fix, `loaded_at` started at `0.0` and the guard reloaded
    only once `time.monotonic() - loaded_at > 3600` — so on a freshly booted
    or freshly restarted host, where `time.monotonic()` itself can be well
    under an hour, the comparison was already False and the cache looked
    "fresh" despite never having read the file even once. Guard 2 was
    therefore inert for the first hour after every boot. Pinning
    `time.monotonic()` at a small value must still load on the very first
    call — the fix is a `None` sentinel, not a smaller number."""
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 198.51.100.53\n", encoding="utf-8")
    monkeypatch.setattr(decider, "_RESOLV_CONF_PATH", str(conf))
    monkeypatch.setattr(decider.time, "monotonic", lambda: 30.0)

    assert decider._configured_resolvers() == {"198.51.100.53"}


def test_configured_resolvers_refreshes_after_the_window_elapses(monkeypatch, tmp_path):
    """Falsifies the cache the other way: a mutation that loads once and
    never refreshes again (e.g. pinning `loaded_at` permanently, or dropping
    the refresh comparison) must be caught. An operator who edits
    `/etc/resolv.conf` needs the guard to notice within the hour, not carry a
    stale resolver set for the life of the process."""
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 198.51.100.53\n", encoding="utf-8")
    monkeypatch.setattr(decider, "_RESOLV_CONF_PATH", str(conf))

    clock = {"t": 100.0}
    monkeypatch.setattr(decider.time, "monotonic", lambda: clock["t"])

    assert decider._configured_resolvers() == {"198.51.100.53"}

    conf.write_text("nameserver 203.0.113.53\n", encoding="utf-8")
    clock["t"] += 10  # well under the refresh window: must still be cached
    assert decider._configured_resolvers() == {"198.51.100.53"}

    clock["t"] += decider._RESOLVERS_REFRESH_S  # crosses the refresh boundary
    assert decider._configured_resolvers() == {"203.0.113.53"}


def test_configured_resolver_is_never_blocked_even_at_critical_severity(monkeypatch, tmp_path):
    """The concrete F3 scenario: Suricata (or any rule) fires on this host's
    own DNS resolver. However severe, however well-corroborated, it must
    never be auto-blocked — cutting it off breaks every other lookup this
    host makes, including its own alerting channel."""
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 198.51.100.53\n", encoding="utf-8")
    monkeypatch.setattr(decider, "_RESOLV_CONF_PATH", str(conf))

    db = _StubDB(tcp_seen=True)
    spec = _spec(actor_key="198.51.100.53", severity="critical",
                 rule_id="auth.ssh_bruteforce", evidence={})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "skipped:configured_resolver"


def test_an_address_that_is_not_a_configured_resolver_is_unaffected(monkeypatch, tmp_path):
    """Falsifies the guard the other way: an ordinary attacker address, with
    some OTHER address configured as the resolver, must still be blockable —
    the guard must match on the specific address, not refuse everything."""
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 198.51.100.53\n", encoding="utf-8")
    monkeypatch.setattr(decider, "_RESOLV_CONF_PATH", str(conf))

    db = _StubDB(tcp_seen=True, is_active=True)
    spec = _spec(actor_key="203.0.113.9", severity="critical",
                 rule_id="auth.ssh_bruteforce", evidence={})
    assert run(decider._decide(db, _cfg(), spec, 1)) == "blocked"


def test_disabled_auto_block_observes_the_resolver_not_skips(monkeypatch, tmp_path):
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 198.51.100.53\n", encoding="utf-8")
    monkeypatch.setattr(decider, "_RESOLV_CONF_PATH", str(conf))

    db = _StubDB()
    spec = _spec(actor_key="198.51.100.53", severity="critical",
                 rule_id="auth.ssh_bruteforce", evidence={})
    assert run(decider._decide(db, _cfg(enabled=False), spec, 1)) == "observed"
