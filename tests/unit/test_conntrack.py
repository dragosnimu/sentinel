"""F04: outbound-traffic sampling.

Every test here exists because of a measured bug or a measured gap:

* A naive read of `/proc/net/nf_conntrack` counted an INBOUND SSH session as
  an outbound connection, because conntrack stores both the original and the
  reply tuple for every flow it tracks. On the host this was built for, that
  naive reading found 81 "destinations" in 24h; only 5 were real.
* An exact-address-only direction check made every CONTAINER's egress
  invisible, because Docker's MASQUERADE rewrites the source only on the way
  OUT — conntrack's ORIGINAL tuple still carries the container's private
  bridge address. Measured on the host: one real outbound connection out of
  five had exactly this shape.
* Deduplication bounds a REPEATED destination, but nothing bounded a sample
  containing many destinations NEVER SEEN BEFORE — a scanner run from the
  host could produce unbounded daily volume.

`_HOST_IP` below is deliberately a GLOBALLY ROUTABLE address, not a private
one: the production host is internet-facing with no NAT in front of it, and
a private `_HOST_IP` would make every inbound-vs-outbound test pass for the
wrong reason — an inbound session's destination (the host itself) would
already be rejected by the is-global scope filter, independent of whether
the direction check does anything at all. That exact masking shipped once
and was only caught by re-running the tests with the direction check
deliberately broken.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from sentinel.collectors import conntrack as ct

# Fabricated, RFC-safe example addresses only — never anything measured on
# the real host, and this file is exempt from the "no real infrastructure"
# scan (tests/ is), so any address here is a synthetic stand-in, not a claim
# about who owns it.
#
# "1.1.1.1" plays the host's own address — GLOBAL, because the production
# host has no NAT in front of it and a private host address would mask the
# direction tests (see module docstring). "93.184.216.34" and "8.8.8.8" play
# globally-routable destinations that are not the host.
_HOST_IP = "1.1.1.1"
_PUBLIC_DST = "93.184.216.34"

# A Docker bridge subnet — private, owned by a LOCAL interface on the host,
# the shape `docker0`/`br-xxxx` actually has.
_BRIDGE_NET = "172.20.0.0/16"
_CONTAINER_IP = "172.20.0.5"

# Private, but NOT part of any subnet the host owns — stands in for "someone
# else's LAN this host happens to see traffic from", the boundary case
# `HostIdentity`'s docstring names as its assumption.
_UNRELATED_PRIVATE_IP = "10.77.0.9"


def _line(proto: str, src: str, dst: str, sport: int, dport: int) -> str:
    """One /proc/net/nf_conntrack row: ORIGINAL tuple, then REPLY tuple.

    Real kernel output repeats src=/dst=/sport=/dport= a second time for the
    reply direction — that repetition is exactly what `parse_line` must not
    be fooled by.
    """
    state = " ESTABLISHED" if proto == "tcp" else ""
    return (
        f"ipv4     2 {proto}      6 431999{state} "
        f"src={src} dst={dst} sport={sport} dport={dport} "
        f"src={dst} dst={src} sport={dport} dport={sport} "
        f"[ASSURED] mark=0 use=1"
    )


def _identity(ips=(), networks=()) -> ct.HostIdentity:
    import ipaddress as _ipaddress
    nets = tuple(
        n if hasattr(n, "network_address") else _ipaddress.ip_network(n, strict=False)
        for n in networks
    )
    return ct.HostIdentity(frozenset(ips), nets)


# ---------------------------------------------------------------------------
# parse_line: only the ORIGINAL tuple, never the reply
# ---------------------------------------------------------------------------
def test_parse_line_reads_the_original_tuple():
    tup = ct.parse_line(_line("tcp", _HOST_IP, _PUBLIC_DST, 51234, 443))
    assert tup is not None
    assert tup.proto == "tcp"
    assert tup.src == _HOST_IP and tup.dst == _PUBLIC_DST
    assert tup.sport == 51234 and tup.dport == 443


def test_parse_line_does_not_pick_up_the_reply_tuple():
    # If parsing ever preferred the LAST match instead of the first, this
    # would return dst=1.1.1.1 (the reply tuple's dst, i.e. the host) —
    # exactly the swap that produced the 81-vs-5 measurement.
    tup = ct.parse_line(_line("tcp", _HOST_IP, _PUBLIC_DST, 51234, 443))
    assert tup.dst != _HOST_IP


def test_parse_line_ignores_non_tcp_udp():
    icmp_line = "ipv4     1 icmp     1 29 src=10.0.0.5 dst=8.8.8.8 type=8 code=0 id=1"
    assert ct.parse_line(icmp_line) is None


@pytest.mark.parametrize("bad", ["", "short", "ipv4 2", "not a conntrack line at all"])
def test_parse_line_rejects_malformed_input(bad):
    assert ct.parse_line(bad) is None


def test_parse_line_rejects_non_numeric_ports():
    line = "ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.5 dst=8.8.8.8 sport=x dport=443 src=8.8.8.8 dst=10.0.0.5 sport=443 dport=x"
    assert ct.parse_line(line) is None


# ---------------------------------------------------------------------------
# HostIdentity: exact addresses AND locally-owned subnets
# ---------------------------------------------------------------------------
def test_host_identity_owns_its_exact_address():
    identity = _identity(ips={_HOST_IP})
    assert identity.owns(_HOST_IP) is True
    assert identity.owns(_PUBLIC_DST) is False


def test_host_identity_owns_an_address_inside_a_local_subnet():
    # This is the container-egress fix: the bridge subnet is owned even
    # though the container's own address is never in `ips`.
    identity = _identity(ips={_HOST_IP}, networks=[_BRIDGE_NET])
    assert identity.owns(_CONTAINER_IP) is True


def test_host_identity_does_not_own_unrelated_private_traffic():
    # The stated assumption's boundary: a private address that is NOT part
    # of any subnet the host's own interfaces report is NOT treated as ours,
    # even though it is RFC1918 like the bridge subnet is.
    identity = _identity(ips={_HOST_IP}, networks=[_BRIDGE_NET])
    assert identity.owns(_UNRELATED_PRIVATE_IP) is False


def test_host_identity_is_falsy_when_empty():
    assert bool(_identity()) is False
    assert bool(_identity(ips={_HOST_IP})) is True


# ---------------------------------------------------------------------------
# is_outbound: the direction discriminator itself
# ---------------------------------------------------------------------------
def test_outbound_connection_is_reported():
    tup = ct.parse_line(_line("tcp", _HOST_IP, _PUBLIC_DST, 51234, 443))
    assert ct.is_outbound(tup, _identity(ips={_HOST_IP})) is True


def test_inbound_ssh_session_is_not_reported_as_outbound():
    """THE regression test: an inbound SSH connection must never become an
    'outbound connection to :22'. This is precisely the bug measured on the
    host — a naive `grep dst=` counted 57 inbound SSH sessions as outbound
    destinations because it read the reply tuple instead of asking who
    dialled whom.

    `_HOST_IP` is GLOBAL on purpose (see module docstring): with a private
    host address this test would pass even if the direction check were
    deleted entirely, because the destination (the host itself) would
    already fail the is-global scope filter on its own. That masking
    happened once, silently, and was only caught by deliberately breaking
    the direction check and watching this test stay green.
    """
    remote_client = "203.0.113.44"  # someone connecting TO this host
    # The ORIGINAL tuple of an inbound session has the REMOTE address as src:
    # the remote end is the one that dialled.
    tup = ct.parse_line(_line("tcp", remote_client, _HOST_IP, 55555, 22))
    assert ct.is_outbound(tup, _identity(ips={_HOST_IP})) is False


def test_is_outbound_recognizes_container_egress_via_nat():
    """The container-egress fix, at the level that matters: a container's
    real outbound connection, with its pre-NAT bridge address as src,
    reaching a public destination, must be reported. Measured on the host:
    one of five real outbound connections had exactly this shape and an
    exact-address-only check silently dropped it."""
    identity = _identity(ips={_HOST_IP}, networks=[_BRIDGE_NET])
    tup = ct.parse_line(_line("tcp", _CONTAINER_IP, _PUBLIC_DST, 51234, 443))
    assert ct.is_outbound(tup, identity) is True


def test_is_outbound_does_not_widen_to_unrelated_private_sources():
    # The NAT fix must not become "any RFC1918 source is ours" — only
    # subnets the host's OWN interfaces actually report.
    identity = _identity(ips={_HOST_IP}, networks=[_BRIDGE_NET])
    tup = ct.parse_line(_line("tcp", _UNRELATED_PRIVATE_IP, _PUBLIC_DST, 51234, 443))
    assert ct.is_outbound(tup, identity) is False


def test_private_destination_is_not_reported():
    # Postgres on loopback, a docker bridge, an internal sidecar — all
    # host-initiated, none of them "outbound" in the sense that matters here.
    tup = ct.parse_line(_line("tcp", _HOST_IP, "127.0.0.1", 51234, 5432))
    assert ct.is_outbound(tup, _identity(ips={_HOST_IP})) is False

    tup2 = ct.parse_line(_line("tcp", _HOST_IP, "172.17.0.2", 51234, 80))
    assert ct.is_outbound(tup2, _identity(ips={_HOST_IP})) is False


def test_unparseable_destination_is_not_reported():
    tup = ct.ConnTuple(proto="tcp", src=_HOST_IP, dst="not-an-ip", sport=1, dport=443)
    assert ct.is_outbound(tup, _identity(ips={_HOST_IP})) is False


# ---------------------------------------------------------------------------
# discover_host_identity: never hardcoded, degrades to "cannot tell" on failure
# ---------------------------------------------------------------------------
def test_discover_host_identity_reads_all_local_interfaces(monkeypatch):
    import socket
    from types import SimpleNamespace as NS

    fake = {
        "lo": [NS(family=socket.AF_INET, address="127.0.0.1", netmask="255.0.0.0")],
        "eth0": [
            NS(family=socket.AF_INET, address=_HOST_IP, netmask="255.255.255.255"),
            NS(family=socket.AF_INET6, address="fe80::1%eth0", netmask=None),
            # A MAC address on the same interface must not be treated as an IP.
            NS(family=socket.AF_PACKET if hasattr(socket, "AF_PACKET") else -1,
               address="aa:bb:cc:dd:ee:ff", netmask=None),
        ],
        "docker0": [NS(family=socket.AF_INET, address="172.20.0.1", netmask="255.255.0.0")],
    }

    import psutil
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: fake)
    identity = ct.discover_host_identity()
    assert identity.ips == frozenset({"127.0.0.1", _HOST_IP, "fe80::1", "172.20.0.1"})
    # The docker bridge's own subnet must be usable to recognise container egress.
    assert identity.owns(_CONTAINER_IP) is True


def test_discover_host_identity_skips_an_unparseable_netmask(monkeypatch):
    import socket
    from types import SimpleNamespace as NS

    fake = {"weird0": [NS(family=socket.AF_INET, address=_HOST_IP, netmask="not-a-netmask")]}
    import psutil
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: fake)
    identity = ct.discover_host_identity()
    # The exact address still counts, even though no usable network came of it.
    assert identity.ips == frozenset({_HOST_IP})
    assert identity.owns(_HOST_IP) is True


def test_discover_host_identity_failure_returns_empty_not_a_guess(monkeypatch):
    import psutil
    def _boom():
        raise OSError("no netlink socket")
    monkeypatch.setattr(psutil, "net_if_addrs", _boom)
    identity = ct.discover_host_identity()
    assert bool(identity) is False


# ---------------------------------------------------------------------------
# _read: absent module vs. denied permission are different facts
# ---------------------------------------------------------------------------
def test_read_missing_file_is_absent_not_denied(tmp_path):
    outcome = ct._read(str(tmp_path / "does_not_exist"))
    assert outcome.status == "absent"


def test_denied_state_names_the_capability_that_actually_works(tmp_path, monkeypatch, caplog):
    """The one time this message is seen, the recommended fix must be right.
    Measured directly: CAP_DAC_READ_SEARCH (already granted to
    sentinel-ingest.service) lets a bare `sentinel` user read this root:root
    0440 file; CAP_NET_ADMIN does not bypass a DAC permission check at all.
    A collector whose whole design is "degrade loudly with the correct
    action" must not send the operator to the wrong capability the one time
    it speaks."""
    target = tmp_path / "nf_conntrack"
    target.write_text("irrelevant\n", encoding="utf-8")
    monkeypatch.setattr(ct, "discover_host_identity", lambda: _identity(ips={_HOST_IP}))
    s = ct.ConntrackSampler(str(target))

    def _denied(*a, **kw):
        raise PermissionError("Permission denied")

    monkeypatch.setattr("builtins.open", _denied)
    with caplog.at_level("ERROR", logger="sentinel.collectors.conntrack"):
        s.maybe_sample(now=1000.0)

    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "CAP_DAC_READ_SEARCH" in messages
    assert "CAP_NET_ADMIN" not in messages


def test_read_permission_denied_is_reported_distinctly(tmp_path, monkeypatch):
    target = tmp_path / "nf_conntrack"
    target.write_text("irrelevant\n", encoding="utf-8")

    def _denied(*a, **kw):
        raise PermissionError("Permission denied")

    monkeypatch.setattr("builtins.open", _denied)
    outcome = ct._read(str(target))
    assert outcome.status == "denied"


def test_read_success_returns_the_lines(tmp_path):
    target = tmp_path / "nf_conntrack"
    target.write_text(_line("tcp", _HOST_IP, _PUBLIC_DST, 1, 443) + "\n", encoding="utf-8")
    outcome = ct._read(str(target))
    assert outcome.status == "ok"
    assert len(outcome.lines) == 1


# ---------------------------------------------------------------------------
# ConntrackSampler: cadence, dedup, the end-to-end direction guard, and the
# new-destination cap
# ---------------------------------------------------------------------------
def _sampler(tmp_path, monkeypatch, lines: list[str]) -> ct.ConntrackSampler:
    path = tmp_path / "nf_conntrack"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setattr(ct, "discover_host_identity", lambda: _identity(ips={_HOST_IP}))
    return ct.ConntrackSampler(str(path))


def test_sampler_first_call_always_samples(tmp_path, monkeypatch):
    s = _sampler(tmp_path, monkeypatch, [_line("tcp", _HOST_IP, _PUBLIC_DST, 1, 443)])
    events = s.maybe_sample(now=1000.0)
    assert len(events) == 1
    assert events[0].source == "conntrack" and events[0].action == "connect"
    assert events[0].dst_ip == _PUBLIC_DST and events[0].dst_port == 443
    assert events[0].src_ip == _HOST_IP
    assert events[0].ts.tzinfo is not None


def test_sampler_end_to_end_inbound_is_dropped_outbound_kept(tmp_path, monkeypatch):
    """Full pipeline, not just the pure function: a file holding BOTH an
    inbound SSH row and a real outbound row must yield exactly one event, and
    it must be the outbound one. `_HOST_IP` is global, per the module
    docstring, so this genuinely exercises the direction check rather than
    riding on the scope filter."""
    inbound = _line("tcp", "203.0.113.44", _HOST_IP, 55555, 22)
    outbound = _line("tcp", _HOST_IP, _PUBLIC_DST, 51234, 443)
    s = _sampler(tmp_path, monkeypatch, [inbound, outbound])

    events = s.maybe_sample(now=1000.0)

    assert len(events) == 1
    assert events[0].dst_ip == _PUBLIC_DST
    assert all(e.dst_port != 22 for e in events)


def test_sampler_end_to_end_recognizes_container_egress(tmp_path, monkeypatch):
    """A container's outbound connection, sampled through the whole pipeline
    (file -> parse -> direction -> event), not just `is_outbound` in
    isolation."""
    path = tmp_path / "nf_conntrack"
    path.write_text(_line("tcp", _CONTAINER_IP, _PUBLIC_DST, 1, 443) + "\n", encoding="utf-8")
    monkeypatch.setattr(ct, "discover_host_identity",
                        lambda: _identity(ips={_HOST_IP}, networks=[_BRIDGE_NET]))
    s = ct.ConntrackSampler(str(path))

    events = s.maybe_sample(now=1000.0)

    assert len(events) == 1
    assert events[0].src_ip == _CONTAINER_IP and events[0].dst_ip == _PUBLIC_DST


def test_sampler_does_not_sample_before_its_interval_elapses(tmp_path, monkeypatch):
    """A dedup check alone would make this pass for the wrong reason — the
    SAME destination sampled 30s later is suppressed by `DEDUP_WINDOW_S`
    (1h) regardless of whether the cadence gate exists. To isolate the
    cadence gate, the file changes to a BRAND NEW destination between calls:
    if the gate were missing, the premature call would read the file and
    emit it (nothing in the dedup cache would stop a destination never seen
    before)."""
    path = tmp_path / "nf_conntrack"
    path.write_text(_line("tcp", _HOST_IP, _PUBLIC_DST, 1, 443) + "\n", encoding="utf-8")
    monkeypatch.setattr(ct, "discover_host_identity", lambda: _identity(ips={_HOST_IP}))
    s = ct.ConntrackSampler(str(path))

    first = s.maybe_sample(now=1000.0)
    assert len(first) == 1

    second_dst = "8.8.8.8"  # never seen before -> dedup cannot be why this is quiet
    path.write_text(_line("tcp", _HOST_IP, second_dst, 2, 443) + "\n", encoding="utf-8")
    # 30s later: well inside SAMPLE_INTERVAL_S (60s) — must not even read the
    # file again, let alone emit the brand new destination now sitting in it.
    premature = s.maybe_sample(now=1030.0)
    assert premature == []

    # Past the interval: now it must see the new destination.
    due = s.maybe_sample(now=1000.0 + ct.SAMPLE_INTERVAL_S + 1)
    assert len(due) == 1 and due[0].dst_ip == second_dst


def test_sampler_dedups_a_steady_destination_within_the_window(tmp_path, monkeypatch):
    """A destination that answers every single sample for an hour must not
    produce 60 rows — see the module docstring's volume budget."""
    s = _sampler(tmp_path, monkeypatch, [_line("tcp", _HOST_IP, _PUBLIC_DST, 1, 443)])
    now = 1000.0
    total_events = 0
    for _ in range(60):  # 60 samples, one per minute -> a full hour
        total_events += len(s.maybe_sample(now=now))
        now += ct.SAMPLE_INTERVAL_S
    # First sample emits; the following 59, all inside DEDUP_WINDOW_S, must not.
    assert total_events == 1


def test_sampler_re_announces_after_the_dedup_window(tmp_path, monkeypatch):
    s = _sampler(tmp_path, monkeypatch, [_line("tcp", _HOST_IP, _PUBLIC_DST, 1, 443)])
    first = s.maybe_sample(now=0.0)
    assert len(first) == 1
    # Just before the dedup window closes, and past the sample-cadence gate
    # (SAMPLE_INTERVAL_S) so this call actually reads the file.
    just_inside = s.maybe_sample(now=float(ct.DEDUP_WINDOW_S - 1))
    assert just_inside == []
    # Past BOTH the dedup window (measured from the first emission) and the
    # sample cadence (measured from the previous call, which also touched
    # `_last_sample_at` even though it emitted nothing).
    after_window = s.maybe_sample(
        now=float(ct.DEDUP_WINDOW_S - 1 + ct.SAMPLE_INTERVAL_S + 1))
    assert len(after_window) == 1


def test_sampler_missing_source_degrades_without_raising(tmp_path, monkeypatch):
    monkeypatch.setattr(ct, "discover_host_identity", lambda: _identity(ips={_HOST_IP}))
    s = ct.ConntrackSampler(str(tmp_path / "nf_conntrack"))  # never created
    events = s.maybe_sample(now=1000.0)  # FileNotFoundError path
    assert events == []


def test_sampler_permission_denied_degrades_without_raising(tmp_path, monkeypatch):
    target = tmp_path / "nf_conntrack"
    target.write_text("irrelevant\n", encoding="utf-8")
    monkeypatch.setattr(ct, "discover_host_identity", lambda: _identity(ips={_HOST_IP}))
    s = ct.ConntrackSampler(str(target))

    def _denied(*a, **kw):
        raise PermissionError("Permission denied")

    monkeypatch.setattr("builtins.open", _denied)
    events = s.maybe_sample(now=1000.0)  # PermissionError path, through the full sampler
    assert events == []


def test_sampler_stays_quiet_when_host_identity_cannot_be_discovered(tmp_path, monkeypatch):
    path = tmp_path / "nf_conntrack"
    path.write_text(_line("tcp", _HOST_IP, _PUBLIC_DST, 1, 443) + "\n", encoding="utf-8")
    monkeypatch.setattr(ct, "discover_host_identity", lambda: _identity())
    s = ct.ConntrackSampler(str(path))
    assert s.maybe_sample(now=1000.0) == []


def test_sampler_cache_is_pruned_so_it_does_not_grow_forever(tmp_path, monkeypatch):
    s = _sampler(tmp_path, monkeypatch, [_line("tcp", _HOST_IP, _PUBLIC_DST, 1, 443)])
    s.maybe_sample(now=0.0)
    assert len(s._last_emitted) == 1
    # Long past _CACHE_TTL_S with the destination gone quiet: the stale entry
    # must be forgotten, or the dict grows for the life of the daemon.
    empty_path = tmp_path / "empty"
    empty_path.write_text("\n", encoding="utf-8")
    s._path = str(empty_path)
    s.maybe_sample(now=float(ct._CACHE_TTL_S + 100))
    assert len(s._last_emitted) == 0


# ---------------------------------------------------------------------------
# MAX_NEW_PER_SAMPLE: unbounded distinct-new-destination volume, bounded
# ---------------------------------------------------------------------------
def _synthetic_public_ip(i: int) -> str:
    # 6.0.0.0/8 is a plain allocated unicast range with no meaning here beyond
    # "globally routable and distinct" — this file is exempt from the
    # real-infrastructure scan (tests/ is), and this is not anyone's address.
    return f"6.{(i // 65536) % 256}.{(i // 256) % 256}.{i % 256}"


def test_max_new_per_sample_caps_emission_and_logs_seen_vs_kept(tmp_path, monkeypatch, caplog):
    """A scanner run from the host (or a burst of connection attempts to
    random addresses) must not turn into unbounded daily volume. Measured
    without a cap: 1,000 new destinations in one sample, repeated over 10
    samples with a different 1,000 each time, produced 10,000 rows with
    nothing to stop it going higher."""
    n = ct.MAX_NEW_PER_SAMPLE + 25
    lines = [_line("tcp", _HOST_IP, _synthetic_public_ip(i), 1, 443) for i in range(n)]
    s = _sampler(tmp_path, monkeypatch, lines)

    with caplog.at_level("WARNING", logger="sentinel.collectors.conntrack"):
        events = s.maybe_sample(now=1000.0)

    assert len(events) == ct.MAX_NEW_PER_SAMPLE, (
        "the cap must actually cap — this is the volume ceiling, not a suggestion")

    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert getattr(warnings[0], "seen", None) == n
    assert getattr(warnings[0], "kept", None) == ct.MAX_NEW_PER_SAMPLE, (
        "truncation must say BOTH numbers — 'we saw N, kept the cap' — or a "
        "truncated count reads exactly like a complete one")


def test_capped_backlog_is_retried_on_the_next_sample(tmp_path, monkeypatch):
    """What the cap drops is not lost forever: the destinations left over
    from one sample are not cached as 'already reported', so the NEXT sample
    picks up where the last one left off instead of only ever seeing the
    first `MAX_NEW_PER_SAMPLE` destinations in file order."""
    n = ct.MAX_NEW_PER_SAMPLE + 10
    lines = [_line("tcp", _HOST_IP, _synthetic_public_ip(i), 1, 443) for i in range(n)]
    s = _sampler(tmp_path, monkeypatch, lines)

    first = s.maybe_sample(now=1000.0)
    second = s.maybe_sample(now=1000.0 + ct.SAMPLE_INTERVAL_S + 1)

    assert len(first) == ct.MAX_NEW_PER_SAMPLE
    assert len(second) == 10, "the 10 left over from the cap must surface next time"
    first_dsts = {e.dst_ip for e in first}
    second_dsts = {e.dst_ip for e in second}
    assert first_dsts.isdisjoint(second_dsts), "no destination should be reported twice"
    assert len(first_dsts | second_dsts) == n, "every destination must eventually be reported"


def test_below_the_cap_nothing_is_truncated_or_logged(tmp_path, monkeypatch, caplog):
    lines = [_line("tcp", _HOST_IP, _synthetic_public_ip(i), 1, 443)
             for i in range(ct.MAX_NEW_PER_SAMPLE - 1)]
    s = _sampler(tmp_path, monkeypatch, lines)

    with caplog.at_level("WARNING", logger="sentinel.collectors.conntrack"):
        events = s.maybe_sample(now=1000.0)

    assert len(events) == ct.MAX_NEW_PER_SAMPLE - 1
    assert not [r for r in caplog.records if r.levelname == "WARNING"]


# ---------------------------------------------------------------------------
# Wiring: the ingest daemon actually calls the sampler
# ---------------------------------------------------------------------------
def test_ingest_poll_once_actually_calls_the_conntrack_sampler(monkeypatch):
    """Regression for a decoupling reproduced during review: deleting the one
    line in `Ingest.poll_once` that calls `self._conntrack.maybe_sample()`
    left the FULL test suite green, because nothing exercised the wiring
    itself — only the sampler's own unit tests, in isolation, which still
    pass perfectly well when nobody calls them from production code.

    This matters beyond a missing assertion: `check_ingest_sources` in
    `sentinel/selfcheck/checks.py` only judges a source that has EVER
    produced a row. A collector that is built but never invoked — severed
    wiring, or permission denied from the very first poll — produces total,
    permanent silence with no failing selfcheck anywhere, ever. This test is
    the only thing standing between that and shipping unnoticed.
    """
    from sentinel.model.event import Event
    from sentinel.services import ingest_service

    class _FakeSampler:
        def __init__(self, events):
            self._events = events
            self.calls = 0

        def maybe_sample(self):
            self.calls += 1
            return self._events

    ev = Event(ts=datetime.now(timezone.utc), source="conntrack", action="connect",
               src_ip=_HOST_IP, src_port=51234,
               dst_ip=_PUBLIC_DST, dst_port=443, proto="tcp")
    fake = _FakeSampler([ev])

    cfg = SimpleNamespace(ingest=SimpleNamespace(exclude_sources=()),
                          history=SimpleNamespace(skip_command_accounts=()))
    ingest = ingest_service.Ingest(cfg, db=None)
    ingest._conntrack = fake

    inserted: list = []

    async def fake_insert(db, events):
        inserted.extend(events)
        return len(events)

    async def fake_set_cursor(db, name, cursor, *, events_seen=0):
        pass

    monkeypatch.setattr(ingest_service.events_repo, "insert_batch", fake_insert)
    monkeypatch.setattr(ingest_service.events_repo, "set_cursor", fake_set_cursor)

    n = asyncio.run(ingest.poll_once())

    assert fake.calls == 1, "poll_once must call maybe_sample exactly once per poll"
    assert n == 1
    assert len(inserted) == 1
    assert inserted[0].source == "conntrack" and inserted[0].dst_ip == _PUBLIC_DST


def test_ingest_setup_constructs_the_sampler_when_enabled(monkeypatch, tmp_path):
    """The other half of the wiring: `setup()` must actually build a
    `ConntrackSampler` when the config says to, not just `poll_once` calling
    whatever happens to be there."""
    from sentinel.services import ingest_service

    cfg = SimpleNamespace(
        ingest=SimpleNamespace(
            journald=False, nginx=False, suricata=False, auditd=False,
            conntrack=True, conntrack_path=str(tmp_path / "nf_conntrack"),
            exclude_sources=()),
        suricata=SimpleNamespace(enabled=False),
        history=SimpleNamespace(skip_command_accounts=()))
    ingest = ingest_service.Ingest(cfg, db=None)
    asyncio.run(ingest.setup())
    assert ingest._conntrack is not None
    assert isinstance(ingest._conntrack, ingest_service.ConntrackSampler)
