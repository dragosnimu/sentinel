"""F04: outbound-traffic sampling.

Every test here exists because of one measured bug: a naive read of
`/proc/net/nf_conntrack` counted an INBOUND SSH session as an outbound
connection, because conntrack stores both the original and the reply tuple
for every flow it tracks. On the host this was built for, that naive reading
found 81 "destinations" in 24h; only 5 were real. `test_inbound_ssh_session_is_not_reported_as_outbound`
is the test that would have caught it.
"""
from __future__ import annotations

from datetime import timezone

import pytest

from sentinel.collectors import conntrack as ct

# Fabricated, RFC-safe example addresses only — never anything measured on
# the real host. "10.0.0.5" plays the host's own (private, RFC1918) address;
# "93.184.216.34" and "8.8.8.8" play globally-routable destinations that are
# not the host and not the operator's own infrastructure.
_HOST_IP = "10.0.0.5"
_PUBLIC_DST = "93.184.216.34"


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
    # would return dst=10.0.0.5 (the reply tuple's dst, i.e. the host) —
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
# is_outbound: the direction discriminator itself
# ---------------------------------------------------------------------------
def test_outbound_connection_is_reported():
    tup = ct.parse_line(_line("tcp", _HOST_IP, _PUBLIC_DST, 51234, 443))
    assert ct.is_outbound(tup, frozenset({_HOST_IP})) is True


def test_inbound_ssh_session_is_not_reported_as_outbound():
    """THE regression test: an inbound SSH connection must never become an
    'outbound connection to :22'. This is precisely the bug measured on the
    host — a naive `grep dst=` counted 57 inbound SSH sessions as outbound
    destinations because it read the reply tuple instead of asking who
    dialled whom."""
    remote_client = "203.0.113.44"  # someone connecting TO this host
    # The ORIGINAL tuple of an inbound session has the REMOTE address as src:
    # the remote end is the one that dialled.
    tup = ct.parse_line(_line("tcp", remote_client, _HOST_IP, 55555, 22))
    assert ct.is_outbound(tup, frozenset({_HOST_IP})) is False


def test_inbound_session_on_a_publicly_addressed_host_is_still_not_outbound():
    """Same bug, but with the host's OWN address made globally routable —
    the production host is internet-facing (nginx on :8443, no NAT), so its
    address is not RFC1918. A direction check that only worked by accident
    because `_HOST_IP` above is private (and so gets rejected by the
    global-scope filter regardless, independent of direction) would pass
    every other test in this file and still misreport every inbound session
    on the real host.

    `198.51.100.0/24` and `203.0.113.0/24` (the documentation ranges this
    file otherwise uses) are themselves treated as private by Python's
    `ipaddress`, so they cannot stand in for a public address here — that
    would silently recreate the same masking. "1.1.1.1" is a well-known
    public resolver address, not the operator's infrastructure.
    """
    public_host_ip = "1.1.1.1"
    remote_client = "198.51.100.9"
    tup = ct.parse_line(_line("tcp", remote_client, public_host_ip, 55555, 22))
    assert ct.is_outbound(tup, frozenset({public_host_ip})) is False


def test_private_destination_is_not_reported():
    # Postgres on loopback, a docker bridge, an internal sidecar — all
    # host-initiated, none of them "outbound" in the sense that matters here.
    tup = ct.parse_line(_line("tcp", _HOST_IP, "127.0.0.1", 51234, 5432))
    assert ct.is_outbound(tup, frozenset({_HOST_IP})) is False

    tup2 = ct.parse_line(_line("tcp", _HOST_IP, "172.17.0.2", 51234, 80))
    assert ct.is_outbound(tup2, frozenset({_HOST_IP})) is False


def test_unparseable_destination_is_not_reported():
    tup = ct.ConnTuple(proto="tcp", src=_HOST_IP, dst="not-an-ip", sport=1, dport=443)
    assert ct.is_outbound(tup, frozenset({_HOST_IP})) is False


# ---------------------------------------------------------------------------
# discover_host_ips: never hardcoded, degrades to "cannot tell" on failure
# ---------------------------------------------------------------------------
def test_discover_host_ips_reads_all_local_interfaces(monkeypatch):
    import socket
    from types import SimpleNamespace

    fake = {
        "lo": [SimpleNamespace(family=socket.AF_INET, address="127.0.0.1")],
        "eth0": [
            SimpleNamespace(family=socket.AF_INET, address=_HOST_IP),
            SimpleNamespace(family=socket.AF_INET6, address="fe80::1%eth0"),
            # A MAC address on the same interface must not be treated as an IP.
            SimpleNamespace(family=socket.AF_PACKET if hasattr(socket, "AF_PACKET")
                             else -1, address="aa:bb:cc:dd:ee:ff"),
        ],
    }

    import psutil
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: fake)
    ips = ct.discover_host_ips()
    assert ips == frozenset({"127.0.0.1", _HOST_IP, "fe80::1"})


def test_discover_host_ips_failure_returns_empty_not_a_guess(monkeypatch):
    import psutil
    def _boom():
        raise OSError("no netlink socket")
    monkeypatch.setattr(psutil, "net_if_addrs", _boom)
    assert ct.discover_host_ips() == frozenset()


# ---------------------------------------------------------------------------
# _read: absent module vs. denied permission are different facts
# ---------------------------------------------------------------------------
def test_read_missing_file_is_absent_not_denied(tmp_path):
    outcome = ct._read(str(tmp_path / "does_not_exist"))
    assert outcome.status == "absent"


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
# ConntrackSampler: cadence, dedup, and the end-to-end direction guard
# ---------------------------------------------------------------------------
def _sampler(tmp_path, monkeypatch, lines: list[str]) -> ct.ConntrackSampler:
    path = tmp_path / "nf_conntrack"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setattr(ct, "discover_host_ips", lambda: frozenset({_HOST_IP}))
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
    it must be the outbound one. This is the fact that matters to the
    operator — that the collector, as wired together, does not turn an
    incoming SSH session into a false 'new outbound destination' alert."""
    inbound = _line("tcp", "203.0.113.44", _HOST_IP, 55555, 22)
    outbound = _line("tcp", _HOST_IP, _PUBLIC_DST, 51234, 443)
    s = _sampler(tmp_path, monkeypatch, [inbound, outbound])

    events = s.maybe_sample(now=1000.0)

    assert len(events) == 1
    assert events[0].dst_ip == _PUBLIC_DST
    assert all(e.dst_port != 22 for e in events)


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
    monkeypatch.setattr(ct, "discover_host_ips", lambda: frozenset({_HOST_IP}))
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
    monkeypatch.setattr(ct, "discover_host_ips", lambda: frozenset({_HOST_IP}))
    s = ct.ConntrackSampler(str(tmp_path / "nf_conntrack"))  # never created
    events = s.maybe_sample(now=1000.0)  # FileNotFoundError path
    assert events == []


def test_sampler_permission_denied_degrades_without_raising(tmp_path, monkeypatch):
    target = tmp_path / "nf_conntrack"
    target.write_text("irrelevant\n", encoding="utf-8")
    monkeypatch.setattr(ct, "discover_host_ips", lambda: frozenset({_HOST_IP}))
    s = ct.ConntrackSampler(str(target))

    def _denied(*a, **kw):
        raise PermissionError("Permission denied")

    monkeypatch.setattr("builtins.open", _denied)
    events = s.maybe_sample(now=1000.0)  # PermissionError path, through the full sampler
    assert events == []


def test_sampler_stays_quiet_when_host_ips_cannot_be_discovered(tmp_path, monkeypatch):
    path = tmp_path / "nf_conntrack"
    path.write_text(_line("tcp", _HOST_IP, _PUBLIC_DST, 1, 443) + "\n", encoding="utf-8")
    monkeypatch.setattr(ct, "discover_host_ips", lambda: frozenset())
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
