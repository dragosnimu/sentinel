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
import ipaddress
import os
import textwrap
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

# ---------------------------------------------------------------------------
# Fixtures for discover_host_identity's real source: /proc/net/route and
# /proc/net/fib_trie. Shapes below mirror what was actually measured on the
# production host (see the collector's module docstring), with every real
# address replaced by a fabricated stand-in — this file is exempt from the
# real-infrastructure scan, but there is no reason to tempt it.
#
# _HOST_IP (1.1.1.1) sits in a fabricated /21, same as the production
# host's public interface. _BRIDGE_SUBNET_16/_BRIDGE_HOST_ADDR stand in for
# a Docker bridge — deliberately a DIFFERENT /16 than `_BRIDGE_NET` above so
# this section's fixtures stay independent of the is_outbound tests.
_HOST_SUBNET_21 = "1.1.0.0"          # 1.1.1.1 & 255.255.248.0
_BRIDGE_SUBNET_16 = "172.30.0.0"
_BRIDGE_HOST_ADDR = "172.30.0.1"     # the bridge's OWN address, not a container's


def _ip_to_route_hex(ip: str) -> str:
    """Encode an IPv4 address the way `/proc/net/route` prints it: the raw
    bytes, reversed. Written independently of `ct._hex_to_ipv4` — a
    round-trip test using the SAME implementation on both sides would prove
    only that the code agrees with itself."""
    octets = [int(p) for p in ip.split(".")]
    return "".join(f"{b:02X}" for b in reversed(octets))


def _route_fixture_text() -> str:
    """A `/proc/net/route` table with one of each shape that matters: a
    gatewayed default route (not ours), a local-attached PUBLIC route (ours
    exactly, not by subnet), a local-attached PRIVATE route (a Docker
    bridge — ours by subnet), a down interface's route (must not count even
    though its Gateway column is zero), and one unparseable line."""
    header = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT"
    gatewayed = (
        f"eth0\t00000000\t{_ip_to_route_hex('1.1.0.1')}\t0003\t0\t0\t0\t"
        f"{_ip_to_route_hex('0.0.0.0')}\t0\t0\t0"
    )
    local_public = (
        f"eth0\t{_ip_to_route_hex(_HOST_SUBNET_21)}\t{_ip_to_route_hex('0.0.0.0')}\t0001\t0\t0\t0\t"
        f"{_ip_to_route_hex('255.255.248.0')}\t0\t0\t0"
    )
    local_bridge = (
        f"docker0\t{_ip_to_route_hex(_BRIDGE_SUBNET_16)}\t{_ip_to_route_hex('0.0.0.0')}\t0001\t0\t0\t0\t"
        f"{_ip_to_route_hex('255.255.0.0')}\t0\t0\t0"
    )
    down_iface = (
        f"eth1\t{_ip_to_route_hex('192.168.99.0')}\t{_ip_to_route_hex('0.0.0.0')}\t0000\t0\t0\t0\t"
        f"{_ip_to_route_hex('255.255.255.0')}\t0\t0\t0"
    )
    malformed = "not a route line at all"
    return "\n".join(
        [header, gatewayed, local_public, local_bridge, down_iface, malformed]
    ) + "\n"


def _fib_trie_fixture_text() -> str:
    """A `/proc/net/fib_trie` excerpt with the shape actually measured on
    the production host: an address line immediately followed by
    `/32 host LOCAL` for a real local address, and BROADCAST leaves (both
    `/32 link BROADCAST` and a bare network `/N link BROADCAST`) that must
    NOT be picked up. Includes a duplicate `Local:` section, as the real
    file does, to prove the result is deduplicated."""
    return textwrap.dedent(f"""\
        Main:
          +-- 0.0.0.0/0 3 0 5
             +-- 127.0.0.0/8 2 0 2
                +-- 127.0.0.0/8 2 0 2
                   |-- 127.0.0.0
                      /8 link BROADCAST
                   |-- 127.0.0.1
                      /32 host LOCAL
                   |-- 127.255.255.255
                      /32 link BROADCAST
             +-- {_BRIDGE_SUBNET_16}/16 2 0 2
                +-- {_BRIDGE_SUBNET_16}/16 2 0 2
                   |-- {_BRIDGE_SUBNET_16}
                      /16 link BROADCAST
                   |-- {_BRIDGE_HOST_ADDR}
                      /32 host LOCAL
             +-- {_HOST_SUBNET_21}/21 2 0 1
                |-- {_HOST_IP}
                   /32 host LOCAL
        Local:
          +-- 0.0.0.0/0 3 0 5
             +-- 127.0.0.0/8 2 0 2
                |-- 127.0.0.1
                   /32 host LOCAL
             +-- {_HOST_SUBNET_21}/21 2 0 1
                |-- {_HOST_IP}
                   /32 host LOCAL
        """)


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


# /proc/net/tcp's own header — column positions matter (`_parse_proc_net_tcp`
# reads local/remote address by fixed index, and inode by index 9), the exact
# text does not.
_TCP_HEADER = ("  sl  local_address rem_address   st tx_queue rx_queue tr "
               "tm->when retrnsmt   uid  timeout inode")


def _tcp_row(local_ip: str, local_port: int, remote_ip: str, remote_port: int,
             inode: str, st: str = "01") -> str:
    """One `/proc/net/tcp` data row. Address encoding reuses `_ip_to_route_hex`
    — /proc/net/route and /proc/net/tcp print a raw IPv4 the same way, the
    same convention `_hex_to_ipv4`'s own docstring describes. Port is plain
    big-endian hex, unlike the address — not reversed."""
    local = f"{_ip_to_route_hex(local_ip)}:{local_port:04X}"
    remote = f"{_ip_to_route_hex(remote_ip)}:{remote_port:04X}"
    return (f"   0: {local} {remote} {st} 00000000:00000000 "
            f"00:00000000 00000000  1000        0 {inode} 1 0000000000000000 100 0 0 10 0")


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


def test_is_outbound_rejects_a_destination_that_is_the_host_itself():
    """The second line of defence: even if `src` were wrongly considered
    ours (a subnet-ownership mistake anywhere upstream), a destination that
    is the host's OWN address can never be a genuine outbound connection.
    Independent of `HostIdentity.networks` being private-only — this check
    would still have caught the /21-neighbour false positive on its own."""
    identity = _identity(ips={_HOST_IP})
    # Contrive the exact shape of the measured bug directly: something the
    # identity considers "owned" (the host's own address, standing in for a
    # source a broken network rule might wrongly own) dialling the host's
    # own address back.
    tup = ct.ConnTuple(proto="tcp", src=_HOST_IP, dst=_HOST_IP, sport=1, dport=22)
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
# _hex_to_ipv4: the little-endian hex fields /proc/net/route actually prints
# ---------------------------------------------------------------------------
def test_hex_to_ipv4_decodes_the_real_measured_shapes():
    """Both values below are the EXACT hex strings measured on the
    production host (see the collector's module docstring) — a /21 mask and
    a Docker bridge's /16 network — decoded independently of `ct`'s own
    encoder (`_ip_to_route_hex`), so this is not the code checking itself."""
    assert ct._hex_to_ipv4("00F8FFFF") == "255.255.248.0"
    assert ct._hex_to_ipv4(_ip_to_route_hex("172.30.0.0")) == "172.30.0.0"
    assert ct._hex_to_ipv4(_ip_to_route_hex(_HOST_IP)) == _HOST_IP


def test_hex_to_ipv4_rejects_a_field_that_is_not_4_bytes():
    """A kernel field this parser cannot fully decode must raise, not
    silently fabricate a truncated or padded address — the same standard
    `parse_line` holds itself to for conntrack's own fields."""
    with pytest.raises(ValueError):
        ct._hex_to_ipv4("AB")
    with pytest.raises(ValueError):
        ct._hex_to_ipv4("not-hex-1")


# ---------------------------------------------------------------------------
# _local_subnets_from_route: /proc/net/route -> owned PRIVATE subnets only
# ---------------------------------------------------------------------------
def test_local_subnets_from_route_keeps_the_local_private_route():
    nets = ct._local_subnets_from_route(_route_fixture_text())
    assert ipaddress.ip_network(f"{_BRIDGE_SUBNET_16}/16") in nets


def test_local_subnets_from_route_excludes_the_local_public_route():
    """The /21-neighbour bug, at the route-parsing layer: a locally-attached
    route whose OWN network address is public must not become a subnet the
    host claims to own — that would recreate the exact widening `HostIdentity`
    exists to prevent, just fed from a different source."""
    nets = ct._local_subnets_from_route(_route_fixture_text())
    assert ipaddress.ip_network(f"{_HOST_SUBNET_21}/21") not in nets


def test_local_subnets_from_route_excludes_a_gatewayed_route():
    """A route reached through a gateway (Destination 0.0.0.0/0 in the
    fixture) is not this host's own subnet, whatever its mask says."""
    nets = ct._local_subnets_from_route(_route_fixture_text())
    assert ipaddress.ip_network("0.0.0.0/0") not in nets


def test_local_subnets_from_route_excludes_a_down_interface():
    """Flags=0000 (RTF_UP not set) in the fixture's `eth1` line: a route
    whose Gateway column happens to be zero but whose interface is down must
    not be read as an owned subnet."""
    nets = ct._local_subnets_from_route(_route_fixture_text())
    assert ipaddress.ip_network("192.168.99.0/24") not in nets


def test_local_subnets_from_route_skips_unparseable_lines_without_raising():
    # The fixture's last line ("not a route line at all") must not crash
    # parsing of the well-formed lines around it.
    nets = ct._local_subnets_from_route(_route_fixture_text())
    assert len(nets) == 1


# ---------------------------------------------------------------------------
# _host_addresses_from_fib_trie: /proc/net/fib_trie -> exact local addresses
# ---------------------------------------------------------------------------
def test_host_addresses_from_fib_trie_finds_every_local_leaf():
    ips = ct._host_addresses_from_fib_trie(_fib_trie_fixture_text())
    assert ips == {"127.0.0.1", _BRIDGE_HOST_ADDR, _HOST_IP}


def test_host_addresses_from_fib_trie_ignores_broadcast_leaves():
    """The trap this fixes: a naive 'any address line under this trie'
    read would also pick up `127.0.0.0` and `127.255.255.255`
    (`/32 link BROADCAST`) and the bridge's bare network address
    (`/16 link BROADCAST`) — none of which is an address configured on this
    host. Only the line whose NEXT line is exactly `/32 host LOCAL` counts."""
    ips = ct._host_addresses_from_fib_trie(_fib_trie_fixture_text())
    assert "127.0.0.0" not in ips
    assert "127.255.255.255" not in ips
    assert _BRIDGE_SUBNET_16 not in ips


# ---------------------------------------------------------------------------
# discover_host_identity: reads /proc/net/route + /proc/net/fib_trie,
# never hardcoded, degrades to "cannot tell" on failure
# ---------------------------------------------------------------------------
def test_discover_host_identity_reads_route_and_fib_trie(tmp_path, monkeypatch):
    """End-to-end through the real entry point, not the parsing helpers in
    isolation: given the fixture files on disk, `discover_host_identity`
    must own the host's exact public address AND the bridge subnet, while
    NOT owning the /21 neighbour around the public address — the same
    /21-neighbour guarantee the old psutil-based version made, now proven
    against the file-based source that replaced it.
    """
    route_path = tmp_path / "route"
    fib_path = tmp_path / "fib_trie"
    route_path.write_text(_route_fixture_text(), encoding="ascii")
    fib_path.write_text(_fib_trie_fixture_text(), encoding="ascii")
    monkeypatch.setattr(ct, "_ROUTE_PATH", str(route_path))
    monkeypatch.setattr(ct, "_FIB_TRIE_PATH", str(fib_path))

    identity = ct.discover_host_identity()

    assert identity.ips == frozenset({"127.0.0.1", _BRIDGE_HOST_ADDR, _HOST_IP})
    # The docker bridge's own subnet must be usable to recognise container egress.
    assert identity.owns(_BRIDGE_HOST_ADDR) is True
    assert identity.owns(f"{_BRIDGE_SUBNET_16.rsplit('.', 1)[0]}.5") is True  # a container address
    # The exact host address is still ours...
    assert identity.owns(_HOST_IP) is True
    # ...but the /21 around it is the PROVIDER's shared segment, not ours.
    assert identity.owns("1.1.0.7") is False


def test_discover_host_identity_needs_no_socket_of_any_family(tmp_path, monkeypatch):
    """THE regression test for the production outage: the previous,
    psutil-based implementation needed an AF_NETLINK socket to enumerate
    interfaces, and sentinel-ingest.service's
    `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` blocks exactly that —
    measured on the host as `OSError: [Errno 97] Address family not
    supported by protocol`, on every single poll, forever. This test makes
    ANY socket construction raise that same error and asserts discovery
    still succeeds — so a regression back to a socket-enumeration library
    (psutil or otherwise) fails HERE, in under a second, instead of silently
    in production."""
    import socket as _socket

    def _no_sockets_allowed(*a, **kw):
        raise OSError(97, "Address family not supported by protocol")

    monkeypatch.setattr(_socket, "socket", _no_sockets_allowed)

    route_path = tmp_path / "route"
    fib_path = tmp_path / "fib_trie"
    route_path.write_text(_route_fixture_text(), encoding="ascii")
    fib_path.write_text(_fib_trie_fixture_text(), encoding="ascii")
    monkeypatch.setattr(ct, "_ROUTE_PATH", str(route_path))
    monkeypatch.setattr(ct, "_FIB_TRIE_PATH", str(fib_path))

    identity = ct.discover_host_identity()

    assert bool(identity) is True
    assert identity.owns(_HOST_IP) is True


def test_conntrack_module_no_longer_imports_psutil():
    """A direct guard on the regression itself: if `psutil` is ever
    reimported at module scope here, this fails immediately — instead of
    the collector going silent in production the next time
    RestrictAddressFamilies is enforced (it already is, today)."""
    assert not hasattr(ct, "psutil")


def test_discover_host_identity_failure_returns_empty_not_a_guess(tmp_path, monkeypatch):
    monkeypatch.setattr(ct, "_ROUTE_PATH", str(tmp_path / "does_not_exist_route"))
    monkeypatch.setattr(ct, "_FIB_TRIE_PATH", str(tmp_path / "does_not_exist_fib_trie"))
    identity = ct.discover_host_identity()
    assert bool(identity) is False


def test_discover_host_identity_returns_empty_when_only_one_file_is_missing(tmp_path, monkeypatch):
    """Partial success is not success: a host where `fib_trie` reads fine but
    `route` does not must stay quiet ENTIRELY, not build an identity with
    addresses but silently no subnets. `bool(identity)` alone cannot catch
    this — an identity with `ips` populated but `networks` silently empty is
    already truthy, so this checks both fields directly: reproduced during
    review, splitting the two reads into independent try/except blocks left
    this exact case with `ips` populated and `networks` quietly empty, and
    every test that only checked `bool(identity)` stayed green."""
    fib_path = tmp_path / "fib_trie"
    fib_path.write_text(_fib_trie_fixture_text(), encoding="ascii")
    monkeypatch.setattr(ct, "_ROUTE_PATH", str(tmp_path / "does_not_exist_route"))
    monkeypatch.setattr(ct, "_FIB_TRIE_PATH", str(fib_path))
    identity = ct.discover_host_identity()
    assert identity.ips == frozenset()
    assert identity.networks == ()


def test_discover_host_identity_is_falsy_if_fib_trie_format_ever_drifts(tmp_path, monkeypatch):
    """The assumption this whole source rests on, made concrete: nothing
    guarantees a future kernel keeps printing `/32 host LOCAL` the way this
    parser expects. If the format ever drifts and no leaf matches, the
    result must be the SAME safe "cannot tell" as any other discovery
    failure — quiet, not a false claim that the host has no addresses being
    read as "the host owns nothing, so nothing it does is outbound"."""
    route_path = tmp_path / "route"
    fib_path = tmp_path / "fib_trie"
    route_path.write_text(_route_fixture_text(), encoding="ascii")
    fib_path.write_text("Main:\n  totally reformatted, matches nothing\n", encoding="ascii")
    monkeypatch.setattr(ct, "_ROUTE_PATH", str(route_path))
    monkeypatch.setattr(ct, "_FIB_TRIE_PATH", str(fib_path))
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
    # Attribution defaults to "found nothing, table readable" here, not the
    # real /proc — a test built to exercise direction/dedup/cap logic has no
    # reason to also depend on THIS machine's actual process table, on
    # whichever OS runs the suite. Tests that care about attribution itself
    # override these explicitly, after this call.
    monkeypatch.setattr(ct, "_build_tcp_socket_index", lambda: ({}, True))
    monkeypatch.setattr(ct, "_scan_fd_sockets", lambda: ({}, 0, 0))
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
    isolation. Also THE regression proof for the production bug: even
    though `_build_tcp_socket_index` returns an index that WOULD have
    matched this exact tuple (an inode is right there), the event must
    report `"container_egress"`, never `"closed_before_scan"` — the source
    is only owned via `HostIdentity.networks`, and the host's own
    `/proc/net/tcp` was never going to contain a container's socket
    regardless of what that index holds."""
    path = tmp_path / "nf_conntrack"
    path.write_text(_line("tcp", _CONTAINER_IP, _PUBLIC_DST, 1, 443) + "\n", encoding="utf-8")
    monkeypatch.setattr(ct, "discover_host_identity",
                        lambda: _identity(ips={_HOST_IP}, networks=[_BRIDGE_NET]))
    monkeypatch.setattr(ct, "_build_tcp_socket_index",
                         lambda: ({(_CONTAINER_IP, 1, _PUBLIC_DST, 443): ("999", "1000")}, True))
    monkeypatch.setattr(ct, "_scan_fd_sockets", lambda: ({"999": "777"}, 1, 0))
    s = ct.ConntrackSampler(str(path))

    events = s.maybe_sample(now=1000.0)

    assert len(events) == 1
    assert events[0].src_ip == _CONTAINER_IP and events[0].dst_ip == _PUBLIC_DST
    assert events[0].raw["process_status"] == "container_egress"
    assert events[0].process is None


def test_sampler_end_to_end_reports_host_tcp_unreadable_not_closed(tmp_path, monkeypatch):
    """THE other half of the same production bug: `/proc/net/tcp` itself
    unreadable must not make a HOST-owned connection look identical to
    "the connection closed before this sampler looked"."""
    s = _sampler(tmp_path, monkeypatch, [_line("tcp", _HOST_IP, _PUBLIC_DST, 51234, 443)])
    monkeypatch.setattr(ct, "_build_tcp_socket_index", lambda: ({}, False))
    monkeypatch.setattr(ct, "_scan_fd_sockets", lambda: ({}, 0, 0))

    events = s.maybe_sample(now=1000.0)

    assert len(events) == 1
    assert events[0].raw["process_status"] == "host_tcp_unreadable"


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


def test_dedup_key_distinguishes_destinations_by_port(tmp_path, monkeypatch):
    """Reproduced during review: reducing the dedup key to `(proto, dst)`,
    dropping `dport`, left every test in this file green — 69 passed across
    all four files touching conntrack. Two DIFFERENT services on the same
    destination address (443 and 8443) are two different destinations for
    this purpose, and must not suppress each other."""
    lines = [
        _line("tcp", _HOST_IP, _PUBLIC_DST, 1, 443),
        _line("tcp", _HOST_IP, _PUBLIC_DST, 2, 8443),
    ]
    s = _sampler(tmp_path, monkeypatch, lines)

    events = s.maybe_sample(now=1000.0)

    ports = sorted(e.dst_port for e in events)
    assert ports == [443, 8443], (
        "a dedup key without dport would treat these as the same "
        "destination and drop one of them")


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


# ---------------------------------------------------------------------------
# _hex_to_ipv6: the four-native-endian-words shape /proc/net/tcp6 documents
# itself as using — checked against a literal kernel-formatted row, not an
# independent encoder (see the test's own docstring for why the mirror
# encoder this file used to check against was itself the circular part).
# ---------------------------------------------------------------------------
def test_hex_to_ipv6_decodes_a_literal_kernel_row_for_loopback():
    """NOT checked against a mirror encoder (a test written independently but
    by the same hand can still share the same wrong assumption about byte
    order — the exact trap this file's own docstring names for
    `_hex_to_ipv4`'s route-hex helper). This is the literal `/proc/net/tcp6`
    field for `::1`, decoded independently of anything in this module.

    Written as four space-separated 32-bit words, not one unbroken run of
    32 hex characters: `bytes.fromhex` treats the two identically (spaces
    between byte pairs are ignored), and an unbroken 32-hex-char literal is
    exactly the shape `tests/security/test_repo_is_sanitised.py` flags as a
    possible planted secret — measured directly: it did, before this."""
    assert ct._hex_to_ipv6("00000000 00000000 00000000 01000000") == "::1"


def test_hex_to_ipv6_rejects_a_field_that_is_not_16_bytes():
    with pytest.raises(ValueError):
        ct._hex_to_ipv6("AB")


# ---------------------------------------------------------------------------
# _parse_proc_net_tcp: the 4-tuple -> inode index a live TCP table gives up
# ---------------------------------------------------------------------------
def test_parse_proc_net_tcp_maps_the_4_tuple_to_its_inode_and_uid():
    """`_tcp_row`'s fixed uid column ("1000", see its own docstring) must
    come back alongside the inode — the uid is what still names an owner on
    a row this process cannot resolve a pid for (see `_uid_to_name`,
    `attribute_process`'s `"not_attributable"` case)."""
    text = "\n".join([_TCP_HEADER,
                       _tcp_row(_HOST_IP, 51234, _PUBLIC_DST, 443, "999888")]) + "\n"
    index = ct._parse_proc_net_tcp(text, v6=False)
    assert index[(_HOST_IP, 51234, _PUBLIC_DST, 443)] == ("999888", "1000")


def test_parse_proc_net_tcp_skips_a_zero_inode_row():
    """TIME_WAIT and similar transient rows report inode 0. Matching against
    one can never resolve to a process — keeping it would only plant false
    confidence that a lookup might still succeed."""
    text = "\n".join([_TCP_HEADER, _tcp_row(_HOST_IP, 1, _PUBLIC_DST, 443, "0")]) + "\n"
    assert ct._parse_proc_net_tcp(text, v6=False) == {}


def test_parse_proc_net_tcp_skips_unparseable_lines_without_raising():
    text = "\n".join([_TCP_HEADER, "not a proc net tcp line at all"]) + "\n"
    assert ct._parse_proc_net_tcp(text, v6=False) == {}


def test_build_tcp_socket_index_combines_both_tables_and_tolerates_a_missing_tcp6(
        tmp_path, monkeypatch):
    """A missing `/proc/net/tcp6` is the EXPECTED, permanent shape on a host
    with IPv6 disabled (see the module docstring) — it must not flip
    `tcp_v4_readable` to False, which would misreport every host-owned
    connection as `"host_tcp_unreadable"` instead of actually looking them up."""
    tcp_path = tmp_path / "tcp"
    tcp6_path = tmp_path / "tcp6"  # deliberately never created
    tcp_path.write_text(
        "\n".join([_TCP_HEADER, _tcp_row(_HOST_IP, 1, _PUBLIC_DST, 443, "42")]) + "\n",
        encoding="ascii")
    monkeypatch.setattr(ct, "_PROC_NET_TCP_PATH", str(tcp_path))
    monkeypatch.setattr(ct, "_PROC_NET_TCP6_PATH", str(tcp6_path))

    index, tcp_v4_readable = ct._build_tcp_socket_index()

    assert index[(_HOST_IP, 1, _PUBLIC_DST, 443)] == ("42", "1000")
    assert tcp_v4_readable is True


def test_build_tcp_socket_index_reports_unreadable_when_tcp_itself_fails(
        tmp_path, monkeypatch):
    """THE regression this flag exists for: `/proc/net/tcp` itself
    unreadable must be told apart from "read fine, connection just wasn't in
    it" — collapsing the two, before this fix, turned a real regression into
    every host-owned row silently reporting `"closed_before_scan"`."""
    monkeypatch.setattr(ct, "_PROC_NET_TCP_PATH", str(tmp_path / "does_not_exist_tcp"))
    monkeypatch.setattr(ct, "_PROC_NET_TCP6_PATH", str(tmp_path / "does_not_exist_tcp6"))

    index, tcp_v4_readable = ct._build_tcp_socket_index()

    assert index == {}
    assert tcp_v4_readable is False


# ---------------------------------------------------------------------------
# _scan_fd_sockets: the ptrace ceiling, measured on the production host —
# os.listdir on another user's fd directory succeeds (CAP_DAC_READ_SEARCH),
# os.readlink on an entry inside it does not (ptrace_may_access).
# ---------------------------------------------------------------------------
def test_scan_fd_sockets_distinguishes_found_denied_and_non_socket(monkeypatch):
    """Regression for the discovery that CAP_DAC_READ_SEARCH lets `listdir`
    traverse another user's fd directory while `readlink` on an entry inside
    it still needs ptrace access — measured on the production host at 3,030
    attempts, 2,953 (97.5%) denied. Collapsing 'denied' into 'not found'
    would make a falling attribution rate look identical to nobody having
    tried, which is exactly the distinction the module docstring exists to
    keep visible."""
    real_listdir, real_readlink = os.listdir, os.readlink
    listings = {"/proc": ["1", "2", "notapid"],
                "/proc/1/fd": ["0", "1"],
                "/proc/2/fd": ["5"]}
    targets = {"/proc/1/fd/0": "socket:[111]",
               "/proc/1/fd/1": "/dev/null"}  # a real fd, just not a socket

    def fake_listdir(path):
        return listings[path] if path in listings else real_listdir(path)

    def fake_readlink(path):
        if path in targets:
            return targets[path]
        if path == "/proc/2/fd/5":
            raise PermissionError(path)  # another user's socket
        return real_readlink(path)

    monkeypatch.setattr(ct.os, "listdir", fake_listdir)
    monkeypatch.setattr(ct.os, "readlink", fake_readlink)
    monkeypatch.setattr(ct, "_PROC_ROOT", "/proc")

    inode_to_pid, attempted, denied = ct._scan_fd_sockets()

    assert inode_to_pid == {"111": "1"}
    assert attempted == 3
    assert denied == 1


def test_scan_fd_sockets_skips_a_pid_that_exited_mid_walk(monkeypatch):
    """A pid can vanish between listing /proc and listing its own fd
    directory — this must degrade the same as a genuine permission denial,
    not raise and abort the whole scan."""
    real_listdir = os.listdir

    def fake_listdir(path):
        if path == "/proc":
            return ["1"]
        if path == "/proc/1/fd":
            raise FileNotFoundError(path)
        return real_listdir(path)

    monkeypatch.setattr(ct.os, "listdir", fake_listdir)
    monkeypatch.setattr(ct, "_PROC_ROOT", "/proc")

    inode_to_pid, attempted, denied = ct._scan_fd_sockets()
    assert inode_to_pid == {} and attempted == 0 and denied == 0


# ---------------------------------------------------------------------------
# _process_info: comm/exe for a pid attribution already proved readable
# ---------------------------------------------------------------------------
def test_process_info_reads_comm_and_exe(monkeypatch):
    import io
    real_open, real_readlink = open, os.readlink

    def fake_open(path, *a, **kw):
        if path == "/proc/123/comm":
            return io.StringIO("python3.12\n")
        return real_open(path, *a, **kw)

    def fake_readlink(path):
        if path == "/proc/123/exe":
            return "/usr/bin/python3.12"
        return real_readlink(path)

    monkeypatch.setattr("builtins.open", fake_open)
    monkeypatch.setattr(ct.os, "readlink", fake_readlink)
    monkeypatch.setattr(ct, "_PROC_ROOT", "/proc")

    comm, exe = ct._process_info("123")
    assert comm == "python3.12"
    assert exe == "/usr/bin/python3.12"


def test_process_info_degrades_to_none_when_the_pid_is_already_gone(monkeypatch):
    def _raise(*a, **kw):
        raise FileNotFoundError("gone")

    monkeypatch.setattr("builtins.open", _raise)
    monkeypatch.setattr(ct.os, "readlink", _raise)
    monkeypatch.setattr(ct, "_PROC_ROOT", "/proc")

    comm, exe = ct._process_info("999")
    assert comm is None and exe is None


# ---------------------------------------------------------------------------
# attribute_process: the six honest outcomes, and only six
# ---------------------------------------------------------------------------
def test_attribute_process_udp_is_never_attempted():
    """No per-connection fd table for UDP on the path this module was asked
    to use — a UDP row must say so, not silently look identical to a TCP
    row nobody could attribute."""
    tup = ct.ConnTuple(proto="udp", src=_HOST_IP, dst=_PUBLIC_DST, sport=1, dport=53)
    attr = ct.attribute_process(tup, {}, {}, is_host_src=True, tcp_readable=True)
    assert attr.status == "udp_unsupported"
    assert attr.process is None and attr.pid is None


def test_attribute_process_reports_container_egress_before_ever_looking_at_the_table():
    """THE fix for the collapse measured on production: a container-owned
    source (only in `HostIdentity.networks`, never `.ips`) must never fall
    through to `"closed_before_scan"` just because the HOST's own
    `/proc/net/tcp` structurally cannot list it. Proven here with a
    `tcp_index` that WOULD have matched, had the container check not run
    first — anything other than `"container_egress"` means the miss was
    misread as a closed connection."""
    tup = ct.ConnTuple(proto="tcp", src="172.20.0.5", dst=_PUBLIC_DST, sport=1, dport=443)
    tcp_index = {("172.20.0.5", 1, _PUBLIC_DST, 443): ("999", "1000")}
    attr = ct.attribute_process(tup, tcp_index, {"999": "777"},
                                 is_host_src=False, tcp_readable=True)
    assert attr.status == "container_egress"
    assert attr.process is None and attr.uid is None


def test_attribute_process_container_egress_outranks_an_unreadable_table():
    """A container-owned source reports `"container_egress"` even when the
    table ALSO could not be read — the table's readability changes nothing
    about a connection it could never have shown anyway, so this must not
    become `"host_tcp_unreadable"` instead."""
    tup = ct.ConnTuple(proto="tcp", src="172.20.0.5", dst=_PUBLIC_DST, sport=1, dport=443)
    attr = ct.attribute_process(tup, {}, {}, is_host_src=False, tcp_readable=False)
    assert attr.status == "container_egress"


def test_attribute_process_reports_host_tcp_unreadable_not_closed(monkeypatch):
    """THE other fix for the same collapse: `/proc/net/tcp` itself failing
    to read must not look like every host-owned connection having closed —
    that is a real regression (the file needs no capability this unit
    lacks) with its own distinct status."""
    tup = ct.ConnTuple(proto="tcp", src=_HOST_IP, dst=_PUBLIC_DST, sport=1, dport=443)
    attr = ct.attribute_process(tup, {}, {}, is_host_src=True, tcp_readable=False)
    assert attr.status == "host_tcp_unreadable"


def test_attribute_process_reports_closed_before_scan_when_never_in_the_tcp_table():
    tup = ct.ConnTuple(proto="tcp", src=_HOST_IP, dst=_PUBLIC_DST, sport=1, dport=443)
    attr = ct.attribute_process(tup, {}, {"999": "123"}, is_host_src=True, tcp_readable=True)
    assert attr.status == "closed_before_scan"


def test_attribute_process_reports_not_attributable_when_the_owner_could_not_be_read():
    """The socket exists (it is in the TCP table) but this process could not
    read whose fd it was — the measured 97.5% case, not the same fact as
    'the connection was already gone'."""
    tup = ct.ConnTuple(proto="tcp", src=_HOST_IP, dst=_PUBLIC_DST, sport=1, dport=443)
    tcp_index = {(_HOST_IP, 1, _PUBLIC_DST, 443): ("42", "1000")}
    attr = ct.attribute_process(tup, tcp_index, {}, is_host_src=True, tcp_readable=True)
    assert attr.status == "not_attributable"


def test_attribute_process_not_attributable_still_carries_the_uid(monkeypatch):
    """The whole point of parsing `uid` at all: it names an owner for free
    even on a row this process could never resolve a pid for — the 97.5%
    case, and the one `process_status` alone cannot help an operator with."""
    tup = ct.ConnTuple(proto="tcp", src=_HOST_IP, dst=_PUBLIC_DST, sport=1, dport=443)
    tcp_index = {(_HOST_IP, 1, _PUBLIC_DST, 443): ("42", "116")}
    monkeypatch.setattr(ct, "_uid_to_name", lambda uid: "postgres" if uid == "116" else None)

    attr = ct.attribute_process(tup, tcp_index, {}, is_host_src=True, tcp_readable=True)

    assert attr.status == "not_attributable"
    assert attr.uid == "116"
    assert attr.user == "postgres"


def test_attribute_process_found_carries_process_pid_exe_and_uid(monkeypatch):
    tup = ct.ConnTuple(proto="tcp", src=_HOST_IP, dst=_PUBLIC_DST, sport=1, dport=443)
    tcp_index = {(_HOST_IP, 1, _PUBLIC_DST, 443): ("42", "1000")}
    inode_to_pid = {"42": "777"}
    monkeypatch.setattr(ct, "_process_info", lambda pid: ("curl", "/usr/bin/curl"))
    monkeypatch.setattr(ct, "_uid_to_name", lambda uid: "sentinel")

    attr = ct.attribute_process(tup, tcp_index, inode_to_pid,
                                 is_host_src=True, tcp_readable=True)

    assert attr.status == "found"
    assert attr.process == "curl"
    assert attr.pid == 777
    assert attr.exe == "/usr/bin/curl"
    assert attr.uid == "1000"
    assert attr.user == "sentinel"


def test_attribute_process_does_not_report_a_pid_with_no_name(monkeypatch):
    """The race window between `_scan_fd_sockets` and reading `comm`: a pid
    was briefly known but the process exited before a name could be read.
    A pid without a process name is not 'found' — it must fall back to the
    same 'not_attributable' as never having resolved a pid at all, not leak
    a number the operator cannot act on either."""
    tup = ct.ConnTuple(proto="tcp", src=_HOST_IP, dst=_PUBLIC_DST, sport=1, dport=443)
    tcp_index = {(_HOST_IP, 1, _PUBLIC_DST, 443): ("42", "1000")}
    inode_to_pid = {"42": "777"}
    monkeypatch.setattr(ct, "_process_info", lambda pid: (None, None))

    attr = ct.attribute_process(tup, tcp_index, inode_to_pid,
                                 is_host_src=True, tcp_readable=True)

    assert attr.status == "not_attributable"
    assert attr.pid is None


# ---------------------------------------------------------------------------
# _uid_to_name: resolves via the local passwd database, never guesses
# ---------------------------------------------------------------------------
def test_uid_to_name_resolves_a_known_uid(monkeypatch):
    """`pwd` is stubbed via `sys.modules`, not relied upon to exist — this
    must pass on the Windows dev box this suite also runs on, where the real
    `pwd` module does not exist at all (see `_uid_to_name`'s own `except
    ImportError` branch, and `sentinel/collectors/auditd.py`'s identical
    pattern)."""
    import sys
    import types
    fake_pwd = types.SimpleNamespace(
        getpwuid=lambda u: types.SimpleNamespace(pw_name="postgres"))
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)
    assert ct._uid_to_name("116") == "postgres"


def test_uid_to_name_returns_none_for_an_unmapped_uid(monkeypatch):
    import sys
    import types

    def _no_such_uid(u):
        raise KeyError(u)

    fake_pwd = types.SimpleNamespace(getpwuid=_no_such_uid)
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)
    assert ct._uid_to_name("999999") is None


def test_uid_to_name_returns_none_for_a_uid_that_is_not_a_number():
    """Platform-independent on purpose: a uid string that fails `int()`
    never reaches `pwd` at all, so this passes whether or not the real `pwd`
    module exists on the machine running the suite."""
    assert ct._uid_to_name("not-a-number") is None


# ---------------------------------------------------------------------------
# ConntrackSampler wiring: attribution reaches the emitted Event, costs
# nothing when there is nothing new to attribute, and never touches TCP
# machinery for an all-UDP sample
# ---------------------------------------------------------------------------
def test_sampler_end_to_end_attributes_a_kept_connection(tmp_path, monkeypatch):
    """THE operator-facing fix: 'new destination X' must be able to say what
    opened it, not just the bare IP the original incident could never be
    triaged from."""
    s = _sampler(tmp_path, monkeypatch, [_line("tcp", _HOST_IP, _PUBLIC_DST, 51234, 443)])
    monkeypatch.setattr(ct, "_build_tcp_socket_index",
                         lambda: ({(_HOST_IP, 51234, _PUBLIC_DST, 443): ("999", "1000")}, True))
    monkeypatch.setattr(ct, "_scan_fd_sockets", lambda: ({"999": "777"}, 10, 5))
    monkeypatch.setattr(ct, "_process_info", lambda pid: ("curl", "/usr/bin/curl"))
    monkeypatch.setattr(ct, "_uid_to_name", lambda uid: "sentinel")

    events = s.maybe_sample(now=1000.0)

    assert len(events) == 1
    ev = events[0]
    assert ev.process == "curl" and ev.pid == 777
    assert ev.raw["process_status"] == "found"
    assert ev.raw["exe"] == "/usr/bin/curl"
    assert ev.raw["uid"] == "1000" and ev.raw["user"] == "sentinel"


def test_sampler_records_unknown_distinctly_from_never_collected(tmp_path, monkeypatch):
    """CLAUDE.md's core distinction, at the row level: a connection this
    sampler genuinely could not attribute must say so explicitly
    (`process_status` present, `process` NULL) — never a bare NULL `process`
    indistinguishable from a row written before attribution existed."""
    s = _sampler(tmp_path, monkeypatch, [_line("tcp", _HOST_IP, _PUBLIC_DST, 51234, 443)])
    monkeypatch.setattr(ct, "_build_tcp_socket_index", lambda: ({}, True))
    monkeypatch.setattr(ct, "_scan_fd_sockets", lambda: ({}, 0, 0))

    events = s.maybe_sample(now=1000.0)

    assert events[0].process is None
    assert events[0].raw["process_status"] == "closed_before_scan"


def test_every_emitted_event_carries_an_explicit_process_status(tmp_path, monkeypatch):
    """A code path that forgot to set `process_status` would silently
    reintroduce 'nobody can tell if attribution was ever attempted' — the
    exact ambiguity this whole feature exists to remove."""
    s = _sampler(tmp_path, monkeypatch, [_line("tcp", _HOST_IP, _PUBLIC_DST, 1, 443)])
    events = s.maybe_sample(now=1000.0)
    assert "process_status" in events[0].raw


def test_sampler_skips_attribution_scans_for_a_sample_with_nothing_new(tmp_path, monkeypatch):
    """Attribution costs real syscalls — a full `/proc` walk. A sample where
    everything is already deduplicated must not pay that cost for zero
    benefit: nothing new is being emitted for it to attribute."""
    s = _sampler(tmp_path, monkeypatch, [_line("tcp", _HOST_IP, _PUBLIC_DST, 1, 443)])
    s.maybe_sample(now=0.0)  # primes the dedup cache

    def _must_not_run():
        raise AssertionError("attribution scan ran for a sample with nothing new to emit")

    monkeypatch.setattr(ct, "_build_tcp_socket_index", lambda: _must_not_run())
    monkeypatch.setattr(ct, "_scan_fd_sockets", lambda: _must_not_run())

    # Same destination, past SAMPLE_INTERVAL_S (so the file IS read again)
    # but well inside DEDUP_WINDOW_S (so nothing new is kept).
    events = s.maybe_sample(now=float(ct.SAMPLE_INTERVAL_S + 1))
    assert events == []


def test_sampler_skips_tcp_scans_for_an_all_udp_sample(tmp_path, monkeypatch):
    """UDP has no per-connection fd table on the path this module uses —
    scanning `/proc` for it would cost real syscalls for an outcome that is
    always `udp_unsupported` regardless of what the scan finds."""
    s = _sampler(tmp_path, monkeypatch, [_line("udp", _HOST_IP, _PUBLIC_DST, 51234, 53)])

    def _must_not_run():
        raise AssertionError("a TCP socket scan ran for an all-UDP sample")

    monkeypatch.setattr(ct, "_build_tcp_socket_index", lambda: _must_not_run())
    monkeypatch.setattr(ct, "_scan_fd_sockets", lambda: _must_not_run())

    events = s.maybe_sample(now=1000.0)

    assert len(events) == 1
    assert events[0].raw["process_status"] == "udp_unsupported"


# ---------------------------------------------------------------------------
# _log_attribution_state: attempted/denied are LOGGED now, not discarded —
# but only on a change of bucket, the same anti-spam shape _log_state_change
# already uses for the conntrack source itself.
# ---------------------------------------------------------------------------
def test_attribution_counts_are_logged_on_the_first_scan(tmp_path, monkeypatch, caplog):
    """Before this fix, `_attempted`/`_denied` were assigned and immediately
    discarded (`_attempted, _denied = ...`) — a real regression (attribution
    suddenly finding 0 candidates to check, say) had nowhere to show up
    short of a full production incident. This proves the counts reach the
    log at all."""
    s = _sampler(tmp_path, monkeypatch, [_line("tcp", _HOST_IP, _PUBLIC_DST, 1, 443)])
    monkeypatch.setattr(ct, "_scan_fd_sockets", lambda: ({}, 42, 41))

    with caplog.at_level("INFO", logger="sentinel.collectors.conntrack"):
        s.maybe_sample(now=1000.0)

    records = [r for r in caplog.records if getattr(r, "attempted", None) == 42]
    assert len(records) == 1
    assert records[0].denied == 41
    assert records[0].bucket == "partially_denied"


def test_attribution_state_is_not_logged_again_when_the_bucket_does_not_change(
        tmp_path, monkeypatch, caplog):
    """The anti-spam half of the same fix: a host in the EXPECTED steady
    state (see the module docstring's 97.5% measurement) must not write a
    fresh log line every single sample forever, even though the exact
    counts drift a little each time. First sample happens BEFORE `caplog`
    starts capturing INFO (default threshold is WARNING), so only the
    second, same-bucket sample's silence is what this actually checks."""
    s = _sampler(tmp_path, monkeypatch, [_line("tcp", _HOST_IP, _PUBLIC_DST, 1, 443)])
    monkeypatch.setattr(ct, "_scan_fd_sockets", lambda: ({}, 100, 100))  # fully_denied
    s.maybe_sample(now=0.0)

    monkeypatch.setattr(ct, "_scan_fd_sockets", lambda: ({}, 97, 97))  # still fully_denied
    second_dst = "8.8.8.8"
    path = tmp_path / "nf_conntrack"
    path.write_text(_line("tcp", _HOST_IP, second_dst, 2, 443) + "\n", encoding="utf-8")
    with caplog.at_level("INFO", logger="sentinel.collectors.conntrack"):
        s.maybe_sample(now=float(ct.SAMPLE_INTERVAL_S + 1))

    assert not any(hasattr(r, "bucket") for r in caplog.records), (
        "same bucket twice in a row must not log a second time")


def test_attribution_state_logs_again_when_the_bucket_actually_changes(
        tmp_path, monkeypatch, caplog):
    """The regression this exists to catch: denied dropping to 0 — either a
    capability change or every match this round happening to be sentinel's
    own process — is a real state change and must be visible, not folded
    into "a few connections got attributed this minute"."""
    s = _sampler(tmp_path, monkeypatch, [_line("tcp", _HOST_IP, _PUBLIC_DST, 1, 443)])
    monkeypatch.setattr(ct, "_scan_fd_sockets", lambda: ({}, 100, 100))
    s.maybe_sample(now=0.0)

    monkeypatch.setattr(ct, "_scan_fd_sockets", lambda: ({}, 100, 0))  # denied -> 0
    second_dst = "8.8.8.8"
    path = tmp_path / "nf_conntrack"
    path.write_text(_line("tcp", _HOST_IP, second_dst, 2, 443) + "\n", encoding="utf-8")
    with caplog.at_level("INFO", logger="sentinel.collectors.conntrack"):
        s.maybe_sample(now=float(ct.SAMPLE_INTERVAL_S + 1))

    matches = [r for r in caplog.records if getattr(r, "bucket", None) == "none_denied"]
    assert len(matches) == 1


# ---------------------------------------------------------------------------
# _conntrack_module_loaded: /proc/modules -> is nf_conntrack a LOADED
# module, distinct from "compiled directly into the kernel" (which this
# cannot see either way) and from "cannot tell at all"
# ---------------------------------------------------------------------------
def test_conntrack_module_loaded_true_when_listed(tmp_path, monkeypatch):
    modules_path = tmp_path / "modules"
    modules_path.write_text(
        "nf_conntrack 172032 3 nf_conntrack_ipv4, Live 0x0000000000000000\n"
        "ip_tables 32768 1 - Live 0x0000000000000000\n",
        encoding="ascii")
    monkeypatch.setattr(ct, "_PROC_MODULES_PATH", str(modules_path))
    assert ct._conntrack_module_loaded() is True


def test_conntrack_module_loaded_false_when_not_listed(tmp_path, monkeypatch):
    modules_path = tmp_path / "modules"
    modules_path.write_text(
        "ip_tables 32768 1 - Live 0x0000000000000000\n", encoding="ascii")
    monkeypatch.setattr(ct, "_PROC_MODULES_PATH", str(modules_path))
    assert ct._conntrack_module_loaded() is False


def test_conntrack_module_loaded_none_when_proc_modules_is_unreadable(tmp_path, monkeypatch):
    monkeypatch.setattr(ct, "_PROC_MODULES_PATH", str(tmp_path / "does_not_exist"))
    assert ct._conntrack_module_loaded() is None


# ---------------------------------------------------------------------------
# The "absent" log message: which of two different problems it names
# ---------------------------------------------------------------------------
def test_absent_message_blames_procfs_not_the_module_when_the_module_is_loaded(
        tmp_path, monkeypatch, caplog):
    """THE misdiagnosis this fixes: a kernel with `nf_conntrack` genuinely
    loaded but `CONFIG_NF_CONNTRACK_PROCFS` compiled out must not be told
    'the module seems unloaded' — that sends an operator to reload a module
    that is already there, for a problem reloading it cannot fix."""
    monkeypatch.setattr(ct, "discover_host_identity", lambda: _identity(ips={_HOST_IP}))
    monkeypatch.setattr(ct, "_conntrack_module_loaded", lambda: True)
    s = ct.ConntrackSampler(str(tmp_path / "does_not_exist_nf_conntrack"))

    with caplog.at_level("WARNING", logger="sentinel.collectors.conntrack"):
        s.maybe_sample(now=1000.0)

    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "CONFIG_NF_CONNTRACK_PROCFS" in messages
    assert "pare neîncărcat" not in messages


def test_absent_message_says_module_when_proc_modules_does_not_list_it(
        tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(ct, "discover_host_identity", lambda: _identity(ips={_HOST_IP}))
    monkeypatch.setattr(ct, "_conntrack_module_loaded", lambda: False)
    s = ct.ConntrackSampler(str(tmp_path / "does_not_exist_nf_conntrack"))

    with caplog.at_level("WARNING", logger="sentinel.collectors.conntrack"):
        s.maybe_sample(now=1000.0)

    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "CONFIG_NF_CONNTRACK_PROCFS" not in messages
    assert "modul separat" in messages


def test_absent_message_admits_it_cannot_tell_when_proc_modules_is_also_unreadable(
        tmp_path, monkeypatch, caplog):
    """The third, honest state: neither 'the module is loaded' nor 'it is
    not' — /proc/modules itself could not be read, which must not be
    silently folded into either claim."""
    monkeypatch.setattr(ct, "discover_host_identity", lambda: _identity(ips={_HOST_IP}))
    monkeypatch.setattr(ct, "_conntrack_module_loaded", lambda: None)
    s = ct.ConntrackSampler(str(tmp_path / "does_not_exist_nf_conntrack"))

    with caplog.at_level("WARNING", logger="sentinel.collectors.conntrack"):
        s.maybe_sample(now=1000.0)

    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "necunoscută" in messages or "nu s-a putut citi" in messages
