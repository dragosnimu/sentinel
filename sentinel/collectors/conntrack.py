"""Sample outbound network connections — the only collector that looks at what
LEAVES the host instead of what arrives at it.

The other nine detection mechanisms in this codebase watch sshd, nginx,
Suricata, auditd: things trying to get in. A host that is already compromised
does not necessarily generate any of that traffic again — it phones out.
This is what can catch a successful compromise, not just an attempt.

## Source: /proc/net/nf_conntrack, not the `conntrack` binary

The binary is not installed on this host and pulling in a new package for one
collector is a cost the operator did not ask to pay. The kernel already
tracks every connection through netfilter's connection tracker and exposes it
read-only at `/proc/net/nf_conntrack` — that is the "conntrack" source already
listed in `sentinel/model/event.py:SOURCES`.

Reading it needs privilege the ingest daemon may or may not have — the file is
root-owned. Measured directly: as a bare `sentinel` user, "Permission denied";
with `CAP_DAC_READ_SEARCH` ambient — exactly how `sentinel-ingest.service`
already runs, to read `/var/log/audit/audit.log` — it reads. `CAP_NET_ADMIN`
does NOT do this: it does not bypass a DAC permission check on a `0440
root:root` file, only `CAP_DAC_READ_SEARCH` does. This module still never
assumes success: a permission failure is caught, logged distinctly from "the
module isn't loaded", with the CORRECT capability named in the message (see
`ConntrackSampler._log_state_change`), and the collector goes quiet rather
than pretending the host has no outbound traffic.

## The trap this fixes: conntrack keeps BOTH directions

A naive `grep dst=` over the file counts every tuple conntrack stores, and
conntrack stores two per connection — the ORIGINAL tuple (what was actually
dialled) and the REPLY tuple (the same connection, seen from the other side).
Measured on the host this collector was built for: a naive grep found 81
apparent "destinations" in 24h; 57 of them were `:22` pointing at the host's
own address — inbound SSH sessions, counted from their reply tuple. Only 5
were real outbound connections.

The discriminator: **this host is the initiator only if `src=` in the
ORIGINAL tuple is one of this host's own addresses.** `parse_line` keeps only
the first occurrence of each `src=`/`dst=`/`sport=`/`dport=` on the line —
that is the original tuple, since the reply tuple's fields repeat those same
key names later on the same line. `is_outbound` then checks that `src`
against `HostIdentity` below.

## Where "this host's own addresses" comes from — and why it is not just IPs

Never hardcoded — this repository is public. `discover_host_identity` reads
two files under `/proc/net/`, never a socket enumeration API. It USED to call
`psutil.net_if_addrs()`; that shipped, passed three review rounds, and was
**dead in production from the first poll**. `psutil` gets there through
glibc's `getifaddrs()`, which enumerates interfaces over an `AF_NETLINK`
socket — and `sentinel-ingest.service` restricts
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, deliberately, because this
collector needs no socket of any kind to do its job. Under that sandbox
`getifaddrs()` fails with `OSError: [Errno 97] Address family not supported
by protocol`, every single time, forever — a dependency on a library call
masquerading as a dependency on the kernel's own answer, caught only by
reading the unit that runs it, not by any test, because no test in this
repository runs under `RestrictAddressFamilies`. See git history for the
production incident this caused: total, silent, permanently-zero output.

The fix reads `/proc/net/route` and `/proc/net/fib_trie` — plain text files,
open()/read(), no socket of any family, needing nothing the unit does not
already grant. **The unit was not weakened to fix this**: `AF_PACKET`/
`AF_NETLINK` was deliberately not added to `RestrictAddressFamilies`, because
raw-socket access is far more than "enumerate my own interfaces" needs, on
exactly the service that parses the least-trusted input in this system.

A set of exact addresses is not enough. **Docker container egress is
invisible with addresses alone**, and this was measured, not assumed: on the
host this was built for, running nine containers behind seven bridge
networks, one real outbound connection had `src=172.x` in the ORIGINAL
tuple — MASQUERADE rewrites the source on the way OUT, but conntrack's
ORIGINAL tuple is the PRE-NAT one, so what lands in `/proc/net/nf_conntrack`
is the container's bridge address, never the host's. An exact-address check
drops it as "not ours" — exactly the case the module docstring's own honesty
standard exists to catch: a compromised container phoning home is the literal
example this detector is for, and it was the one silently missed.

The fix: `HostIdentity` carries the host's own PRIVATE subnets too, built
from `/proc/net/route`'s locally-attached routes (the `Gateway` column is
all-zero — routed through nobody, dialled directly off this interface). A
Docker bridge (`docker0`, `br-xxxx`) shows up there as its own route with its
own private subnet, so a container's address on it is owned by that subnet
the same way the host's public address is owned by its own.

Widening PUBLIC subnets the same way was tried and measured wrong: the
host's public interface here is a /21, the hosting provider's shared
segment, not the host's own — widening it made every other customer on that
segment "ours" and let an inbound scan from one of them pass the direction
check with the host's own address as the "destination". `networks` therefore
only ever holds routes whose network address is private (`ipaddress`'s own
`is_private`, checked against the route's masked network, not a per-interface
address — a route table has no "interface address" to ask); the host's
public address is still covered exactly by `ips`, and `is_outbound`
separately refuses any destination that is itself owned, as a second line of
defence. See `HostIdentity`'s docstring for the full shape and the ASSUMPTION
the private-only rule still rests on.

## What this catches, and what it cannot

The signal is periodic SAMPLING of a live kernel table, not a log. A
connection that opens and closes between two samples is invisible — this
mechanism catches persistent C2 and slow exfiltration, **not** a single fast
request. An operator who thinks this sees all outbound traffic is worse
defended than one who knows exactly what it misses.

Destinations are also narrowed to globally-routable addresses
(`ipaddress.*.is_global`): Postgres on 127.0.0.1, a docker bridge talking to
another container, a sidecar on an RFC1918 subnet are not "outbound" in the
sense that matters for this detector, and including them would drown the
handful of real egress destinations in intra-host chatter with zero security
value — the same reasoning that keeps `trivy_fs` off the general filesystem
and Suricata's BPF filter off high-volume, no-value flows (see
`ARHITECTURA.md` §3.11).

Container egress reached through anything OTHER than a bridge network that
shows up as a local interface — `--net=host` (already covered: the source is
the host's own address directly), and macvlan/ipvlan, where a container gets
an address on the physical LAN with no local-interface subnet to own it — is
still invisible. Not the case measured on the host this was built for
(standard bridge networking), stated here so it is not assumed away silently
if the setup ever changes.

IPv6 is exact-address-only, not subnet-aware — see `HostIdentity`. Latent on
this host: IPv6 is disabled system-wide and the table has zero v6 entries, so
this is a stated limit, not a fixed bug, until it matters.

## Cadence and volume — the numbers this was sized against

Measured on the host: ingestion runs 46,500-121,000 rows/day, and outbound
traffic normally uses ~5 distinct destinations at once. The ingest daemon
polls every `flush_interval_ms` (1s by default) — sampling conntrack on every
poll would mean reading and parsing the whole table once a second for a
number that changes maybe a few times an hour. `ConntrackSampler` gates on
its own clock instead: `SAMPLE_INTERVAL_S` (60s) between reads, independent
of the ingest loop's own interval.

Sampling once a minute with NO deduplication at all would still only reach
5 destinations x 1,440 samples/day = 7,200 rows/day in the worst NORMAL case —
10-15% on top of the daily floor, tolerable but not free. `DEDUP_WINDOW_S`
(1h) cuts that further: a destination that is still active is re-announced at
most once per window, not once per sample, so a steady connection produces
one row an hour, not sixty. The real day-one volume on a quiet host is a few
hundred rows, not thousands.

That bound only holds for REPEATED destinations. It says nothing about a
sample that contains a large number of destinations NEVER SEEN BEFORE, each
of which is "new" to the dedup cache and would otherwise be emitted in full —
a port scanner run from the host, or a burst of outbound connection attempts
to random addresses, can put thousands of distinct destinations in one
sample. `MAX_NEW_PER_SAMPLE` bounds that case explicitly; see its own comment
for the worst-case math and why hitting it is logged every time, not once.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from sentinel.logging_setup import get_logger
from sentinel.model.event import Event

log = get_logger(__name__)

# Once a minute. See the module docstring for the volume math behind this
# number — it is independent of `ingest.flush_interval_ms`.
SAMPLE_INTERVAL_S = 60

# A destination that stays open re-announces at most once per hour, not once
# per sample. Absolute, not derived from SAMPLE_INTERVAL_S: the two answer
# different questions (how often do we look vs. how often do we say it again).
DEDUP_WINDOW_S = 3600

# How long a destination is remembered after it last emitted, before the
# in-memory cache forgets it. Twice the dedup window: long enough that a
# destination active right at the edge of the window is not re-announced
# early, short enough that the cache does not grow for the life of the daemon
# on a host that talks to many short-lived peers over a long uptime.
_CACHE_TTL_S = DEDUP_WINDOW_S * 2

# Absolute ceiling on how many NEVER-BEFORE-EMITTED destinations one sample
# may turn into rows. Dedup bounds a REPEATED destination; it does nothing
# for a sample that is mostly destinations the cache has never seen — a
# scanner run from the host, or a burst of connection attempts to random
# addresses, can put thousands of distinct destinations in the table in one
# poll, and every one of them is "new" by definition. Measured: 1,000 new
# destinations in a single sample, repeated over 10 samples with a DIFFERENT
# 1,000 each time, produced 10,000 rows with nothing to stop it going higher.
#
# 50 * (86,400s / SAMPLE_INTERVAL_S) = 72,000 rows/day in the worst SUSTAINED
# case — comparable to the measured whole-host daily floor (46,500-121,000).
# That is deliberately a lot: hitting this ceiling means an active event is
# happening right now, and a burst is itself part of the signal (a smaller
# ceiling would throw away exactly the evidence a real incident produces).
# It is a ceiling, not a target — routine operation never gets near it.
MAX_NEW_PER_SAMPLE = 50

# Where the host's own identity is read from. Plain text under /proc/net/ —
# open()/read(), no socket of any family — see the module docstring for why
# this replaced psutil.net_if_addrs() and what broke when it didn't.
_ROUTE_PATH = "/proc/net/route"
_FIB_TRIE_PATH = "/proc/net/fib_trie"

_KV = re.compile(r"\b(?P<key>src|dst|sport|dport)=(?P<val>\S+)")


@dataclass(frozen=True)
class ConnTuple:
    """The ORIGINAL tuple of one conntrack row — who dialled whom."""

    proto: str
    src: str
    dst: str
    sport: int
    dport: int


def parse_line(line: str) -> ConnTuple | None:
    """One line of `/proc/net/nf_conntrack` -> its ORIGINAL tuple, or None.

    None for anything that is not TCP/UDP (ICMP and friends carry no
    sport=/dport=, so they fall out naturally), for a truncated line, and for
    a line whose ports are not integers — a kernel we cannot fully parse must
    not become a fabricated destination.
    """
    tokens = line.split(None, 3)
    if len(tokens) < 3:
        return None
    proto = tokens[2].strip().lower()
    if proto not in ("tcp", "udp"):
        return None

    # Only the FIRST occurrence of each key: that is the ORIGINAL tuple. The
    # REPLY tuple repeats the same four key names later on the same line, and
    # reading those instead is exactly the 81-vs-5 bug described above.
    found: dict[str, str] = {}
    for m in _KV.finditer(line):
        key = m["key"]
        if key not in found:
            found[key] = m["val"]
        if len(found) == 4:
            break
    if len(found) < 4:
        return None
    try:
        return ConnTuple(
            proto=proto, src=found["src"], dst=found["dst"],
            sport=int(found["sport"]), dport=int(found["dport"]),
        )
    except ValueError:
        return None


@dataclass(frozen=True)
class HostIdentity:
    """Every address, AND every subnet, this host can claim as its own.

    An exact-address set alone misses container egress. Docker (and any NAT
    the host does) rewrites the source to the host's own address only on the
    way OUT through MASQUERADE; conntrack's ORIGINAL tuple is the PRE-NAT
    one, so what actually lands in the table is the CONTAINER's bridge
    address (172.x), never the host's. Measured on the host this was built
    for, running nine containers behind seven bridges: a container's real
    outbound connection had exactly this shape, and an exact-address check
    silently dropped it — the single example the module docstring uses for
    what this detector is FOR.

    `networks` fixes it, built from `/proc/net/route`'s locally-attached
    routes (the `Gateway` column all-zero — dialled directly off an
    interface, not through anyone else) — but ONLY when the route's own
    network address is PRIVATE. A Docker bridge shows up as its own
    locally-attached route with a private network, so a container's address
    on it is owned the same way. The host's PUBLIC route is deliberately NOT
    widened this way: it is covered by its own exact address in `ips`, never
    by its subnet.

    That distinction is not cosmetic — it is the second bug this class
    fixes. The public route's subnet is usually the hosting provider's
    shared segment, not the host's own: measured directly, `eth0` here is a
    /21, so widening it the same way as a Docker bridge would have made
    every one of roughly 2,000 OTHER CUSTOMERS' addresses "ours". An inbound
    scan from a neighbour on that segment (`src=neighbour`,
    `dst=this host's own public IP`) would then pass the direction check —
    the exact 81-vs-5 bug from the top of the module, reborn on a subnet
    nobody meant to include. `owns()` below also refuses any destination
    that is itself ours, as a second, independent line of defence: a real
    outbound connection can never dial the host's own address, whichever
    check let the source through.

    ASSUMPTION, stated here because this is exactly where it can go wrong:
    every PRIVATE subnet in `networks` is reachable ONLY behind this host's
    own NAT/forwarding path (a Docker bridge, a VPN concentrator this host
    runs itself). A host that also ROUTES a foreign PRIVATE network through
    one of its interfaces — without NAT-ing or owning it — would have that
    foreign traffic misread as its own. True for a single VPS running
    Docker containers, the case this was built for and measured against;
    re-check before reusing this on a host that forwards someone else's LAN.

    IPv6 is not collected at all: `/proc/net/fib_trie` is the IPv4 FIB, and
    IPv4 is what `/proc/net/nf_conntrack` needs to be checked against — the
    kernel writes UNABBREVIATED IPv6 addresses into the conntrack table, and
    matching those correctly is a separate problem this module has never
    solved (the previous `psutil`-based version had the same gap, documented
    the same way). IPv6 is disabled on the host this was built for — zero
    entries in the conntrack table to test either implementation against —
    so this is a stated limit, not a fixed bug, until it matters; see the
    module docstring.
    """

    ips: frozenset[str]
    networks: tuple[ipaddress.IPv4Network, ...] = ()

    def owns(self, ip_str: str) -> bool:
        if ip_str in self.ips:
            return True
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)

    def __bool__(self) -> bool:
        return bool(self.ips)


def is_outbound(tup: ConnTuple, identity: HostIdentity) -> bool:
    """True only when THIS host (or something it NATs for) dialled a
    globally-routable destination that is NOT itself.

    Three checks, each closing a different way this has actually been wrong:
    without the direction check, an inbound SSH session counts as an
    "outbound connection to :22" the moment conntrack's reply tuple is read
    instead of the original; without the scope check, every Postgres query
    on 127.0.0.1 counts as a new "destination"; without the destination
    check, a spoofed or genuinely inbound packet whose source happens to
    fall inside a subnet `HostIdentity` owns reports the host's OWN address
    as a newly-contacted destination — see `HostIdentity`'s docstring for
    the /21-neighbour measurement that produced exactly this shape.
    """
    if not identity.owns(tup.src):
        return False
    try:
        dst = ipaddress.ip_address(tup.dst)
    except ValueError:
        return False
    if identity.owns(tup.dst):
        # A real outbound connection never dials the host's own address.
        # Independent of whatever let `src` pass above — a subnet-ownership
        # mistake anywhere upstream should not also need this check to be
        # the only thing standing between it and a false "new destination".
        return False
    return bool(dst.is_global)


def _hex_to_ipv4(field: str) -> str:
    """One 8-hex-char column of `/proc/net/route` -> dotted-decimal.

    The kernel prints the 32-bit address as `%08X` of its raw in-memory
    layout, which on this (little-endian) architecture puts the FIRST byte
    of the address LAST in the hex string — verified against a real route
    table: `000011AC` is `172.17.0.0`, Docker's default bridge network,
    spelled backwards a byte at a time, and `006433C6` is `198.51.100.0`.
    Reversing the 4 raw bytes before handing them to `inet_ntoa` is what
    makes both read correctly; treating the hex string as a plain big-endian integer
    (the very first parse attempt, and the one that silently returned zero
    subnets) does not.
    """
    raw = bytes.fromhex(field)
    if len(raw) != 4:
        raise ValueError(f"not a 4-byte IPv4 route field: {field!r}")
    return socket.inet_ntoa(raw[::-1])


def _local_subnets_from_route(text: str) -> list[ipaddress.IPv4Network]:
    """`/proc/net/route` -> every PRIVATE subnet this host is directly
    attached to.

    Columns are `Iface Destination Gateway Flags RefCnt Use Metric Mask MTU
    Window IRTT`, tab/space-separated, one header line first. `Gateway`
    all-zero (`00000000`) is the discriminator for "reached directly off
    this interface" — a routed line (a default route via the provider's
    gateway, say) has a real gateway address there instead and is not a
    subnet this host owns.

    Only kept if the route's own network address is private
    (`ipaddress.IPv4Network.is_private`) — the same reasoning `HostIdentity`
    documents: a Docker bridge's route (`172.x/16`) is private and kept, the
    host's public /21 is not and is left to `ips`' exact-address coverage
    alone. A malformed line (too few columns, a hex field that will not
    parse) is skipped, not guessed at.
    """
    networks: list[ipaddress.IPv4Network] = []
    lines = text.splitlines()
    for line in lines[1:]:  # first line is the column header, not a route
        cols = line.split()
        if len(cols) < 8:
            continue
        gw_hex, flags_hex, mask_hex = cols[2], cols[3], cols[7]
        if gw_hex != "00000000":
            continue  # reached through a gateway, not attached to us directly
        try:
            if not int(flags_hex, 16) & 0x1:  # RTF_UP
                continue
            net = ipaddress.ip_network(
                f"{_hex_to_ipv4(cols[1])}/{_hex_to_ipv4(mask_hex)}", strict=False)
        except ValueError:
            continue
        if not net.network_address.is_private:
            continue
        networks.append(net)
    return networks


_FIB_TRIE_ADDR = re.compile(r"^\s*[|+]--\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$")


def _host_addresses_from_fib_trie(text: str) -> set[str]:
    """`/proc/net/fib_trie` -> every IPv4 address configured on this host.

    The trie prints each leaf address on its own line, followed by one or
    more route-type lines for that address; `/32 host LOCAL` is the kernel's
    own label for "this exact address is mine", the same fact `ips` needs.
    Real shape (addresses elided; see this module's own tests for a
    synthetic fixture matching it exactly):

        +-- <network>/21 2 0 1
           |-- <host-address>
              /32 host LOCAL

    Only the line immediately following an address is checked — the
    `/32 host LOCAL` leaf is always the first route line for a LOCAL address
    in every kernel version this was checked against. An address whose next
    line is anything else (a route, not a local address) is not collected.
    """
    ips: set[str] = set()
    lines = text.splitlines()
    for i in range(len(lines) - 1):
        m = _FIB_TRIE_ADDR.match(lines[i])
        if m and lines[i + 1].strip().startswith("/32 host LOCAL"):
            ips.add(m.group(1))
    return ips


def discover_host_identity() -> HostIdentity:
    """Every address AND every locally-owned subnet — never hardcoded.

    Reads two files under `/proc/net/`: `route` for locally-attached
    subnets, `fib_trie` for exact addresses. Both are plain text, no socket
    of any family, nothing `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
    on `sentinel-ingest.service` disallows — unlike the `psutil` version this
    replaced, which called glibc's `getifaddrs()` under the hood, needed an
    `AF_NETLINK` socket to do it, and failed with `OSError: [Errno 97]
    Address family not supported by protocol` on every single poll in
    production. See the module docstring for the full incident.

    Both files are world-readable on a standard kernel (unlike
    `/proc/net/nf_conntrack`, which needs `CAP_DAC_READ_SEARCH`) — this
    function does not distinguish "absent" from "denied" the way `_read`
    does for conntrack itself, because either failure means the same thing
    here: identity cannot be established this round, try again next sample.

    Returns an identity with an empty `ips` on failure. The caller MUST treat
    that as "cannot tell direction" and stay quiet, never as "the host has no
    addresses".
    """
    try:
        with open(_ROUTE_PATH, "r", encoding="ascii", errors="strict") as fh:
            route_text = fh.read()
        with open(_FIB_TRIE_PATH, "r", encoding="ascii", errors="strict") as fh:
            fib_text = fh.read()
        networks = _local_subnets_from_route(route_text)
        ips = _host_addresses_from_fib_trie(fib_text)
        return HostIdentity(frozenset(ips), tuple(networks))
    except Exception as exc:  # noqa: BLE001 - discovery failing degrades, never crashes ingest
        log.error(
            "nu s-au putut afla adresele/subrețelele gazdei; eșantionarea "
            "traficului de ieșire rămâne oprită până la o nouă încercare",
            extra={"detail": str(exc)})
        return HostIdentity(frozenset(), ())


@dataclass(frozen=True)
class _SampleOutcome:
    status: str                      # "ok" | "absent" | "denied" | "error"
    lines: tuple[str, ...] = ()
    detail: str = ""


def _read(path: str) -> _SampleOutcome:
    """Read the conntrack table, distinguishing WHY it failed.

    "The module isn't loaded" and "the process lacks permission" are
    different facts that call for different operator action — collapsing
    them into one "unavailable" would hide which one it is. Neither is ever
    reported as "0 destinations", which would read as a clean host.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return _SampleOutcome("ok", tuple(fh))
    except FileNotFoundError:
        return _SampleOutcome("absent")
    except PermissionError as exc:
        return _SampleOutcome("denied", detail=str(exc))
    except OSError as exc:  # noqa: BLE001 - any other read failure degrades the same way
        return _SampleOutcome("error", detail=str(exc))


class ConntrackSampler:
    """Periodic, deduplicated, volume-bounded snapshot of who this host (and
    what it NATs for) dialled out to.

    Owns its own clock — `time.monotonic()`, never wall clock, so an NTP
    correction cannot make it sample twice in the same second or go silent
    for an hour (the same reasoning `ARHITECTURA.md` §3.13 applies to the
    aggregator watermark). `maybe_sample` is the only entry point: it is a
    plain no-op, no file I/O at all, until its own interval has elapsed, so
    calling it from an ingest loop that polls once a second costs nothing on
    59 out of every 60 calls.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._identity = discover_host_identity()
        self._last_sample_at: float | None = None
        self._last_emitted: dict[tuple[str, str, int], float] = {}
        self._last_status: str | None = None
        if not self._identity:
            log.error(
                "adresele IP ale gazdei nu s-au putut afla la pornirea "
                "colectorului conntrack; se reîncearcă la fiecare eșantion")

    def maybe_sample(self, now: float | None = None) -> list[Event]:
        """New `connect` events since the last sample, or `[]` if not due yet
        or if the source could not be read this time."""
        now = time.monotonic() if now is None else now
        if (self._last_sample_at is not None
                and now - self._last_sample_at < SAMPLE_INTERVAL_S):
            return []
        self._last_sample_at = now

        if not self._identity:
            # An interface can come up after the daemon started (DHCP, a NIC
            # hot-added). Cheap to retry — this whole branch runs once a
            # minute at most.
            self._identity = discover_host_identity()
            if not self._identity:
                return []

        outcome = _read(self._path)
        self._log_state_change(outcome)
        if outcome.status != "ok":
            return []

        events = self._events_from(outcome.lines, now)
        self._prune_cache(now)
        return events

    def _events_from(self, lines: tuple[str, ...], now: float) -> list[Event]:
        seen_this_sample: set[tuple[str, str, int]] = set()
        # Destinations this sample would newly report, in encounter order —
        # separated from `events` so the cap below can log BOTH how many were
        # seen and how many were actually kept, and never truncate silently.
        new_candidates: list[ConnTuple] = []
        for line in lines:
            tup = parse_line(line)
            if tup is None or not is_outbound(tup, self._identity):
                continue
            key = (tup.proto, tup.dst, tup.dport)
            if key in seen_this_sample:
                continue  # several parallel flows to the same dest, one sample
            seen_this_sample.add(key)
            last = self._last_emitted.get(key)
            if last is not None and now - last < DEDUP_WINDOW_S:
                continue  # already reported this destination recently
            new_candidates.append(tup)

        kept = new_candidates
        if len(new_candidates) > MAX_NEW_PER_SAMPLE:
            # Logged every time, not once: unlike "the file is unreadable"
            # (a persistent state), "how many new destinations this minute"
            # is itself the information, and it changes every time this
            # fires. Silence here is exactly the failure this repository has
            # shipped before: a count reading as "clean" when it meant
            # "truncated".
            log.warning(
                "prea multe destinații noi într-un singur eșantion; "
                "trunchiat, nu ignorat — vezi 'seen' vs. 'kept'",
                extra={"seen": len(new_candidates), "kept": MAX_NEW_PER_SAMPLE})
            kept = new_candidates[:MAX_NEW_PER_SAMPLE]

        ts = datetime.now(timezone.utc)
        events: list[Event] = []
        for tup in kept:
            key = (tup.proto, tup.dst, tup.dport)
            self._last_emitted[key] = now
            events.append(Event(
                ts=ts, source="conntrack", action="connect",
                src_ip=tup.src, src_port=tup.sport,
                dst_ip=tup.dst, dst_port=tup.dport, proto=tup.proto,
                raw={"sampled": True},
            ))
        return events

    def _prune_cache(self, now: float) -> None:
        cutoff = now - _CACHE_TTL_S
        self._last_emitted = {k: v for k, v in self._last_emitted.items() if v >= cutoff}

    def _log_state_change(self, outcome: _SampleOutcome) -> None:
        """Log only on a CHANGE of status — loud enough to be seen once,
        quiet enough not to write the same line to the journal every minute
        forever while a known-broken host stays broken."""
        if outcome.status == self._last_status:
            return
        self._last_status = outcome.status
        if outcome.status == "absent":
            log.warning(
                "nf_conntrack indisponibil (modulul de kernel pare neîncărcat); "
                "eșantionarea traficului de ieșire e oprită",
                extra={"path": self._path})
        elif outcome.status == "denied":
            log.error(
                "nf_conntrack ilizibil (permisiune refuzată); sentinel-ingest "
                "are nevoie de CAP_DAC_READ_SEARCH (deja acordat în unitatea "
                "systemd — dacă acest mesaj apare oricum, procesul nu rulează "
                "cu capabilitatea aceea, de exemplu pornit manual, în afara "
                "systemd)",
                extra={"path": self._path, "detail": outcome.detail})
        elif outcome.status == "error":
            log.error("citirea nf_conntrack a eșuat",
                      extra={"path": self._path, "detail": outcome.detail})
        elif outcome.status == "ok":
            log.info("nf_conntrack citibil; eșantionarea traficului de ieșire a pornit",
                     extra={"path": self._path})
