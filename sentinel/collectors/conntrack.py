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
`psutil.net_if_addrs()`, which is the kernel's own answer to "what addresses
are bound to my interfaces", no network I/O, no root required.

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

The fix: `HostIdentity` carries the host's own SUBNETS too (built from each
local interface's own address + netmask), not only its addresses. A Docker
bridge (`docker0`, `br-xxxx`) is a real local interface with its own subnet,
so a container's address on it is owned by that subnet the same way the
host's public address is owned by its own. See `HostIdentity`'s docstring for
the ASSUMPTION this rests on, stated there because that is where it can go
wrong.

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

import psutil

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

    `networks` fixes it, built from each local interface's own
    (address, netmask): a Docker bridge is a real local interface with its
    own subnet, so a container's address on it is owned the same way the
    host's public address is owned by its own /32 (or wider) subnet.

    ASSUMPTION, stated here because this is exactly where it can go wrong:
    every subnet in `networks` is reachable ONLY behind this host's own
    NAT/forwarding path (a Docker bridge, a VPN concentrator this host runs
    itself). A host that also ROUTES a foreign network through one of its
    interfaces — without NAT-ing or owning it — would have that foreign
    traffic misread as its own. True for a single VPS running Docker
    containers, the case this was built for and measured against; re-check
    before reusing this on a host that forwards someone else's LAN.

    IPv6 is exact-address-only: the kernel writes UNABBREVIATED IPv6
    addresses into the table, `psutil` returns the ABBREVIATED form, and a
    plain string comparison between "2001:0db8:0000::0001" and "2001:db8::1"
    never matches even for the identical address — not fixed here because
    IPv6 is disabled on the host this was built for (zero entries in the
    table to prove it against); see the module docstring.
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
    globally-routable destination.

    Both halves matter. Without the direction check, an inbound SSH session
    counts as an "outbound connection to :22" the moment conntrack's reply
    tuple is read instead of the original. Without the scope check, every
    Postgres query on 127.0.0.1 counts as a new "destination" and buries the
    handful that are real.
    """
    if not identity.owns(tup.src):
        return False
    try:
        dst = ipaddress.ip_address(tup.dst)
    except ValueError:
        return False
    return bool(dst.is_global)


def discover_host_identity() -> HostIdentity:
    """Every address AND every locally-owned subnet — never hardcoded.

    Reads `psutil.net_if_addrs()` — the kernel's own answer to "what
    addresses (and netmasks) are bound to my interfaces", no network I/O, no
    elevated privilege needed to ask it.

    IPv4 netmasks build `HostIdentity.networks` (this is what makes Docker
    bridge subnets, and therefore container egress, visible — see
    `HostIdentity`'s docstring). IPv6 addresses are still collected into
    `ips` for the exact-address case; their netmasks are not used, since
    `ipaddress` does not accept the netmask STRING form psutil returns for
    IPv6 the way it does for IPv4's dotted-decimal form, and this host has
    nothing in IPv6 to test that conversion against.

    Returns an identity with an empty `ips` on failure. The caller MUST treat
    that as "cannot tell direction" and stay quiet, never as "the host has no
    addresses".
    """
    try:
        ips: set[str] = set()
        networks: list[ipaddress.IPv4Network] = []
        for iface_addrs in psutil.net_if_addrs().values():
            for a in iface_addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    # Strip an IPv6 zone id (fe80::1%eth0) before comparing.
                    ips.add(a.address.split("%", 1)[0])
                if a.family == socket.AF_INET and a.netmask:
                    try:
                        networks.append(ipaddress.ip_network(
                            f"{a.address}/{a.netmask}", strict=False))
                    except ValueError:
                        # An interface psutil cannot describe cleanly (a
                        # malformed netmask, a point-to-point oddity) is
                        # skipped, not guessed at — the exact address from
                        # `ips` above still covers the interface itself.
                        pass
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
