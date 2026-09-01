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
root-owned. `sentinel-ingest.service` already carries `CAP_DAC_READ_SEARCH` to
read `/var/log/audit/audit.log`, and that capability is specifically "bypass
file read permission checks", so it should also cover this root:root 0440
file. That is a claim about a specific kernel/systemd combination on the
production host, not something provable from a laptop, so this module never
assumes it: a permission failure is caught, logged distinctly from "the
module isn't loaded", and the collector goes quiet rather than pretending the
host has no outbound traffic. See `ConntrackSampler._log_state_change`.

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
against the host's own addresses.

## Where the host's own addresses come from

Never hardcoded — this repository is public. `discover_host_ips` reads
`psutil.net_if_addrs()`, which is the kernel's own answer to "what addresses
are bound to my interfaces", no network I/O, no root required. If discovery
returns nothing (a namespace with no interfaces configured yet, a `psutil`
failure), the sampler cannot tell inbound from outbound and refuses to guess
— it logs the failure once and stays quiet on that poll rather than treating
"unknown" as "safe to report".

## What this catches, and what it cannot

The signal is periodic SAMPLING of a live kernel table, not a log. A
connection that opens and closes between two samples is invisible — this
mechanism catches persistent C2 and slow exfiltration, **not** a single fast
request. An operator who thinks this sees all outbound traffic is worse
defended than one who knows exactly what it misses.

Destinations are also narrowed to globally-routable addresses
(`ipaddress.*.is_global`): Postgres on 127.0.0.1, a docker bridge, a sidecar
on an RFC1918 subnet are not "outbound" in the sense that matters for this
detector, and including them would drown the handful of real egress
destinations in intra-host chatter with zero security value — the same
reasoning that keeps `trivy_fs` off the general filesystem and Suricata's BPF
filter off high-volume, no-value flows (see `ARHITECTURA.md` §3.11).

## Cadence and volume — the numbers this was sized against

Measured on the host: ingestion runs 47,000–72,000 rows/day, and outbound
traffic normally uses ~5 distinct destinations at once. The ingest daemon
polls every `flush_interval_ms` (1s by default) — sampling conntrack on every
poll would mean reading and parsing the whole table once a second for a
number that changes maybe a few times an hour. `ConntrackSampler` gates on
its own clock instead: `SAMPLE_INTERVAL_S` (60s) between reads, independent
of the ingest loop's own interval.

Sampling once a minute with NO deduplication at all would still only reach
5 destinations x 1,440 samples/day = 7,200 rows/day in the worst case — 10-15%
on top of the daily floor, tolerable but not free. `DEDUP_WINDOW_S` (1h) cuts
that further: a destination that is still active is re-announced at most once
per window, not once per sample, so a steady connection produces one row an
hour, not sixty. The real day-one volume on a quiet host is a few hundred
rows, not thousands.
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


def is_outbound(tup: ConnTuple, host_ips: frozenset[str]) -> bool:
    """True only when THIS host dialled a globally-routable destination.

    Both halves matter. Without the direction check, an inbound SSH session
    counts as an "outbound connection to :22" the moment conntrack's reply
    tuple is read instead of the original. Without the scope check, every
    Postgres query on 127.0.0.1 counts as a new "destination" and buries the
    handful that are real.
    """
    if tup.src not in host_ips:
        return False
    try:
        dst = ipaddress.ip_address(tup.dst)
    except ValueError:
        return False
    return bool(dst.is_global)


def discover_host_ips() -> frozenset[str]:
    """Every address bound to a local interface (loopback included).

    Never hardcoded: the repository is public, and the host's own addresses
    are not something this code is allowed to assume. Reads
    `psutil.net_if_addrs()` — the kernel's own answer, no network traffic, no
    elevated privilege needed to ask it.

    Returns an empty set on failure. The caller MUST treat that as "cannot
    tell direction" and stay quiet, never as "the host has no addresses".
    """
    try:
        addrs: set[str] = set()
        for iface_addrs in psutil.net_if_addrs().values():
            for a in iface_addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    # Strip an IPv6 zone id (fe80::1%eth0) before comparing.
                    addrs.add(a.address.split("%", 1)[0])
        return frozenset(addrs)
    except Exception as exc:  # noqa: BLE001 - discovery failing degrades, never crashes ingest
        log.error(
            "nu s-au putut afla adresele IP ale gazdei; eșantionarea "
            "traficului de ieșire rămâne oprită până la o nouă încercare",
            extra={"detail": str(exc)})
        return frozenset()


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
    """Periodic, deduplicated snapshot of who this host dialled out to.

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
        self._host_ips = discover_host_ips()
        self._last_sample_at: float | None = None
        self._last_emitted: dict[tuple[str, str, int], float] = {}
        self._last_status: str | None = None
        if not self._host_ips:
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

        if not self._host_ips:
            # An interface can come up after the daemon started (DHCP, a NIC
            # hot-added). Cheap to retry — this whole branch runs once a
            # minute at most.
            self._host_ips = discover_host_ips()
            if not self._host_ips:
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
        events: list[Event] = []
        ts = datetime.now(timezone.utc)
        for line in lines:
            tup = parse_line(line)
            if tup is None or not is_outbound(tup, self._host_ips):
                continue
            key = (tup.proto, tup.dst, tup.dport)
            if key in seen_this_sample:
                continue  # several parallel flows to the same dest, one sample
            seen_this_sample.add(key)
            last = self._last_emitted.get(key)
            if last is not None and now - last < DEDUP_WINDOW_S:
                continue  # already reported this destination recently
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
                "are nevoie de CAP_NET_ADMIN sau de root pentru sursa asta",
                extra={"path": self._path, "detail": outcome.detail})
        elif outcome.status == "error":
            log.error("citirea nf_conntrack a eșuat",
                      extra={"path": self._path, "detail": outcome.detail})
        elif outcome.status == "ok":
            log.info("nf_conntrack citibil; eșantionarea traficului de ieșire a pornit",
                     extra={"path": self._path})
