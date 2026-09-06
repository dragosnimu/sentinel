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

## What opened it — and the wall this hits almost immediately

Before this section existed, `process` and `pid` were NULL on every row this
collector ever wrote — not because nobody asked, but because nobody tried.
An operator looking at "new destination: 203.0.113.9" had no way to tell
"a cron job I wrote" from "something that got in", and the `novelty.
outbound_dst` alert text (`detect/novelty.py`) says exactly that: confirm it
yourself if you recognise it, otherwise find out who did this — advice that
is impossible to follow from a bare IP.

The path available without a new dependency or a wider capability grant:
`/proc/net/tcp` and `/proc/net/tcp6` map a live TCP 4-tuple to a socket
inode AND to the uid that owns it (world-readable, `-r--r--r-- root:root` —
no capability needed, see `_build_tcp_socket_index`); `/proc/<pid>/fd/*`
symlinks named `socket:[<inode>]` map that inode to a owning pid (see
`_scan_fd_sockets`); `/proc/<pid>/comm` and `/proc/<pid>/exe` name the
process once the pid is known. All of it plain file reads — nothing this
collector's unit does not already have.

**Measured on the production host, under the EXACT capability set
`sentinel-ingest.service` is granted (`CAP_DAC_READ_SEARCH`, no
`CAP_SYS_PTRACE`), not a bare shell:** `os.listdir("/proc/<pid>/fd")` on a
process owned by a DIFFERENT user succeeds — `CAP_DAC_READ_SEARCH` bypasses
the directory permission bits, confirmed with `setpriv
--ambient-caps=+dac_read_search` reproducing the unit's own grant exactly.
But `os.readlink("/proc/<pid>/fd/<n>")` on that same directory's entries —
the one call that turns an fd NUMBER into the inode it points at — fails
with `PermissionError` regardless: naming a socket's target is gated by
`ptrace_may_access`, a check `CAP_DAC_READ_SEARCH` was never meant to
satisfy and does not. Measured at scale on the same host: of 3,030 fd
entries across 216 processes, 2,953 (97.5%) were denied this way; every one
of the 77 that succeeded belonged to a process running as the SAME user as
the collector.

**The consequence, stated plainly so it is not discovered by someone
reading a "found" rate near zero and assuming the code is broken:**
attribution below can only ever succeed for a connection opened by a
process running as `sentinel` itself — the AI worker calling the Anthropic
API, the Telegram bot's long poll, the shipper posting to the external
aggregator. A connection opened by nginx, php-fpm, a cron job, a container,
or an attacker's process running as literally any other user — root
included — is invisible to this mechanism by kernel design, not by a gap in
this code. Verified positively, not just by absence: on the production
host, an established connection genuinely opened by `sentinel`'s own
Telegram bot process resolved correctly to that process's pid, comm and
exe through this exact path; two other live connections on unrelated
ports, opened by another user's process, resolved to nothing, as the math
above predicts.

Full pid-level attribution (a compromised web app or container actually
phoning home — the case this whole collector exists for) still needs one of
two things this file does not decide on its own: granting `CAP_SYS_PTRACE`
to `sentinel-ingest.service` (this process parses the least-trusted input
in the system — see `ARHITECTURA.md` §5 — and that capability would let a
compromised instance of it read the memory-mapped fds of any process on the
host), or a narrowly-scoped read-only lookup added to `sentinel-executor`
(the one root component, and adding to it is exactly the kind of scope
`ARHITECTURA.md` §3.4 says to watch). Both are real trade-offs an operator
should pick, not a default this module reaches for quietly.

Two paths are open WITHOUT either of those, neither implemented here — left
as a decision, not a gap silently closed:

* The `uid` column of `/proc/net/tcp` (`cols[7]`) is parsed and kept for
  every row with a matching inode, `"not_attributable"` included — the
  kernel hands it out with the exact same permission as the rest of the
  table, no `CAP_SYS_PTRACE` needed. `_uid_to_name` resolves it to a
  username where the local passwd database has an entry; an unmapped uid
  (a container's own UID namespace, most often) stays a bare number, not a
  guess.
* `/proc/<pid>/net/tcp` is scoped to THAT pid's network namespace, and is
  as world-readable as the host's own `/proc/net/tcp` — measured directly:
  reading it for a representative pid of each of several docker network
  namespaces succeeded under the unit's own capability set with zero
  denials, and a live container connection checked against it matched.
  That would name the CONTAINER a connection came from, not a pid — the
  question an operator triaging container egress actually asks — but
  deciding which pids to check per namespace, and turning a matched netns
  back into a container id via `/proc/<pid>/cgroup`, is a second piece of
  work this change does not take on.

Container egress is a SECOND, independent ceiling on top of the ptrace one
above: a container's socket lives in its own network namespace, with its
own `/proc/net/tcp`. The HOST's own `/proc/net/tcp` — the only one
`_build_tcp_socket_index` reads today — structurally never lists it,
whatever the capability set; the exact motivating case from §3.18 of
`ARHITECTURA.md` (a container's egress, visible here only through its
pre-NAT bridge address) is invisible to THIS lookup for that reason. That is
narrower than "unattributable regardless of privilege" — this paragraph's
previous wording, corrected after measurement showed a container-scoped
`/proc/<pid>/net/tcp` read succeeds cleanly (see above): it is a namespace
question this module does not currently answer, not a wall no amount of
code could ever cross. `HostIdentity.ips` (exact host addresses) versus
`HostIdentity.networks` (bridge/private subnets) is what tells the two
cases apart BEFORE any lookup runs — `attribute_process` uses exactly that
to assign `"container_egress"` instead of misreading an inevitable miss in
the host's own table as "the connection closed".

None of this makes the attempt worthless. What it cannot attribute, it
records as exactly that — an explicit `process_status` in `raw`, never a
silently-NULL `process` column that looks identical to "nobody asked":
`"found"` (a name was read), `"closed_before_scan"` (a HOST-owned
connection was gone from `/proc/net/tcp{,6}` by the time this sampler
looked — the already-documented short-lived-connection gap, now visible
per-row instead of only in this docstring), `"not_attributable"` (the
socket was still open, but this process could not read whose it was — the
97.5% case above; `uid`/`user` may still be populated here, since the
kernel hands those out on the same terms as the rest of the row),
`"container_egress"` (the source is owned only via `HostIdentity.networks`,
never `.ips` — a container's or other NAT'd bridge's address, which the
HOST's own `/proc/net/tcp` cannot show by namespace design, decided BEFORE
the lookup runs instead of discovered afterwards as a false "closed"),
`"host_tcp_unreadable"` (`/proc/net/tcp` itself could not be read this
round — a real regression, since that file needs no capability beyond what
this unit already has, and must never collapse into "closed": the two mean
different things to an operator), `"udp_unsupported"` (conntrack tracks
UDP; `/proc/net/udp` was not in the path this was asked to use, so a UDP
row is never even attempted). Absence of the `process_status` key entirely
— any row written before this section existed — means the collector never
tried at all, a state distinct from all of the above.

## Destination hostnames: reachable, not built here

A CDN address rotates, so raising "never seen before" forever on the IP
alone is a standing false-positive generator the operator explicitly asked
about. Investigated, not assumed: Suricata already writes `dns` records to
`eve.json` on this host — `event_type=dns`, `dns.type=answer` entries carry
`rrname` and each answer's `rdata`, measured directly against the live file
(real `rrname` -> `rdata` pairs observed, at roughly 4% of eve.json's line
volume, alongside `flow`/`stats`/`tls` that `collectors/suricata_eve.py`
already drops before the database for the same volume reason — see that
module's docstring). No packet capture beyond what already runs would be
needed.

Building the correlation is a second collector's work, not this file's: it
needs `suricata_eve.py` to stop discarding `dns` records (a decision with
its own volume cost, on a module that discards non-alert records
specifically to protect partitions), a place to hold recent answers long
enough to be useful (a persisted table, so it survives an ingest restart
and both collectors can read it; or an in-process cache, cheaper but gone
every restart and shared awkwardly between two collectors that do not
otherwise know about each other), and a decision about which of those two
shapes is worth the cost. That is a second collector's design, not a
one-file fix riding along in this one — left explicitly undone, not
silently dropped.

## Severity: revisited with a measurement, not a hunch

`predict/behaviour.py`'s `outbound_dst` dimension used the shared defaults
(`severity="high"`, `warmup_days=3`) sized for dimensions with a handful of
stable values (which admin logs in). Measured on the production host across
its first six days: daily NEW destinations (not total — total stayed
~650-920/day throughout) ran 671, 355, 59, 19, 7, 4 — still nonzero on day
six, the last day measured, the same day the dimension had already been
"warm" for two days and HAD ALREADY raised 16 HIGH incidents. A destination
space that has not finished decaying by the day it starts alerting at HIGH
is not the same shape as `login_user`. `severity` is now `medium` and
`warmup_days` is 14 (the same constant `RATE_LOOKBACK_HOURS` already treats
as "enough history to mean something" for this rule family, in
`detect/novelty.py`) — not a number picked to make the graph prettier, but
not proven correct past day six either, since six days is all that was
measured; see `predict/behaviour.py` for the same note kept where the
constant lives.

**Stated plainly, because it is easy to believe the opposite from the diff
alone: `warmup_days=14` is a NO-OP on the host that motivated it.**
`outbound_dst.warm_at` was already set on that host — two days after
`started_at`, under the previous `warmup_days=3` — and `_promote_warm` in
`predict/behaviour.py` skips any row where `warm_at IS NOT NULL`, by its own
documented invariant: a dimension that has gone warm may never go cold
again. Raising the threshold in code does not touch an already-warm row;
only `severity` (read live from `DIMENSIONS` at alert time, never cached)
takes effect immediately, and only for alerts from this point forward — the
16 HIGH incidents already open do not become MEDIUM retroactively.
Resetting `warm_at` for `outbound_dst` on that host would make
`warmup_days=14` matter there too, but doing that quietly, from this
module, would be exactly the kind of unilateral fix `ARHITECTURA.md` warns
against for a written invariant: it is the operator's call, not made here.
"""

from __future__ import annotations

import ipaddress
import os
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

# Where a live TCP socket's local/remote 4-tuple maps to its inode — see the
# module docstring's "What opened it" section for what this can and cannot
# attribute, measured, before anyone reads a near-zero "found" rate and
# assumes the code is broken rather than the kernel's own ptrace check.
_PROC_NET_TCP_PATH = "/proc/net/tcp"
_PROC_NET_TCP6_PATH = "/proc/net/tcp6"
_PROC_ROOT = "/proc"

# Where a LOADED kernel module (as opposed to one built directly into the
# kernel) shows up — used only to tell apart the two different reasons
# `/proc/net/nf_conntrack` can be absent, see `_conntrack_module_loaded`.
_PROC_MODULES_PATH = "/proc/modules"

_KV = re.compile(r"\b(?P<key>src|dst|sport|dport)=(?P<val>\S+)")
_FD_SOCKET_RE = re.compile(r"^socket:\[(\d+)\]$")


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


# ---------------------------------------------------------------------------
# Process attribution — see the module docstring's "What opened it" section
# for the measured ceiling this runs into and why it is a kernel property,
# not a bug here.
# ---------------------------------------------------------------------------
def _hex_to_ipv6(field: str) -> str:
    """One 32-hex-char address field of `/proc/net/tcp6` -> its text form.

    The kernel prints an IPv6 address as four 32-bit words, each in the
    machine's native byte order — the same convention `_hex_to_ipv4` decodes
    for a single 32-bit field, applied per word here. Decode format confirmed
    against a literal kernel-formatted `/proc/net/tcp6` field for loopback
    (the four 32-bit words `00000000 00000000 00000000 01000000` -> `::1`,
    see this module's own tests — written here with a space between words
    for readability; `bytes.fromhex` treats that identically to the
    unbroken string the kernel actually prints) — no longer "written from
    the documented format and never checked". Still UNPROVEN end-to-end on
    the production host this collector actually runs on: IPv6 is disabled
    there (zero entries in either conntrack or this table — see the module
    and `HostIdentity` docstrings), so the decoder itself is right, but
    nothing here has ever matched a real v6 tuple against a real v6 socket
    on THIS host. Kept as
    its own function, not folded into `_hex_to_ipv4`, so that remaining gap
    stays visible at the call site instead of borrowing v4's fully
    end-to-end-tested confidence.
    """
    raw = bytes.fromhex(field)
    if len(raw) != 16:
        raise ValueError(f"not a 16-byte IPv6 address field: {field!r}")
    words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    return str(ipaddress.IPv6Address(words))


def _parse_proc_net_tcp(text: str, *, v6: bool) -> dict[tuple[str, int, str, int], tuple[str, str]]:
    """One `/proc/net/tcp` or `/proc/net/tcp6` table -> {(local_ip,
    local_port, remote_ip, remote_port): (inode, uid)}.

    Columns are `sl local_address rem_address st tx_queue:rx_queue tr:tm->when
    retrnsmt uid timeout inode`, whitespace-separated, one header line first.
    `uid` (`cols[7]`) is kept alongside the inode — the kernel hands it out
    on the same terms as everything else in the row, no capability beyond
    what reads the table at all, and it is the one thing that can still name
    an owner on a `"not_attributable"` row (see `_uid_to_name`,
    `attribute_process`). A row whose inode is `"0"` (TIME_WAIT and similar
    transient states report no owning fd) is skipped — matching against it
    could never resolve to a process, so keeping it would only plant false
    confidence that a lookup MIGHT still succeed. A line this cannot parse
    is skipped, not guessed at, the same standard `parse_line` holds itself
    to for conntrack's own lines.
    """
    to_ip = _hex_to_ipv6 if v6 else _hex_to_ipv4
    index: dict[tuple[str, int, str, int], tuple[str, str]] = {}
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 10:
            continue
        inode = cols[9]
        if inode == "0":
            continue
        uid = cols[7]
        try:
            l_ip_hex, l_port_hex = cols[1].split(":")
            r_ip_hex, r_port_hex = cols[2].split(":")
            key = (to_ip(l_ip_hex), int(l_port_hex, 16),
                   to_ip(r_ip_hex), int(r_port_hex, 16))
        except ValueError:
            continue
        index[key] = (inode, uid)
    return index


def _build_tcp_socket_index() -> tuple[dict[tuple[str, int, str, int], tuple[str, str]], bool]:
    """Both TCP tables -> ({4-tuple: (inode, uid)}, tcp_v4_readable).

    World-readable (`-r--r--r-- root:root`, measured) — no capability the
    unit does not already have.

    `tcp_v4_readable` is False only when `/proc/net/tcp` ITSELF could not be
    opened — a real regression worth its own `process_status`
    (`"host_tcp_unreadable"`, see `attribute_process`), since that file needs
    no capability this unit lacks. `/proc/net/tcp6` failing on its own is
    NOT the same signal and does not affect this flag: IPv6 is disabled on
    every host this module was measured against (see the module and
    `HostIdentity` docstrings), so `/proc/net/tcp6` being absent there is the
    expected, permanent case, not a regression to flag every sample.
    """
    index: dict[tuple[str, int, str, int], tuple[str, str]] = {}
    tcp_v4_readable = False
    for path, v6 in ((_PROC_NET_TCP_PATH, False), (_PROC_NET_TCP6_PATH, True)):
        try:
            with open(path, "r", encoding="ascii", errors="strict") as fh:
                text = fh.read()
        except OSError:
            continue
        if not v6:
            tcp_v4_readable = True
        index.update(_parse_proc_net_tcp(text, v6=v6))
    return index, tcp_v4_readable


def _uid_to_name(uid: str) -> str | None:
    """A socket's owning uid (`/proc/net/tcp`'s own `cols[7]`, parsed for
    free alongside the inode in `_parse_proc_net_tcp`) -> a username, via the
    local passwd database.

    Works for ANY live socket this process matched an inode for —
    `"not_attributable"` rows included — since the kernel hands `uid` out on
    the same terms as the rest of the row, unlike the pid this function does
    not try to find. `None` for a uid with no local passwd entry (most often
    a container's own UID namespace, which this host's NSS cannot resolve)
    is an unmapped uid, not a resolution failure to hide; the numeric `uid`
    stays on `ProcessAttribution` either way.
    """
    try:
        import pwd

        return pwd.getpwuid(int(uid)).pw_name
    except (ImportError, KeyError, ValueError, OverflowError):
        # ImportError on Windows, where this test suite also runs (see
        # sentinel/collectors/auditd.py's own uid resolver for the same
        # pattern); the rest for a uid string that is not a number, or a
        # number with no passwd entry. All of it means "cannot tell", never
        # a fabricated name.
        return None


def _scan_fd_sockets() -> tuple[dict[str, str], int, int]:
    """Walk every `/proc/<pid>/fd` entry this process is ALLOWED to read,
    mapping socket inode -> pid.

    Measured on the production host, under the exact capability set
    `sentinel-ingest.service` is granted: `os.listdir` on another user's fd
    directory succeeds (`CAP_DAC_READ_SEARCH` bypasses the directory
    permission bits), but `os.readlink` on an individual entry — the call
    that actually names the inode a fd points at — fails with
    `PermissionError` unless the target process runs as the SAME user as
    this one; `ptrace_may_access` gates it, and `CAP_DAC_READ_SEARCH` was
    never meant to satisfy that check. See the module docstring for the
    97.5%-denied measurement this produced at scale.

    Returns (inode_to_pid, attempted, denied) rather than swallowing the
    counts — a "found" rate near zero is expected and correct given the
    above, not a sign this function is broken, and the counts are what let
    that be told apart from an actual regression later.
    """
    inode_to_pid: dict[str, str] = {}
    attempted = 0
    denied = 0
    try:
        pids = [p for p in os.listdir(_PROC_ROOT) if p.isdigit()]
    except OSError:
        return {}, 0, 0
    for pid in pids:
        fd_dir = f"{_PROC_ROOT}/{pid}/fd"
        try:
            names = os.listdir(fd_dir)
        except OSError:
            # Gone since the pid listing, or (the common case for another
            # user's process — see docstring) simply not ours to enumerate.
            continue
        for name in names:
            attempted += 1
            try:
                target = os.readlink(f"{fd_dir}/{name}")
            except PermissionError:
                denied += 1
                continue
            except OSError:
                continue  # the fd closed between listing it and reading it
            m = _FD_SOCKET_RE.match(target)
            if m:
                inode_to_pid.setdefault(m.group(1), pid)
    return inode_to_pid, attempted, denied


def _process_info(pid: str) -> tuple[str | None, str | None]:
    """(comm, exe) for a pid `_scan_fd_sockets` already proved this process
    can read an fd of. `comm` is world-readable regardless of the target's
    owner; `exe` needs the same same-uid access the fd symlink itself did,
    so if the caller got this far, `exe` reliably succeeds too — a failure
    here means the process exited in the race window between the two
    `/proc` reads, not a permission gap this collector could still close.
    """
    comm: str | None = None
    exe: str | None = None
    try:
        with open(f"{_PROC_ROOT}/{pid}/comm", "r", encoding="utf-8", errors="replace") as fh:
            comm = fh.read().strip() or None
    except OSError:
        pass
    try:
        exe = os.readlink(f"{_PROC_ROOT}/{pid}/exe")
    except OSError:
        pass
    return comm, exe


@dataclass(frozen=True)
class ProcessAttribution:
    """The outcome of trying to name what opened one connection.

    `status` is written to every emitted event's `raw["process_status"]` —
    never collapsed into a bare NULL `process` column, which would be
    indistinguishable from a row written before this existed at all (see the
    module docstring): `"found"` (a name was read), `"closed_before_scan"` (a
    HOST-owned connection was already gone from `/proc/net/tcp{,6}` — the
    documented short-lived-connection gap, now visible per-row),
    `"not_attributable"` (the socket was still open, but this process could
    not read whose it was — the measured 97.5% case), `"container_egress"`
    (the source is owned only via `HostIdentity.networks`, never `.ips` — the
    HOST's own `/proc/net/tcp` cannot show it by namespace design, decided
    BEFORE any lookup runs), `"host_tcp_unreadable"` (`/proc/net/tcp` itself
    could not be read this round — a real regression, never the same fact as
    "closed"), `"udp_unsupported"` (conntrack tracks UDP; there is no
    per-connection fd table for it on the path this module was asked to use,
    so it is never attempted).

    `uid`/`user`: the owning uid of the matched socket, and its resolved
    username, populated whenever `tcp_index` had a matching inode — even for
    `"not_attributable"` rows, which is the point: the kernel hands out `uid`
    on the same terms as the rest of the row, no ptrace involved. Both are
    `None` for `"udp_unsupported"`, `"container_egress"`,
    `"host_tcp_unreadable"` and `"closed_before_scan"`, none of which ever
    reach a matched table row.
    """

    process: str | None
    pid: int | None
    exe: str | None
    status: str
    uid: str | None = None
    user: str | None = None


def attribute_process(
    tup: ConnTuple,
    tcp_index: dict[tuple[str, int, str, int], tuple[str, str]],
    inode_to_pid: dict[str, str],
    *,
    is_host_src: bool,
    tcp_readable: bool,
) -> ProcessAttribution:
    """One `ConnTuple` -> what (if anything) could be learned about the
    process that opened it, given a socket index and pid map already built
    for this sample (see `_build_tcp_socket_index`, `_scan_fd_sockets`) —
    built once per sample, not once per connection, since both cost real
    syscalls.

    `is_host_src` and `tcp_readable` are decided by the CALLER before this
    function ever looks at `tcp_index` — see the module docstring's
    "Container egress is a SECOND..." paragraph. A container's connection
    must never be allowed to fall through to `"closed_before_scan"`: the
    host's own `/proc/net/tcp` structurally cannot ever contain it, whether
    or not the read itself succeeded, so treating a miss there as "the
    process closed it" would be exactly the intention-instead-of-effect
    substitution this repository was built to stop shipping. Checked in
    that order — a container-owned source reports `"container_egress"` even
    when `tcp_readable` is also False, since the table being unreadable
    changes nothing about a connection it could never have shown anyway.
    """
    if tup.proto != "tcp":
        return ProcessAttribution(None, None, None, "udp_unsupported")
    if not is_host_src:
        return ProcessAttribution(None, None, None, "container_egress")
    if not tcp_readable:
        return ProcessAttribution(None, None, None, "host_tcp_unreadable")
    entry = tcp_index.get((tup.src, tup.sport, tup.dst, tup.dport))
    if entry is None:
        return ProcessAttribution(None, None, None, "closed_before_scan")
    inode, uid = entry
    user = _uid_to_name(uid)
    pid = inode_to_pid.get(inode)
    if pid is None:
        return ProcessAttribution(None, None, None, "not_attributable", uid=uid, user=user)
    comm, exe = _process_info(pid)
    if comm is None:
        # The pid vanished between _scan_fd_sockets and here — a real name
        # could not be produced, so this is not "found" even though a pid
        # was briefly known. uid/user survive this fallback: the kernel
        # gave those up from the table row itself, not from the pid lookup
        # that just failed.
        return ProcessAttribution(None, None, None, "not_attributable", uid=uid, user=user)
    return ProcessAttribution(comm, int(pid), exe, "found", uid=uid, user=user)


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


def _conntrack_module_loaded() -> bool | None:
    """Best-effort: is `nf_conntrack` a LOADED module, per `/proc/modules`?

    Used only to make the "absent" branch of `_log_state_change` name the
    right one of two different problems: "the module was never loaded" (an
    operator can fix that by loading it) versus "it IS loaded, but this
    kernel's procfs interface for it is compiled out" (loading it again does
    nothing, and the message must not send anyone to try). Returns True/False
    when `/proc/modules` itself is readable and does/does not list a
    `nf_conntrack` line; `None` when even that could not be read — its own
    honest "cannot tell", not a guess in either direction.

    A module compiled directly INTO the kernel (`CONFIG_NF_CONNTRACK=y`, not
    `=m`) never appears in `/proc/modules` regardless of whether it is
    active. This check cannot rule that shape out and does not claim to —
    the `False` message says exactly that, rather than asserting the module
    is absent.
    """
    try:
        with open(_PROC_MODULES_PATH, "r", encoding="ascii", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    return any(line.split(" ", 1)[0] == "nf_conntrack" for line in text.splitlines())


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
        # (bucket, tcp_v4_readable) from the last _attribute() call — see
        # _log_attribution_state. None until the first TCP attribution scan
        # actually runs.
        self._last_attribution_state: tuple[str, bool] | None = None
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

        attributions = self._attribute(kept)

        ts = datetime.now(timezone.utc)
        events: list[Event] = []
        for tup in kept:
            key = (tup.proto, tup.dst, tup.dport)
            self._last_emitted[key] = now
            attr = attributions[tup]
            raw: dict[str, object] = {"sampled": True, "process_status": attr.status}
            if attr.exe:
                raw["exe"] = attr.exe
            if attr.uid is not None:
                raw["uid"] = attr.uid
            if attr.user:
                raw["user"] = attr.user
            events.append(Event(
                ts=ts, source="conntrack", action="connect",
                src_ip=tup.src, src_port=tup.sport,
                dst_ip=tup.dst, dst_port=tup.dport, proto=tup.proto,
                process=attr.process, pid=attr.pid,
                raw=raw,
            ))
        return events

    def _attribute(self, kept: list[ConnTuple]) -> dict[ConnTuple, ProcessAttribution]:
        """Attribution for exactly the tuples about to be emitted — never
        for the ones dedup or the per-sample cap already dropped, since
        those cost real syscalls (see `_build_tcp_socket_index`,
        `_scan_fd_sockets`) that a connection nobody will see this round
        gains nothing from paying.

        `is_host_src` is decided HERE, from `HostIdentity.ips` — never
        inferred from a lookup miss — so a container's connection is
        reported as `"container_egress"`, not misread as `"closed_before_scan"`
        just because the host's own `/proc/net/tcp` was never going to list
        it. See the module docstring's "Container egress" section.
        """
        if not kept:
            return {}
        if not any(tup.proto == "tcp" for tup in kept):
            return {tup: ProcessAttribution(None, None, None, "udp_unsupported")
                    for tup in kept}
        tcp_index, tcp_readable = _build_tcp_socket_index()
        inode_to_pid, attempted, denied = _scan_fd_sockets()
        self._log_attribution_state(attempted, denied, tcp_readable)
        return {tup: attribute_process(
                    tup, tcp_index, inode_to_pid,
                    is_host_src=tup.src in self._identity.ips,
                    tcp_readable=tcp_readable)
                for tup in kept}

    def _prune_cache(self, now: float) -> None:
        cutoff = now - _CACHE_TTL_S
        self._last_emitted = {k: v for k, v in self._last_emitted.items() if v >= cutoff}

    def _log_attribution_state(self, attempted: int, denied: int, tcp_readable: bool) -> None:
        """Log ATTEMPTED/DENIED from `_scan_fd_sockets`, and whether
        `/proc/net/tcp` itself was readable, only when the bucket changes —
        the same anti-spam shape as `_log_state_change`.

        A near-total denial rate is the EXPECTED steady state (see the
        module docstring's 97.5% measurement); this does not warn about
        that. It exists so that a state which stops matching that
        expectation — `attempted` staying at 0 (the `/proc` walk itself
        broke), or `denied` dropping to 0 (either a capability change, or
        every match this round happening to be `sentinel`'s own process) —
        is visible, instead of being silently discarded the way `_attempted`/
        `_denied` were before this existed.
        """
        if attempted == 0:
            bucket = "no_attempt"
        elif denied == 0:
            bucket = "none_denied"
        elif denied == attempted:
            bucket = "fully_denied"
        else:
            bucket = "partially_denied"
        state = (bucket, tcp_readable)
        if state == self._last_attribution_state:
            return
        self._last_attribution_state = state
        log.info(
            "stare atribuire proces la eșantionarea conntrack",
            extra={"bucket": bucket, "attempted": attempted, "denied": denied,
                   "tcp_v4_readable": tcp_readable})

    def _log_state_change(self, outcome: _SampleOutcome) -> None:
        """Log only on a CHANGE of status — loud enough to be seen once,
        quiet enough not to write the same line to the journal every minute
        forever while a known-broken host stays broken."""
        if outcome.status == self._last_status:
            return
        self._last_status = outcome.status
        if outcome.status == "absent":
            # /proc/net/nf_conntrack missing has two different causes an
            # operator would act on differently — "the module was never
            # loaded" (load it) vs. "it IS loaded, but this kernel's procfs
            # interface for it is compiled out" (loading it again does
            # nothing) — collapsing them into one guess is exactly the
            # mistake this message existed to avoid making about CAP_NET_ADMIN
            # vs CAP_DAC_READ_SEARCH just below. See `_conntrack_module_loaded`
            # for what it can and cannot tell.
            loaded = _conntrack_module_loaded()
            if loaded is True:
                log.warning(
                    "nf_conntrack apare ÎNCĂRCAT ca modul (listat în "
                    "/proc/modules), dar /proc/net/nf_conntrack lipsește — "
                    "kernelul e probabil compilat fără "
                    "CONFIG_NF_CONNTRACK_PROCFS; NU se rezolvă reîncărcând "
                    "modulul. Eșantionarea traficului de ieșire e oprită",
                    extra={"path": self._path})
            elif loaded is False:
                log.warning(
                    "nf_conntrack nu apare încărcat ca modul separat "
                    "(verificat în /proc/modules) — dacă e compilat direct în "
                    "kernel (fără CONFIG_NF_CONNTRACK=m), verificarea asta nu "
                    "îl vede. Eșantionarea traficului de ieșire e oprită",
                    extra={"path": self._path})
            else:
                log.warning(
                    "nf_conntrack indisponibil, iar /proc/modules nu s-a "
                    "putut citi ca să spună dacă modulul e încărcat sau nu — "
                    "cauza rămâne necunoscută. Eșantionarea traficului de "
                    "ieșire e oprită",
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
