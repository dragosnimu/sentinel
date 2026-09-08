"""The auto-block decider — the one place that turns a detection into a block.

It runs inside sentinel-detect, right after an incident is written. It never
touches Telegram or the executor's socket directly for messaging: it records its
decision on the incident (`auto_action`) and, when armed, calls the same
`respond.actions.block` a human command would. The push loop reads the decision
and shapes the alert. That split means:

  * the detect service needs no Telegram token and no bot;
  * the alert and the action can never disagree (both read one column);
  * observe mode and armed mode share every guard — the only difference is
    whether the block is actually placed.

Guards, in order (any one stops the block; armed mode records why):
  1. actor must be a real network address — a single host, or (only relevant
     once allow_cidr_blocks is armed) an aligned range;
  2. this host's own configured DNS resolver is never a target, whatever rule
     proposed it — see "Never-block resolvers" below;
  3. severity at or above the gate (default: high) — noise must not arm. A
     known-hostile actor (reputation feed category botnet/tor/compromised/
     drop) clears this one severity tier earlier — see "Reputation moves the
     threshold" below;
  4. source_is_authentic — a Suricata alert with NO TCP protocol among its
     evidence is refused unless corroborated by a real TCP exchange from the
     same source in the same window; see "Suricata over anything but TCP"
     below;
  5. no CIDR unless explicitly allowed — one /24 takes out a NAT'd building;
  6. a CIDR must carry a real TTL — auto-block never places a permanent
     block, and a range even less so;
  7. actor not allowlisted and not a known research scanner;
  8. blocklist below max_elements;
  9. a CIDR stays below its own max_active_cidrs, tighter than max_elements;
  10. under max_per_minute — the runaway-detector backstop.

## Never-block resolvers

`constants.NEVER_BLOCK_NETWORKS` (and the executor's own copy) already cover
the loopback stub resolver — 127.0.0.53 sits inside 127.0.0.0/8 — but a host's
REAL upstream resolver can be a routable, public address: an ISP's own DNS, a
VPN's, or an operator's deliberate choice of a well-known public resolver such
as Cloudflare's or Google's. No hard-coded list can name that in advance,
because it is genuinely host-specific, unlike
the RFC1918/loopback ranges that are the same everywhere. This guard reads
`/etc/resolv.conf` directly (cached, refreshed hourly rather than on every
decision — resolv.conf does not change minute to minute, and this function
runs on every fresh detection) and refuses to block anything on that list,
full stop, before severity or reputation are even consulted: blocking your own
resolver breaks every OTHER lookup this host makes, including the one needed
to reach Telegram or the AI endpoint by name.

Best-effort by design: a host without `/etc/resolv.conf` (a container using
`--dns`, a non-Linux dev box, a sandbox with no such file) sees an empty
resolver set and this guard simply does nothing — it narrows what gets
protected, never what gets blocked, so a missing file cannot itself cause a
block that would not otherwise happen.

## Suricata over anything but TCP

An off-path attacker can put ANY address they like in a UDP, ICMP, GRE,
IP-in-IP, or SCTP packet's source field — none of those require completing an
exchange, so nothing forces the attacker to be reachable at that address. A
severity-1 Suricata signature over any of those protocols is therefore one
crafted packet away from auto-blocking an innocent, uninvolved address instead
of whoever actually sent it — production has fired exactly this shape of alert
on this host's own DNS traffic (UDP), and separately logged GRE and IP-in-IP
alerts an earlier version of this guard treated as authentic because it
checked evidence against an allowlist of "known spoofable" names instead of
requiring proof — see `_is_spoofable_evidence` for why that shape was the bug.

What this guard does NOT close: a bare TCP SYN is just as spoofable as a UDP
packet — nothing requires the sender to be reachable at the source address it
put in a SYN, and a SYN-flood or decoy scan does exactly that. Only a
*completed* handshake proves reachability (the peer had to receive the
kernel-chosen SYN-ACK to send the final ACK), but `evidence["protocols"]` is
the transport Suricata tagged the alert with, not evidence the exchange
finished — a stateless signature that fires on a lone SYN is recorded as
"TCP" exactly like one that fires deep into an established connection, and
this guard cannot tell the two apart. Distinguishing them would need
Suricata's own `flow` (established vs. not) state carried into evidence,
which nothing here consumes yet — out of scope for this guard; noted as a
follow-up in `docs/SECURITATE.md` item 9. In practice this still closes the
hole that has actually fired in production: 273 of 274 Suricata events over a
7-day sample (measured 8 Sep 2026 on the production host) were TCP, so the guard's TCP/not-TCP line covers the traffic
that matters here even though it does not (yet) distinguish a SYN from a full
exchange within it.

`source_is_authentic` only ever applies to `ids.suricata` evidence: the other
rules already require a real TCP/HTTP exchange to produce ANY evidence at all
(an sshd auth line or an nginx request cannot exist without one), so they have
nothing to corroborate. It reads `evidence["protocols"]`, the distinct
transport protocols `detect/rules.suricata_alert` saw for that source in the
window; unless at least one of them is TCP (case-insensitively — the list is
empty, absent, or every entry is something else, UDP/ICMP/GRE/IP-in-IP/SCTP/
unrecognised alike: an unknown protocol is not evidence of authenticity, so it
is treated the same as spoofable, per CLAUDE.md: unknown and fine are
different states), the guard looks for a completed TCP exchange from the same
source in the same window. In practice the only two sources that actually
corroborate an EXTERNAL actor are an nginx request or an sshd line — both
protocols are TCP-only by definition, so either one existing at all proves a
completed handshake from that address. `_has_tcp_corroboration`'s query also
accepts a `conntrack` row with `proto = 'tcp'`; that branch is kept because it
is harmless, not because it currently corroborates anything here — the
conntrack collector samples only outbound rows (`src_ip` is always this host),
so for an off-host attacker the branch never matches and nginx/sshd are the
only real corroboration this guard has. Finding neither, the block is
refused and the reason recorded (`skipped:spoofable_source`), surfaced to the
operator as a refusal, not a silent drop of the incident.

The executor re-checks its own never-block on top of all this, so even a bug
here cannot firewall off the admin. Ships DISABLED: with auto_block.enabled
false, every path lands in observe mode and nothing is ever placed automatically.

## Reputation moves the threshold, never the decision

A reputation feed says what an address did somewhere ELSE, on somebody else's
network, aggregated by a third party this host has no way to audit. Blocking
on that alone would import every mistake in that feed as a blind spot this
host cannot diagnose — a wrong DROP-list entry becomes a block with no local
evidence behind it, and nobody investigating this host's own logs would ever
find a reason for it.

So `flags["reputation"]` (categories: `botnet`, `tor`, `compromised`, `drop` —
see `sentinel/intel/reputation.py`; `scanner` is handled separately at guard 7,
with the OPPOSITE effect) only ever shifts guard 3's severity floor down by
one tier — `high` needs `medium` instead, `medium` needs `low`. It can never
push the floor below `low`, and it never substitutes for severity: `severity`
on every `DetectionSpec` is still assigned purely from what a rule measured on
THIS host (a count of failed logins, a rate of 404s — see `detect/rules.py`),
never from the feed. A hostile-tagged address with zero local evidence never
reaches this function with a severity at all, because no rule ever fired for
it; a lower floor cannot arm what was never proposed. That is the literal
meaning of "shortens the local-evidence requirement, does not waive it".
"""

from __future__ import annotations

import ipaddress
import time
from pathlib import Path

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import blocklist as blocklist_repo
from sentinel.db.repo import incidents as inc_repo
from sentinel.detect.rules import DetectionSpec, SURICATA_WINDOW_MIN
from sentinel.logging_setup import get_logger
from sentinel.respond import actions

log = get_logger(__name__)

_SEV_ORDER = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}

# Categories that make an address MORE likely to deserve an earlier block.
# `scanner` is deliberately absent — it has the inverse effect, handled at
# guard 7 via `is_known_scanner`/`skip_known_scanners`, never here.
_HOSTILE_CATEGORIES = frozenset({"botnet", "tor", "compromised", "drop"})

# ---------------------------------------------------------------------------
# Never-block resolvers (guard 2) — see "Never-block resolvers" above.
# ---------------------------------------------------------------------------
_RESOLV_CONF_PATH = "/etc/resolv.conf"
_RESOLVERS_REFRESH_S = 3600  # re-read at most hourly; resolv.conf is not hot.
# `loaded_at` starts at `None`, never at `time.monotonic()`'s own zero point.
# `time.monotonic()` measures seconds since SOME arbitrary epoch that on Linux
# is boot time — a `0.0` starting value compared with `now - loaded_at >
# _RESOLVERS_REFRESH_S` meant the guard would not load ANYTHING until the
# host's uptime itself exceeded an hour, because until then `now` was already
# smaller than the refresh threshold and the cache looked "still fresh" despite
# never having been populated. A freshly restarted `sentinel-detect` (the
# common case right after a deploy) ran guard 2 as a no-op — reading an empty
# resolver set — for its first hour every time. `None` is loaded unconditionally
# on the first call, whatever the host's uptime is.
_resolvers_cache: dict[str, object] = {"loaded_at": None, "addrs": frozenset()}


def _read_configured_resolvers(path: str = _RESOLV_CONF_PATH) -> frozenset[str]:
    """Every `nameserver` address in `/etc/resolv.conf`, normalised through
    `ipaddress` so an address like `203.0.113.7` and any equivalent spelling
    (leading zeros, a compressed IPv6 form) compare equal to whatever an
    incoming `actor_key` looks like. Best-effort: a missing file,
    a permissions error, or a line `ipaddress` cannot parse (an IPv6 zone-id
    suffix, a stray comment) is skipped rather than raised — this guard
    narrows what gets protected, never what gets blocked, so failing to read
    the file must not itself enable a block that would not otherwise happen."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return frozenset()
    out: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                out.add(str(ipaddress.ip_address(parts[1])))
            except ValueError:
                continue
    return frozenset(out)


def _configured_resolvers() -> frozenset[str]:
    """Cached for `_RESOLVERS_REFRESH_S`: this runs on every fresh detection,
    potentially many times a minute, and re-reading a file that changes on the
    timescale of "the operator edited it" that rarely would be pure overhead.

    Loads unconditionally on the first call (`loaded_at is None`), regardless
    of `time.monotonic()`'s own value — see the comment on `_resolvers_cache`
    for why that sentinel matters. After the first load, refreshes once
    `_RESOLVERS_REFRESH_S` has elapsed.

    Reads `_RESOLV_CONF_PATH` fresh on every cache miss (rather than relying on
    `_read_configured_resolvers`'s default argument, bound once at import time)
    so a test can point it at a temp file without needing to wait an hour."""
    now = time.monotonic()
    loaded_at = _resolvers_cache["loaded_at"]
    if loaded_at is None or now - loaded_at >= _RESOLVERS_REFRESH_S:  # type: ignore[operator]
        _resolvers_cache["addrs"] = _read_configured_resolvers(_RESOLV_CONF_PATH)
        _resolvers_cache["loaded_at"] = now
    return _resolvers_cache["addrs"]  # type: ignore[return-value]


def _is_configured_resolver(actor_key: str) -> bool:
    try:
        addr = ipaddress.ip_address(actor_key)
    except ValueError:
        return False  # a CIDR (or anything else non-host-shaped) is never a resolver
    return str(addr) in _configured_resolvers()


# ---------------------------------------------------------------------------
# source_is_authentic (guard 4) — see "Suricata over anything but TCP" above.
# ---------------------------------------------------------------------------
# Deliberately NOT an allowlist of "known spoofable" protocol names — see
# `_is_spoofable_evidence` below for why an allowlist of the untrusted side is
# the wrong shape for this check.


def _is_spoofable_evidence(evidence: dict) -> bool:
    """True unless a real TCP entry is present in `evidence["protocols"]`.

    This is inverted from the tempting shape ("is every protocol in a
    known-spoofable set?") on purpose: that shape needs the set to name every
    spoofable transport in advance, and it cannot — production has logged
    severity-2 Suricata alerts over GRE (156 of them) and IP-in-IP (14), and
    ICMPv6 shows up in Suricata's own event log spelled `IPv6-ICMP`, none of
    which an allowlist of `{"UDP", "ICMP", ...}` anticipated. Every one of
    those fell through the old check's `protocols <= _SPOOFABLE_PROTOCOLS`
    test as `False` (`"GRE" <= {"UDP", "ICMP", ...}` is false because GRE is
    not a member), which made `_is_spoofable_evidence` return `False` too —
    "not proven spoofable" was read as "authentic", so GRE/IP-in-IP/SCTP/
    anything-not-yet-catalogued auto-armed with ZERO TCP corroboration, the
    exact hole this guard exists to close.

    TCP is the one protocol that cannot be spoofed off-path (it needs a
    completed handshake), so it is the only thing this function trusts
    POSITIVELY: authentic iff "TCP" is present, case-insensitively; every
    other protocol, any unknown/future one, and an empty or absent list are
    all "not proven" and therefore spoofable — unknown and fine are different
    states, per CLAUDE.md, and this function never conflates them."""
    protocols = {str(p).upper() for p in (evidence.get("protocols") or ()) if p}
    return "TCP" not in protocols


async def _has_tcp_corroboration(db: Database, src_ip: str, window_min: int) -> bool:
    """A real TCP exchange from the same source in the same window: an nginx
    request or an sshd auth line — both protocols run over TCP only, so
    either one existing at all proves a completed handshake from that
    address. This is confirming the source is reachable at that address, not
    raising a second independent detection against it.

    Also matches a `conntrack` row with `proto = 'tcp'`, kept for the day the
    conntrack collector samples inbound rows too; it does not today (it keeps
    only outbound ones, so `src_ip` there is always this host), which makes
    the branch inert — never matching, never wrongly matching — for every
    off-host actor this guard is asked about. See the module docstring's
    "Suricata over anything but TCP" section."""
    return bool(await db.fetchval(
        """
        SELECT 1 FROM raw_events
         WHERE src_ip = $1::inet
           AND ts > now() - make_interval(mins => $2)
           AND (source IN ('nginx', 'sshd')
                OR (source = 'conntrack' AND lower(proto) = 'tcp'))
         LIMIT 1
        """,
        src_ip, window_min))


def _lower_by_one(min_sev: str) -> str:
    """One severity tier below `min_sev`, never below `low`. A known-hostile
    actor earns a SHORTER local-evidence requirement, not a WAIVED one — see
    "Reputation moves the threshold" in the module docstring."""
    idx = _SEV_RANK.get(min_sev, _SEV_RANK["high"])
    return _SEV_ORDER[max(idx - 1, 1)]


def _is_ip(actor_key: str | None) -> bool:
    """A real network address for nftables — a single host, or (only relevant
    once allow_cidr_blocks is armed) an aligned network like `198.51.100.0/24`.

    `ip_network(actor_key, strict=True)` accepts both and rejects a sloppy
    `198.51.100.5/24` (host bits set past the mask) exactly as it rejects
    `campaign:<hash>` — neither is something nftables can drop. Before this
    used `ip_address`, any CIDR-shaped actor_key failed here and returned
    "observed" before ever reaching guard 5 below, so the CIDR gate there was
    unreachable code — dead for every proposal, not just the disallowed ones."""
    if not actor_key:
        return False
    try:
        ipaddress.ip_network(actor_key, strict=True)
    except ValueError:
        return False
    return True


async def consider(db: Database, cfg: Config, spec: DetectionSpec, incident_id: int) -> str:
    """Decide and act on one fresh detection. Returns the auto_action recorded
    ('blocked' | 'observed' | 'skipped:<reason>'), which the caller has already
    persisted via this function. Never raises into the detect pass."""
    action = await _decide(db, cfg, spec, incident_id)
    await inc_repo.set_auto_action(db, incident_id, action)
    if action == "blocked":
        log.warning("auto-blocked", extra={"ip": spec.src_ip, "rule": spec.rule_id,
                                            "incident_id": incident_id})
    elif action.startswith("skipped:"):
        log.info("auto-block skipped", extra={"ip": spec.src_ip, "reason": action[8:],
                                              "incident_id": incident_id})
    return action


async def _decide(db: Database, cfg: Config, spec: DetectionSpec, incident_id: int) -> str:
    ab = cfg.response.auto_block

    # Guard 1: a network block needs a network address.
    if not _is_ip(spec.actor_key):
        return "observed"

    # Guard 2: never block this host's own configured DNS resolver, whatever
    # rule proposed it and however severe — see "Never-block resolvers" in the
    # module docstring. Ahead of severity/reputation on purpose: nothing below
    # should be able to override it.
    if _is_configured_resolver(spec.actor_key):
        return "skipped:configured_resolver" if ab.enabled else "observed"

    # Fetched here, not at guard 7 where only allowlist/scanner used to need
    # it: guard 3 below now also reads `flags["reputation"]`.
    flags = await inc_repo.actor_flags(db, spec.actor_key)

    # Guard 3: severity gate. Below it, never arm — but still surface the alert
    # with a manual block button. A known-hostile actor clears the gate one
    # tier earlier; see "Reputation moves the threshold" in the module
    # docstring for why this can only ever shorten the local-evidence
    # requirement, never replace it.
    effective_min = ab.min_severity
    if any(cat in _HOSTILE_CATEGORIES for cat in flags.get("reputation", ())):
        effective_min = _lower_by_one(ab.min_severity)
    if _SEV_RANK.get(spec.severity, 0) < _SEV_RANK.get(effective_min, 3):
        return "observed"

    # Guard 4: source_is_authentic — see "Suricata over anything but TCP" in
    # the module docstring. Only `ids.suricata` evidence carries a `protocols`
    # field; every other rule's evidence cannot exist without a real TCP/HTTP
    # exchange, so this is a no-op for them.
    if spec.rule_id == "ids.suricata" and _is_spoofable_evidence(spec.evidence):
        window_min = spec.evidence.get("window_min") or SURICATA_WINDOW_MIN
        if not await _has_tcp_corroboration(db, spec.actor_key, int(window_min)):
            return "skipped:spoofable_source" if ab.enabled else "observed"

    is_cidr = "/" in spec.actor_key

    # Guard 5: a /24 is a CIDR; actor_key is a single host here, but keep the
    # guard honest for when cluster actors gain address ranges.
    if is_cidr and not ab.allow_cidr_blocks:
        return "skipped:cidr_not_allowed" if ab.enabled else "observed"

    # Guard 6: 0002's schema comment is explicit that only an operator creates
    # a permanent block and "auto-block never does" — a range even less than a
    # single host, since a bad /24 sits on far more innocent addresses than a
    # bad /32. default_ttl_s is a required int in config, but a stray YAML
    # `null` or a `0` must not silently turn into a permanent range block —
    # refuse instead of placing one nobody decided on.
    if is_cidr and not ab.default_ttl_s:
        return "skipped:cidr_requires_ttl" if ab.enabled else "observed"

    # Guard 7: allowlisted or a known research scanner — internet background
    # noise, blocking it achieves nothing and risks a false positive. `flags`
    # was already fetched above, for guard 3's reputation check.
    if flags.get("is_allowlisted"):
        return "skipped:allowlisted" if ab.enabled else "observed"
    if ab.skip_known_scanners and flags.get("is_known_scanner"):
        return "skipped:known_scanner" if ab.enabled else "observed"

    # Everything below is enforcement. In observe mode we stop here: the operator
    # gets the alert and the button, and we record that we WOULD have acted.
    if not ab.enabled:
        return "observed"

    # Already blocked (an earlier detection in the same campaign armed it): keep
    # the state, do not re-place the rule or fire a second notification.
    if await blocklist_repo.is_active(db, spec.actor_key):
        return "blocked"

    # Guard 8: hard ceiling on set size.
    if await blocklist_repo.count_active(db) >= ab.max_elements:
        log.error("auto-block cap: max_elements reached", extra={"cap": ab.max_elements})
        return "skipped:max_elements"

    # Guard 9: a separate, tighter ceiling on active RANGE blocks. max_elements
    # counts individual addresses too — a handful of /24s already covers
    # thousands of them without the raw element count coming anywhere near its
    # cap, so a runaway CIDR proposer needs its own backstop.
    if is_cidr and await blocklist_repo.count_active_cidrs(db) >= ab.max_active_cidrs:
        log.error("auto-block cap: max_active_cidrs reached",
                  extra={"cap": ab.max_active_cidrs})
        return "skipped:max_active_cidrs"

    # Guard 10: rate cap — the runaway-detector backstop.
    if await blocklist_repo.count_auto_since(db, 60) >= ab.max_per_minute:
        log.error("auto-block cap: max_per_minute reached", extra={"cap": ab.max_per_minute})
        return "skipped:rate_cap"

    # Place it. The executor is still the authority and re-checks never-block;
    # a refusal there is caught and recorded, not raised into the detect pass.
    try:
        await actions.block(
            db, spec.actor_key, ttl=ab.default_ttl_s,
            reason=f"auto-block: {spec.rule_id}", by=f"auto:{spec.rule_id}",
            incident_id=incident_id, actor_key=spec.actor_key,
        )
        return "blocked"
    except actions.BlockRefused as exc:
        return f"skipped:refused_client"
    except Exception as exc:  # noqa: BLE001 - executor rejected/unavailable, never fatal
        log.error("auto-block failed", extra={"ip": spec.actor_key, "detail": str(exc)})
        return "skipped:executor_error"
