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
  2. severity at or above the gate (default: high) — noise must not arm. A
     known-hostile actor (reputation feed category botnet/tor/compromised/
     drop) clears this one severity tier earlier — see "Reputation moves the
     threshold" below;
  3. no CIDR unless explicitly allowed — one /24 takes out a NAT'd building;
  4. a CIDR must carry a real TTL — auto-block never places a permanent
     block, and a range even less so;
  5. actor not allowlisted and not a known research scanner;
  6. blocklist below max_elements;
  7. a CIDR stays below its own max_active_cidrs, tighter than max_elements;
  8. under max_per_minute — the runaway-detector backstop.

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
see `sentinel/intel/reputation.py`; `scanner` is handled separately at guard 5,
with the OPPOSITE effect) only ever shifts guard 2's severity floor down by
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

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import blocklist as blocklist_repo
from sentinel.db.repo import incidents as inc_repo
from sentinel.detect.rules import DetectionSpec
from sentinel.logging_setup import get_logger
from sentinel.respond import actions

log = get_logger(__name__)

_SEV_ORDER = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}

# Categories that make an address MORE likely to deserve an earlier block.
# `scanner` is deliberately absent — it has the inverse effect, handled at
# guard 5 via `is_known_scanner`/`skip_known_scanners`, never here.
_HOSTILE_CATEGORIES = frozenset({"botnet", "tor", "compromised", "drop"})


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
    "observed" before ever reaching guard 3 below, so the CIDR gate there was
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

    # Fetched here, not at guard 5 where only allowlist/scanner used to need
    # it: guard 2 below now also reads `flags["reputation"]`.
    flags = await inc_repo.actor_flags(db, spec.actor_key)

    # Guard 2: severity gate. Below it, never arm — but still surface the alert
    # with a manual block button. A known-hostile actor clears the gate one
    # tier earlier; see "Reputation moves the threshold" in the module
    # docstring for why this can only ever shorten the local-evidence
    # requirement, never replace it.
    effective_min = ab.min_severity
    if any(cat in _HOSTILE_CATEGORIES for cat in flags.get("reputation", ())):
        effective_min = _lower_by_one(ab.min_severity)
    if _SEV_RANK.get(spec.severity, 0) < _SEV_RANK.get(effective_min, 3):
        return "observed"

    is_cidr = "/" in spec.actor_key

    # Guard 3: a /24 is a CIDR; actor_key is a single host here, but keep the
    # guard honest for when cluster actors gain address ranges.
    if is_cidr and not ab.allow_cidr_blocks:
        return "skipped:cidr_not_allowed" if ab.enabled else "observed"

    # Guard 4: 0002's schema comment is explicit that only an operator creates
    # a permanent block and "auto-block never does" — a range even less than a
    # single host, since a bad /24 sits on far more innocent addresses than a
    # bad /32. default_ttl_s is a required int in config, but a stray YAML
    # `null` or a `0` must not silently turn into a permanent range block —
    # refuse instead of placing one nobody decided on.
    if is_cidr and not ab.default_ttl_s:
        return "skipped:cidr_requires_ttl" if ab.enabled else "observed"

    # Guard 5: allowlisted or a known research scanner — internet background
    # noise, blocking it achieves nothing and risks a false positive. `flags`
    # was already fetched above, for guard 2's reputation check.
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

    # Guard 6: hard ceiling on set size.
    if await blocklist_repo.count_active(db) >= ab.max_elements:
        log.error("auto-block cap: max_elements reached", extra={"cap": ab.max_elements})
        return "skipped:max_elements"

    # Guard 7: a separate, tighter ceiling on active RANGE blocks. max_elements
    # counts individual addresses too — a handful of /24s already covers
    # thousands of them without the raw element count coming anywhere near its
    # cap, so a runaway CIDR proposer needs its own backstop.
    if is_cidr and await blocklist_repo.count_active_cidrs(db) >= ab.max_active_cidrs:
        log.error("auto-block cap: max_active_cidrs reached",
                  extra={"cap": ab.max_active_cidrs})
        return "skipped:max_active_cidrs"

    # Guard 8: rate cap — the runaway-detector backstop.
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
