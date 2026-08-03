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
  1. actor must be a real IP — a campaign cluster key has nothing to block;
  2. severity at or above the gate (default: high) — noise must not arm;
  3. actor not allowlisted and not a known research scanner;
  4. no CIDR unless explicitly allowed — one /24 takes out a NAT'd building;
  5. blocklist below max_elements;
  6. under max_per_minute — the runaway-detector backstop.

The executor re-checks its own never-block on top of all this, so even a bug
here cannot firewall off the admin. Ships DISABLED: with auto_block.enabled
false, every path lands in observe mode and nothing is ever placed automatically.
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

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _is_ip(actor_key: str | None) -> bool:
    if not actor_key:
        return False
    try:
        ipaddress.ip_address(actor_key)
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

    # Guard 2: severity gate. Below it, never arm — but still surface the alert
    # with a manual block button.
    if _SEV_RANK.get(spec.severity, 0) < _SEV_RANK.get(ab.min_severity, 3):
        return "observed"

    # Guard 3: a /24 is a CIDR; actor_key is a single host here, but keep the
    # guard honest for when cluster actors gain address ranges.
    if "/" in spec.actor_key and not ab.allow_cidr_blocks:
        return "skipped:cidr_not_allowed" if ab.enabled else "observed"

    # Guard 4: allowlisted or a known research scanner — internet background
    # noise, blocking it achieves nothing and risks a false positive.
    flags = await inc_repo.actor_flags(db, spec.actor_key)
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

    # Guard 5: hard ceiling on set size.
    if await blocklist_repo.count_active(db) >= ab.max_elements:
        log.error("auto-block cap: max_elements reached", extra={"cap": ab.max_elements})
        return "skipped:max_elements"

    # Guard 6: rate cap — the runaway-detector backstop.
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
