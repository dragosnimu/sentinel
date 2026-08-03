"""Run the rules, turn their matches into detections and incidents.

One pass: advance from the last processed event id, evaluate every rule, and for
each match attribute an actor, record a detection, and fold it into an incident
(new or existing). An allowlisted actor is skipped before anything is written —
Sentinel's own address, the operator's, a known-good scanner — so a rule can
never raise an incident against something explicitly trusted.
"""

from __future__ import annotations

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import incidents as inc_repo
from sentinel.detect.rules import RULES, DetectionSpec
from sentinel.logging_setup import get_logger
from sentinel.respond import decider

log = get_logger(__name__)


async def run_once(db: Database, cfg: Config) -> dict[str, int]:
    if not cfg.detection.enabled:
        return {"detections": 0, "new_incidents": 0}

    cursor = await inc_repo.get_detect_cursor(db)
    max_id = int(await db.fetchval("SELECT COALESCE(max(id), 0) FROM raw_events") or 0)
    if max_id <= cursor:
        return {"detections": 0, "new_incidents": 0}

    detections = 0
    new_incidents = 0
    for rule in RULES:
        try:
            specs = await rule(db, cursor)
        except Exception as exc:  # noqa: BLE001 - one broken rule must not stop the rest
            log.error("rule failed", extra={"rule": rule.__name__, "detail": str(exc)})
            continue
        for spec in specs:
            n, was_new = await _apply(db, cfg, spec)
            detections += n
            new_incidents += was_new

    await inc_repo.set_detect_cursor(db, max_id)
    if detections:
        log.info("detections", extra={"detections": detections, "new_incidents": new_incidents,
                                      "cursor": max_id})
    return {"detections": detections, "new_incidents": new_incidents}


async def _apply(db: Database, cfg: Config, spec: DetectionSpec) -> tuple[int, int]:
    if await inc_repo.actor_is_allowlisted(db, spec.actor_key):
        return 0, 0

    await inc_repo.upsert_actor(
        db, spec.actor_key,
        src_ip=spec.src_ip,
        country=spec.evidence.get("country"),
        asn=spec.evidence.get("asn"),
        user_agent=spec.evidence.get("user_agent"),
        asset_id=spec.asset_id,
    )
    detection_id = await inc_repo.record_detection(
        db,
        rule_id=spec.rule_id, rule_family=spec.rule_family, severity=spec.severity,
        actor_key=spec.actor_key, src_ip=spec.src_ip, dst_port=spec.dst_port,
        asset_id=spec.asset_id, evidence=spec.evidence, event_ids=spec.event_ids,
    )
    incident_id, is_new = await inc_repo.upsert_incident(
        db,
        fingerprint=spec.fingerprint, severity=spec.severity, title=spec.title,
        summary=spec.summary, actor_key=spec.actor_key, asset_id=spec.asset_id,
    )
    await inc_repo.link_detection(db, detection_id, incident_id)
    await inc_repo.add_timeline(
        db, incident_id, "detection", "auto",
        {"rule": spec.rule_id, "severity": spec.severity, "detection_id": detection_id},
    )

    # The response arm. Observe mode records "would block" and leaves the manual
    # button; armed mode may place the block. Isolated so a decider failure can
    # never lose the detection that is already safely written above.
    try:
        action = await decider.consider(db, cfg, spec, incident_id)
        if action != "observed":
            await inc_repo.add_timeline(
                db, incident_id, "action", "auto", {"auto_action": action, "ip": spec.src_ip})
    except Exception as exc:  # noqa: BLE001 - detection must survive a bad decision
        log.error("decider failed", extra={"incident_id": incident_id, "detail": str(exc)})

    return 1, (1 if is_new else 0)
