"""Load the operator's inventory.yaml and sync its confirmed assets into the DB.

inventory.yaml is the source of truth for *what Sentinel watches*. This module
reads it, upserts each entry under `assets:` into the assets table so the health
prober has something to probe, and retires the assets that are no longer listed.
It never writes inventory.yaml — discovery does that, additively, and only the
operator promotes a discovered entry into `assets:`.

Source of truth means both halves. Until 29 August 2026 this module only ever
confirmed what was PRESENT in the file, so the assets table could grow and never
shrink, and removing an entry from inventory.yaml did nothing at all. See
`sync` for what that cost.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from sentinel.constants import CONFIG_DIR
from sentinel.db.engine import Database
from sentinel.db.repo import assets as assets_repo
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

# SENTINEL_INVENTORY lets tests point this at a fixture without touching /etc.
INVENTORY_PATH = Path(os.environ.get("SENTINEL_INVENTORY", f"{CONFIG_DIR}/inventory.yaml"))

_ALLOWED = {
    "name", "kind", "bind_addr", "port", "is_internet_exposed", "criticality",
    "systemd_unit", "container_id", "container_image", "vhost_file", "webroot",
    "stack", "databases", "protected", "confirmed_by_operator", "tags", "notes",
}


def load(path: Path = INVENTORY_PATH) -> list[dict[str, Any]]:
    """Return the confirmed asset specs from inventory.yaml (the `assets:` list).

    A missing or empty file yields an empty list rather than an error: a fresh
    install with no inventory yet is a valid state, not a failure.
    """
    if not path.exists():
        return []
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    specs = raw.get("assets") or []
    if not isinstance(specs, list):
        raise ValueError(f"{path}: 'assets' must be a list")

    cleaned: list[dict[str, Any]] = []
    for i, spec in enumerate(specs):
        if not isinstance(spec, dict) or "name" not in spec:
            raise ValueError(f"{path}: assets[{i}] needs at least a 'name'")
        unknown = set(spec) - _ALLOWED
        if unknown:
            raise ValueError(f"{path}: assets[{i}] ({spec['name']}) has unknown keys: {sorted(unknown)}")
        cleaned.append(spec)
    return cleaned


def diff(current: list[dict[str, Any]], proposed: list[dict[str, Any]]) -> dict[str, list[str]]:
    """What `sync` would do if `proposed` replaced `current` as inventory.yaml.

    Pure and DB-free, on purpose: `scripts/inventory-push.sh` needs to show an
    operator what a push would change *before* anything reaches the host, and
    the only way to make that promise honestly is to compute it from the same
    two lists `sync` itself would see — not from a second, hand-written
    comparison that could drift from what `sync` actually does. See `sync`'s
    own docstring for why an empty `proposed` is `sync`'s special "retire
    nothing" case; the caller (the push script) is the one that must refuse to
    treat a locally-truncated file as "retire everything", by validating
    `proposed` with `load` first and never diffing an empty list in here.

    Returns `{"added": [...], "retired": [...], "kept": [...]}`, each sorted by
    name. `retired` is exactly `assets_repo.retire_missing`'s effect: every
    name in `current` that `proposed` does not repeat.
    """
    current_names = {spec["name"] for spec in current}
    proposed_names = {spec["name"] for spec in proposed}
    return {
        "added": sorted(proposed_names - current_names),
        "retired": sorted(current_names - proposed_names),
        "kept": sorted(current_names & proposed_names),
    }


async def sync(db: Database, path: Path = INVENTORY_PATH) -> dict[str, Any]:
    """Make the assets table match inventory.yaml, in both directions.

    Upserts every listed asset, then retires every asset that is not listed.
    Returns {'assets': n, 'retired': k, 'retired_names': […], 'retire_skipped': 0 or 1}.

    `retired_names` is there because a count cannot be acted on. The caller has
    to be able to tell the operator WHICH probes stopped — "3 retired" and
    "n8n, qdrant, webmin retired" are the difference between a number to shrug
    at and a list to check against what you actually edited.

    Idempotent: re-running only refreshes discovered fields and last_seen, and
    retires nothing the second time because `retire_missing` skips rows that
    already carry a `retired_at`. The operator-owned flags are preserved by
    assets_repo.upsert.

    Retiring is what closes the loop. Without it the table only grew: on
    29 August 2026 the Services page had shown four permanently red rows for
    eighteen days — n8n, n8n-traefik, qdrant and webmin — none of which was
    down. All four had been uninstalled from the host weeks earlier, three of
    them still declared internet-exposed ports that no longer existed, and
    nothing the operator could do to inventory.yaml would remove them.

    ## Why an empty file retires nothing

    `load` returns an empty list for at least three different states, and from
    here they are indistinguishable:

      * a fresh install that has no inventory yet (deliberate — see `load`);
      * a file truncated to nothing, by a failed edit or a full disk;
      * a file whose `assets:` key was lost or renamed in an edit.

    Only the first is intended, and acting on any of them would retire every
    asset at once and stop all monitoring on the host, silently, at the moment
    monitoring is least likely to be watched. So an empty list retires nothing,
    and that outcome is reported as `retire_skipped`, never as `retired: 0`:
    "there was nothing to retire" and "I could not tell what to retire" are
    different facts, and a tally that collapses them is a tally that lies.

    A file that exists but does not parse never reaches the retiring step at
    all — `load` raises, health_service logs it and keeps probing what it
    already has, which is the same conservative outcome by a different route.

    What this cannot detect is a PARTIALLY truncated file: eleven assets left
    of fourteen looks exactly like three assets removed on purpose. Nothing in
    the file distinguishes them, so retirement is deliberately reversible and
    every retired name is both logged and RETURNED, rather than guessed at with
    a threshold. The one party who can tell an edit from a truncation is the
    operator, and the only way they get to answer is by being shown the names.
    """
    specs = load(path)
    for spec in specs:
        await assets_repo.upsert(db, spec)

    if not specs:
        log.warning(
            "inventory lists no assets; nothing retired",
            extra={"path": str(path), "file_exists": path.exists()},
        )
        return {"assets": 0, "retired": 0, "retired_names": [], "retire_skipped": 1}

    # Everything in the table that the file no longer names. Assets only ever
    # enter this table through this function, so "not in the file" is the same
    # statement as "the operator stopped watching it" — including for
    # `protected` assets, whose flag means "no automated patch plan may touch
    # it", not "this row is permanent".
    retired = sorted(await assets_repo.retire_missing(db, [spec["name"] for spec in specs]))
    if retired:
        # Named, not counted: four rows going quiet has to be traceable back to
        # one edit of one file, months later, from the log alone. The journal is
        # the record; it is not the notice — see `health_service._sync_inventory`
        # for the half of this that reaches a human.
        log.info("assets retired", extra={"names": ", ".join(retired)})
    log.info("inventory synced", extra={"assets": len(specs), "retired": len(retired)})
    return {"assets": len(specs), "retired": len(retired),
            "retired_names": retired, "retire_skipped": 0}
