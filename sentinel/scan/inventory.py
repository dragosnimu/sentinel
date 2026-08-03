"""Load the operator's inventory.yaml and sync its confirmed assets into the DB.

inventory.yaml is the source of truth for *what Sentinel watches*. This module
reads it and upserts each entry under `assets:` into the assets table so the
health prober has something to probe. It never writes inventory.yaml — discovery
does that, additively, and only the operator promotes a discovered entry into
`assets:`.
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


async def sync(db: Database, path: Path = INVENTORY_PATH) -> dict[str, int]:
    """Upsert every confirmed asset into the DB. Returns {'assets': n}.

    Idempotent: re-running only refreshes discovered fields and last_seen. The
    operator-owned flags are preserved by assets_repo.upsert.
    """
    specs = load(path)
    for spec in specs:
        await assets_repo.upsert(db, spec)
    log.info("inventory synced", extra={"assets": len(specs)})
    return {"assets": len(specs)}
