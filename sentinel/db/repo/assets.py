"""The asset inventory: every service, container, site and host Sentinel watches.

Discovery proposes rows; the operator confirms them in inventory.yaml. This module
only reads and writes — it never decides what is worth monitoring or scanning.
Two flags carry weight and are set by a human, never by discovery:

* ``protected`` — no automated patch plan may target it (also enforced in
  patch/validator.py, not only here).
* ``confirmed_by_operator`` — required before active DAST scanning; discovery
  finding a service is not authorisation to attack it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sentinel.db.engine import Database

KINDS = ("web", "service", "container", "database", "host")


@dataclass
class Asset:
    id: int
    name: str
    kind: str
    bind_addr: str | None
    port: int | None
    is_internet_exposed: bool
    criticality: int
    systemd_unit: str | None
    container_id: str | None
    container_image: str | None
    vhost_file: str | None
    webroot: str | None
    stack: str | None
    databases: list[dict[str, Any]]
    protected: bool
    confirmed_by_operator: bool
    tags: list[str]
    notes: str | None
    first_seen: datetime
    last_seen: datetime

    # How this asset should be probed for availability. Derived, not stored:
    # a systemd service is checked with `systemctl is-active`, a container with
    # `docker inspect`, a listening port with a TCP connect, a web asset with an
    # HTTP request. See health/prober.py.
    @property
    def probe_kind(self) -> str:
        if self.kind == "web":
            return "http"
        if self.kind == "container":
            return "docker"
        if self.kind == "database":
            return "tcp"
        if self.systemd_unit:
            return "systemd"
        if self.port:
            return "tcp"
        return "unknown"


_COLUMNS = """
    id, name, kind, host(bind_addr) AS bind_addr, port, is_internet_exposed,
    criticality, systemd_unit, container_id, container_image, vhost_file,
    webroot, stack, databases, protected, confirmed_by_operator, tags, notes,
    first_seen, last_seen
"""


def _row_to_asset(row: Any) -> Asset:
    data = dict(row)
    databases = data["databases"]
    if isinstance(databases, str):
        databases = json.loads(databases)
    return Asset(
        id=data["id"],
        name=data["name"],
        kind=data["kind"],
        bind_addr=data["bind_addr"],
        port=data["port"],
        is_internet_exposed=data["is_internet_exposed"],
        criticality=data["criticality"],
        systemd_unit=data["systemd_unit"],
        container_id=data["container_id"],
        container_image=data["container_image"],
        vhost_file=data["vhost_file"],
        webroot=data["webroot"],
        stack=data["stack"],
        databases=list(databases or []),
        protected=data["protected"],
        confirmed_by_operator=data["confirmed_by_operator"],
        tags=list(data["tags"] or []),
        notes=data["notes"],
        first_seen=data["first_seen"],
        last_seen=data["last_seen"],
    )


async def list_all(db: Database, *, include_protected: bool = True) -> list[Asset]:
    where = "" if include_protected else "WHERE NOT protected"
    rows = await db.fetch(f"SELECT {_COLUMNS} FROM assets {where} ORDER BY criticality DESC, name")
    return [_row_to_asset(r) for r in rows]


async def get_by_name(db: Database, name: str) -> Asset | None:
    row = await db.fetchrow(f"SELECT {_COLUMNS} FROM assets WHERE name = $1", name)
    return _row_to_asset(row) if row else None


async def count(db: Database) -> int:
    return int(await db.fetchval("SELECT count(*) FROM assets") or 0)


async def upsert(db: Database, spec: dict[str, Any]) -> int:
    """Insert or update an asset by its unique name.

    `last_seen` always moves forward; `first_seen` is preserved. The
    operator-owned flags (protected, confirmed_by_operator, criticality, notes)
    are only set on INSERT — a re-sync from inventory.yaml or discovery must not
    silently un-protect an asset or revoke a scan authorisation. To change those,
    edit inventory.yaml (which is applied explicitly) or the row directly.
    """
    databases = json.dumps(spec.get("databases", []))
    tags = list(spec.get("tags", []))
    return int(
        await db.fetchval(
            """
            INSERT INTO assets (
                name, kind, bind_addr, port, is_internet_exposed, criticality,
                systemd_unit, container_id, container_image, vhost_file, webroot,
                stack, databases, protected, confirmed_by_operator, tags, notes
            ) VALUES (
                $1, $2, $3::inet, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                $13::jsonb, $14, $15, $16, $17
            )
            ON CONFLICT (name) DO UPDATE SET
                kind                = EXCLUDED.kind,
                bind_addr           = EXCLUDED.bind_addr,
                port                = EXCLUDED.port,
                is_internet_exposed = EXCLUDED.is_internet_exposed,
                systemd_unit        = EXCLUDED.systemd_unit,
                container_id        = EXCLUDED.container_id,
                container_image     = EXCLUDED.container_image,
                vhost_file          = EXCLUDED.vhost_file,
                webroot             = EXCLUDED.webroot,
                stack               = EXCLUDED.stack,
                databases           = EXCLUDED.databases,
                tags                = EXCLUDED.tags,
                last_seen           = now()
            RETURNING id
            """,
            spec["name"],
            spec.get("kind", "service"),
            spec.get("bind_addr"),
            spec.get("port"),
            bool(spec.get("is_internet_exposed", False)),
            int(spec.get("criticality", 3)),
            spec.get("systemd_unit"),
            spec.get("container_id"),
            spec.get("container_image"),
            spec.get("vhost_file"),
            spec.get("webroot"),
            spec.get("stack"),
            databases,
            bool(spec.get("protected", False)),
            bool(spec.get("confirmed_by_operator", False)),
            tags,
            spec.get("notes"),
        )
    )
