"""The asset inventory: every service, container, site and host Sentinel watches.

Discovery proposes rows; the operator confirms them in inventory.yaml. This module
only reads and writes — it never decides what is worth monitoring or scanning.
Two flags carry weight and are set by a human, never by discovery:

* ``protected`` — no automated patch plan may target it (also enforced in
  patch/validator.py, not only here).
* ``confirmed_by_operator`` — required before active DAST scanning; discovery
  finding a service is not authorisation to attack it.

A third piece of state is not a flag but a consequence: ``retired_at``. It is
set when an asset disappears from inventory.yaml, and it is the reason
``list_all`` is the single door every consumer goes through — see there.
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
    # `repo_path`, `repo_branch` si `repo_remote` exista in tabela din 0001 dar
    # NU sunt aici, nu sunt in `_COLUMNS` si nu sunt scrise de `upsert`. Pe
    # 30 august 2026 au fost scoase si din `inventory.yaml.example`, fiindca
    # `_ALLOWED` le respinge: un exemplu care sugereaza chei pe care
    # incarcatorul le refuza opreste tacut aplicarea intregului inventar.
    #
    # Ce ramane, si merita stiut inainte sa le adauge cineva: dosarul de
    # incident LE CITESTE (`.claude/skills/sentinel-soc/scripts/`), deci azi
    # coloana e lizibila si nescriibila — apare mereu goala. Nu e o scapare, e
    # o functionalitate necoborata: cine o vrea trebuie sa decida intai ce plan
    # de patch foloseste un `repo_remote` si cum se valideaza, nu doar sa
    # adauge trei nume in doua liste.
    stack: str | None
    databases: list[dict[str, Any]]
    protected: bool
    confirmed_by_operator: bool
    tags: list[str]
    notes: str | None
    first_seen: datetime
    last_seen: datetime

    # NULL while the asset is listed in inventory.yaml; the moment it stopped
    # being listed otherwise. Defaulted so that the many places which build an
    # Asset from a spec (tests, fixtures) keep meaning "watched" without saying
    # so. See retire_missing.
    retired_at: datetime | None = None

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
    first_seen, last_seen, retired_at
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
        retired_at=data["retired_at"],
    )


async def list_all(
    db: Database,
    *,
    include_protected: bool = True,
    include_retired: bool = False,
) -> list[Asset]:
    """Every asset Sentinel currently watches, most critical first.

    Retired assets are excluded by default, and that default is the whole
    mechanism: this query is the only door the health prober, the Services page
    and the Telegram summary go through, so an asset the operator deleted from
    inventory.yaml stops being probed and stops being counted without any of
    the three having to learn that retirement exists. Making the exclusion
    opt-in instead would mean three separate places to forget it in.

    `include_retired=True` is for reading history — the rows are still there,
    with their ids, and so is everything that hangs off them.
    """
    clauses: list[str] = []
    if not include_protected:
        clauses.append("NOT protected")
    if not include_retired:
        clauses.append("retired_at IS NULL")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = await db.fetch(f"SELECT {_COLUMNS} FROM assets {where} ORDER BY criticality DESC, name")
    return [_row_to_asset(r) for r in rows]


async def get_by_name(db: Database, name: str) -> Asset | None:
    # Deliberately does not filter on retired_at: a lookup by name is how you
    # ask about a specific asset, including one that is gone. Read `retired_at`
    # on the result if you need to know which it is.
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

    `retired_at` is cleared on UPDATE, and that is the opposite of preserving:
    it is not the operator's intent stored in the row, it is a consequence of
    the file, and being in the file again is the operator saying "watch this".
    The id does not change, so an asset put back after a mistaken removal comes
    back attached to every incident, finding and sample it ever had.
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
                last_seen           = now(),
                retired_at          = NULL
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


async def retire_missing(db: Database, keep: list[str]) -> list[str]:
    """Retire every asset whose name is not in `keep`. Returns the names retired.

    Retired, not deleted: the row stays, keeps its id, and everything hanging
    off that id stays queryable. `0032_assets_retired.sql` lists what a DELETE
    would cost, table by table — findings and outages vanish, incidents survive
    as orphans, health_samples has no foreign key at all and would simply be
    left behind.

    `keep` must not be empty. "Retire everything" is not something a caller
    ever means; it is what an unreadable or truncated inventory.yaml looks like
    from in here, and it would switch off every probe on the host in silence.
    The guard sits next to the statement that would do it, not only in the
    caller, because this is the statement.

    Returns the names rather than a count, and `retired_at IS NULL` keeps the
    UPDATE off rows that were already retired, so what comes back is the set of
    assets that actually changed on this run — the observable effect, not the
    size of the request. That is what the caller logs.
    """
    if not keep:
        raise ValueError(
            "retire_missing refuses an empty keep list: it would retire every asset"
        )
    rows = await db.fetch(
        """
        UPDATE assets
           SET retired_at = now()
         WHERE retired_at IS NULL
           AND name <> ALL($1::text[])
        RETURNING name
        """,
        list(keep),
    )
    return [r["name"] for r in rows]
