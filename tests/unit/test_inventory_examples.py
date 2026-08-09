"""The shipped inventory examples must be loadable and probeable.

An example inventory is copied by hand into `/etc/sentinel/inventory.yaml`. Two
things go wrong there, and neither announces itself:

* a key the loader rejects makes `inventory.load` raise. `health_service`
  catches that, logs it and keeps probing the assets it already has — so the
  operator's edit appears to do nothing at all, with no error in front of them.
* an asset with no probe method (`kind: host`, or a database whose container
  never published a port) probes as `unknown`, and `unknown` is counted with
  `down` in `prober.probe_all`. After `health.down_after_failures` samples an
  outage opens, and it only closes on an `up` sample that can never arrive.
  The operator gets a permanently red row and learns to ignore the page.

These tests read the example files as they ship, through the real loader and
the real `probe_kind` property — not through a copy of either.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel.db.repo.assets import KINDS, Asset
from sentinel.scan import inventory

REPO = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO / "deploy" / "config"

# The example that is deliberately near-empty (installed as the starting point)
# and the one that is deliberately filled in (read, not installed).
TEMPLATE = CONFIG_DIR / "inventory.yaml.example"
FILLED = CONFIG_DIR / "inventory-filled.yaml.example"

EXAMPLES = sorted(CONFIG_DIR.glob("inventory*.yaml.example"))


def test_both_inventory_examples_are_present() -> None:
    """A parametrised list that came out empty would skip every check below.

    This repository has already shipped a test that passed because its
    parameter list was empty. If an example is renamed again, this fails loudly
    instead of the suite quietly checking nothing.
    """
    assert EXAMPLES == sorted([FILLED, TEMPLATE]), (
        "expected exactly the two inventory examples, found: "
        + ", ".join(p.name for p in EXAMPLES))


def _asset(spec: dict) -> Asset:
    """Build the runtime Asset from an inventory spec, defaults and all.

    Uses the real dataclass so `probe_kind` is the production decision, not a
    re-implementation of it in a test.
    """
    now = datetime.now(timezone.utc)
    return Asset(
        id=0,
        name=spec["name"],
        kind=spec.get("kind", "service"),
        bind_addr=spec.get("bind_addr"),
        port=spec.get("port"),
        is_internet_exposed=bool(spec.get("is_internet_exposed", False)),
        criticality=int(spec.get("criticality", 3)),
        systemd_unit=spec.get("systemd_unit"),
        container_id=spec.get("container_id"),
        container_image=spec.get("container_image"),
        vhost_file=spec.get("vhost_file"),
        webroot=spec.get("webroot"),
        stack=spec.get("stack"),
        databases=list(spec.get("databases") or []),
        protected=bool(spec.get("protected", False)),
        confirmed_by_operator=bool(spec.get("confirmed_by_operator", False)),
        tags=list(spec.get("tags") or []),
        notes=spec.get("notes"),
        first_seen=now,
        last_seen=now,
    )


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_loads_through_the_real_loader(path: Path) -> None:
    """An example the loader rejects is an edit that silently does nothing.

    `inventory.load` is the same function the health service calls. If it
    raises on a file we ship as a model, whoever copies it gets an inventory
    that never reaches the assets table.
    """
    specs = inventory.load(path)
    assert specs, f"{path.name}: no assets, so nothing below is being checked"


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_assets_satisfy_the_database_constraints(path: Path) -> None:
    """A CHECK violation surfaces as a failed sync, not as a message to read.

    `assets.kind` and `assets.criticality` are constrained in 0001_core.sql. A
    value the schema refuses turns the operator's inventory into a log line.
    """
    bad: list[str] = []
    for spec in inventory.load(path):
        if spec.get("kind", "service") not in KINDS:
            bad.append(f"{spec['name']}: kind={spec.get('kind')!r} not in {KINDS}")
        crit = spec.get("criticality", 3)
        if not (isinstance(crit, int) and 1 <= crit <= 5):
            bad.append(f"{spec['name']}: criticality={crit!r} outside 1..5")
        port = spec.get("port")
        if port is not None and not (isinstance(port, int) and 1 <= port <= 65535):
            bad.append(f"{spec['name']}: port={port!r} outside 1..65535")
    assert not bad, f"{path.name}:\n  " + "\n  ".join(bad)


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_no_example_asset_is_unprobeable(path: Path) -> None:
    """An unprobeable asset teaches the operator to build a permanent outage.

    `probe_kind == "unknown"` means the prober has no method for the asset. The
    sample is recorded as `unknown`, counted with `down`, and after
    `health.down_after_failures` of them an outage opens that no probe can ever
    close. One such row on the Services page is how a monitoring page stops
    being read.
    """
    unprobeable = [spec["name"] for spec in inventory.load(path)
                   if _asset(spec).probe_kind == "unknown"]
    assert not unprobeable, (
        f"{path.name}: assets with no probe method: {', '.join(unprobeable)}")


def test_the_filled_example_still_exercises_every_probe_method() -> None:
    """The filled example is the only place all four probe paths are shown.

    It exists to be read. If a rewrite drops the container or the unit-less
    service, the file stops documenting the branch it was kept for, and the
    next operator writes `kind: service` with no port and wonders why the
    dashboard says nothing.
    """
    seen = {_asset(spec).probe_kind for spec in inventory.load(FILLED)}
    missing = {"http", "systemd", "tcp", "docker"} - seen
    assert not missing, (
        f"{FILLED.name} no longer covers: {', '.join(sorted(missing))}")
