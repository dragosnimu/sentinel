"""P2 unit tests: the pure logic that does not need a database.

The DB-backed queries (live_status, sparkline SQL, rollups) are exercised on a
real Postgres during deploy verification; here we test the parts that are pure
Python and easy to get subtly wrong: sparkline geometry, inventory validation,
capacity sampling, and the probe-kind decision.
"""

from __future__ import annotations

import os

import pytest


# --- sparkline geometry ----------------------------------------------------
def test_sparkline_skips_gap_buckets():
    from sentinel.web.routers.services import _sparkline_points

    buckets = [{"up": 100.0}, {"up": None}, {"up": 50.0}, {"up": 0.0}]
    points, gaps = _sparkline_points(buckets, width=300, height=30)
    coords = [p.split(",") for p in points.split()]

    assert gaps is True                       # the None bucket is a gap
    assert len(coords) == 3                    # only the three real samples plotted
    # 100% maps to the top (y=0), 0% to the bottom (y=height).
    assert float(coords[0][1]) == pytest.approx(0.0)
    assert float(coords[-1][1]) == pytest.approx(30.0)


def test_sparkline_empty_is_safe():
    from sentinel.web.routers.services import _sparkline_points

    assert _sparkline_points([]) == ("", False)


# --- inventory loading + validation ---------------------------------------
def _write(tmp_path, text: str):
    p = tmp_path / "inventory.yaml"
    p.write_text(text, encoding="utf-8")
    os.environ["SENTINEL_INVENTORY"] = str(p)
    return p


def test_inventory_loads_valid_assets(tmp_path):
    import importlib

    _write(tmp_path, """
assets:
  - name: sentinel.web
    kind: web
    port: 8787
    protected: true
  - name: sshd
    kind: service
    port: 22
""")
    inv = importlib.reload(__import__("sentinel.scan.inventory", fromlist=["x"]))
    specs = inv.load(inv.INVENTORY_PATH)
    assert {s["name"] for s in specs} == {"sentinel.web", "sshd"}


def test_inventory_rejects_unknown_keys(tmp_path):
    from sentinel.scan import inventory

    p = _write(tmp_path, """
assets:
  - name: x
    kind: service
    bogus_field: 1
""")
    with pytest.raises(ValueError, match="unknown keys"):
        inventory.load(p)


def test_inventory_requires_a_name(tmp_path):
    from sentinel.scan import inventory

    p = _write(tmp_path, """
assets:
  - kind: service
    port: 22
""")
    with pytest.raises(ValueError, match="needs at least a 'name'"):
        inventory.load(p)


def test_inventory_missing_file_is_empty(tmp_path):
    from sentinel.scan import inventory

    assert inventory.load(tmp_path / "nope.yaml") == []


# --- probe-kind decision ---------------------------------------------------
def _asset(**kw):
    from datetime import datetime, timezone

    from sentinel.db.repo.assets import Asset

    base = dict(
        id=1, name="x", kind="service", bind_addr=None, port=None,
        is_internet_exposed=False, criticality=3, systemd_unit=None,
        container_id=None, container_image=None, vhost_file=None, webroot=None,
        stack=None, databases=[], protected=False, confirmed_by_operator=False,
        tags=[], notes=None, first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    base.update(kw)
    return Asset(**base)


def test_probe_kind_by_asset_shape():
    assert _asset(kind="web", port=8787).probe_kind == "http"
    assert _asset(kind="container", container_id="abc").probe_kind == "docker"
    assert _asset(kind="database", port=5432).probe_kind == "tcp"
    assert _asset(kind="service", systemd_unit="sshd.service").probe_kind == "systemd"
    assert _asset(kind="service", port=22).probe_kind == "tcp"
    assert _asset(kind="service").probe_kind == "unknown"


# --- capacity sampling -----------------------------------------------------
def test_capacity_sample_has_the_expected_shape():
    from sentinel.health import capacity

    s = capacity.sample()
    for key in ("cpu_pct", "mem_total_mb", "mem_available_mb", "disk_used_pct",
                "disks", "per_service_rss"):
        assert key in s
    assert isinstance(s["disks"], dict)
    assert isinstance(s["per_service_rss"], dict)
    assert s["mem_total_mb"] is None or s["mem_total_mb"] > 0
