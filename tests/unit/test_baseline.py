"""The baseline math is the whole point of P6.2 — if the robust z is wrong, the
anomaly rule is wrong. Pure functions, pinned hard. No DB.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sentinel.predict import baseline as bl


def test_hour_of_week_monday_midnight_is_zero():
    # 2026-07-27 is a Monday.
    assert bl.hour_of_week(datetime(2026, 7, 27, 0, 0, tzinfo=timezone.utc)) == 0


def test_hour_of_week_spans_the_week():
    # Monday 14:00 -> 14; Sunday 23:00 -> 6*24 + 23 = 167 (the last bucket).
    assert bl.hour_of_week(datetime(2026, 7, 27, 14, 0)) == 14
    assert bl.hour_of_week(datetime(2026, 8, 2, 23, 0)) == 167  # a Sunday


def test_robust_z_zero_at_median():
    assert bl.robust_z(10.0, 10.0, 5.0) == 0.0


def test_robust_z_positive_above_median():
    z = bl.robust_z(40.0, 10.0, 5.0)
    assert z > 0
    # 0.6745 * (40-10) / 5 = 4.047
    assert round(z, 2) == 4.05


def test_robust_z_mad_floor_keeps_it_finite():
    # MAD 0 must not divide-by-zero; the floor of 1.0 applies.
    z = bl.robust_z(5.0, 0.0, 0.0)
    assert z == 0.6745 * 5.0 / 1.0


def test_summarize_median_mad_ewma():
    med, mad, ewma = bl.summarize([10, 10, 10, 10])
    assert med == 10
    assert mad == 0
    assert ewma == 10  # constant series


def test_summarize_mad_is_robust_to_a_spike():
    # One huge value barely moves the median; the mean would be wrecked.
    med, mad, ewma = bl.summarize([10, 10, 10, 10, 1000])
    assert med == 10
    assert mad == 0  # median abs deviation of mostly-10s is 0


def test_severity_for_z_bands():
    from sentinel.detect.rules import _severity_for_z
    assert _severity_for_z(2.0) is None
    assert _severity_for_z(3.5) == "medium"
    assert _severity_for_z(5.0) == "high"
    assert _severity_for_z(9.0) == "critical"


# --- F04: outbound-volume metric wired into the existing engine ------------
def test_outbound_metric_is_registered_on_the_conntrack_source():
    """`detect/rules.volume_anomaly` iterates `bl.METRICS` generically — if
    this metric isn't in the tuple, F04's volume signal silently never runs,
    with no error anywhere to say so."""
    names = {m.name: m for m in bl.METRICS}
    assert "outbound_connections_per_min" in names
    metric = names["outbound_connections_per_min"]
    assert metric.source == "conntrack"
    assert metric.action == "connect"
