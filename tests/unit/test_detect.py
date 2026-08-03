"""P4 unit tests: the pure detection logic (thresholds, specs, severity order).

The rule SQL and the incident dedup run against a real Postgres during deploy
verification; here we test the parts that decide severity and identity, which are
pure and easy to get subtly wrong.
"""

from __future__ import annotations

import pytest


def test_ssh_severity_thresholds():
    from sentinel.detect.rules import SSH_THRESHOLDS, _severity_for

    assert _severity_for(7, SSH_THRESHOLDS) is None      # below the floor
    assert _severity_for(8, SSH_THRESHOLDS) == "medium"
    assert _severity_for(25, SSH_THRESHOLDS) == "high"
    assert _severity_for(150, SSH_THRESHOLDS) == "critical"


def test_detection_spec_defaults_actor_to_ip():
    from sentinel.detect.rules import DetectionSpec

    spec = DetectionSpec(
        rule_id="auth.ssh_bruteforce", rule_family="auth", severity="medium",
        src_ip="203.0.113.9", fingerprint="auth.ssh_bruteforce:203.0.113.9",
        title="t", summary="s", evidence={}, event_ids=[],
    )
    assert spec.actor_key == "203.0.113.9"           # falls back to src_ip
    assert spec.fingerprint == "auth.ssh_bruteforce:203.0.113.9"


def test_severity_ordering():
    from sentinel.db.repo.incidents import severity_at_least

    assert severity_at_least("critical", "medium")
    assert severity_at_least("medium", "medium")
    assert not severity_at_least("low", "medium")


@pytest.mark.parametrize("count,expected", [(0, None), (8, "medium"), (200, "critical")])
def test_ssh_severity_parametrized(count, expected):
    from sentinel.detect.rules import SSH_THRESHOLDS, _severity_for

    assert _severity_for(count, SSH_THRESHOLDS) == expected
