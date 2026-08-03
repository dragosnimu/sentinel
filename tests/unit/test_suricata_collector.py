"""The eve.json collector keeps alerts and drops the flow/stats firehose. If it
let non-alert records through, the partitions would fill with traffic metadata
that has no security value. Pinned here.
"""
from __future__ import annotations

import json

from sentinel.collectors.suricata_eve import parse_suricata

_ALERT = json.dumps({
    "timestamp": "2026-07-31T12:00:00.123456+0000",
    "event_type": "alert",
    "src_ip": "203.0.113.9", "src_port": 51514,
    "dest_ip": "203.0.113.10", "dest_port": 443,
    "proto": "TCP", "app_proto": "tls",
    "alert": {"signature": "ET SCAN Suspicious inbound", "signature_id": 2000123,
              "category": "Attempted Information Leak", "severity": 1, "action": "allowed"},
})


def test_alert_becomes_event():
    ev = parse_suricata(_ALERT)
    assert ev is not None
    assert ev.source == "suricata" and ev.action == "alert"
    assert ev.src_ip == "203.0.113.9" and ev.dst_port == 443
    assert ev.raw["signature"] == "ET SCAN Suspicious inbound"
    assert ev.raw["severity"] == 1


def test_flow_record_is_dropped():
    flow = json.dumps({"timestamp": "2026-07-31T12:00:00+0000", "event_type": "flow",
                       "src_ip": "1.2.3.4"})
    assert parse_suricata(flow) is None


def test_stats_record_is_dropped():
    assert parse_suricata(json.dumps({"event_type": "stats", "timestamp": "2026-07-31T12:00:00+0000"})) is None


def test_garbage_and_empty_are_ignored():
    assert parse_suricata("") is None
    assert parse_suricata("not json at all") is None
    assert parse_suricata("[]") is None  # valid JSON, wrong shape


def test_missing_timestamp_is_dropped():
    assert parse_suricata(json.dumps({"event_type": "alert", "alert": {"severity": 1}})) is None


def test_timestamp_with_colon_offset_also_parses():
    line = json.dumps({"timestamp": "2026-07-31T12:00:00+00:00", "event_type": "alert",
                       "src_ip": "9.9.9.9", "alert": {"signature": "x", "severity": 2}})
    ev = parse_suricata(line)
    assert ev is not None and ev.src_ip == "9.9.9.9"


def test_suricata_rule_is_wired_into_the_engine():
    # A collector with no rule behind it silently drops the whole source.
    from sentinel.detect.rules import RULES, suricata_alert
    assert suricata_alert in RULES


def test_suricata_severity_mapping():
    from sentinel.detect.rules import _SURICATA_SEV
    # 1 is the most severe in Suricata; 3 (informational) must not raise.
    assert _SURICATA_SEV.get(1) == "high"
    assert _SURICATA_SEV.get(2) == "medium"
    assert _SURICATA_SEV.get(3) is None


def test_reputational_alerts_need_repeat_hits():
    """A severity-2 signature is often "this source is on a block list", not an
    attack. One hit produced 485 open incidents on the live host and buried
    everything else; a severity-1 exploit attempt still raises immediately."""
    from sentinel.detect.rules import SURICATA_MIN_HITS
    assert SURICATA_MIN_HITS[1] == 1      # real exploit attempt: raise at once
    assert SURICATA_MIN_HITS[2] >= 3      # reputational: needs a pattern
