"""The /24 proposer (sentinel/detect/cidr.py) is the only place that ever asks
the auto-block decider to consider a range instead of one address. Its guards
are pure functions precisely so a mistake in any of them shows up here, not
three weeks later as an operator's own subnet on the blocklist page.
"""

from __future__ import annotations

from sentinel.detect.cidr import (
    CIDR_MIN_DISTINCT,
    CIDR_WINDOW_HOURS,
    _overlaps_any,
    _severity_for,
    build_specs,
)


def _row(prefix="65.49.1.0/24", distinct=202, events=5000, event_ids=None, sample_ips=None):
    return {
        "prefix_cidr": prefix,
        "distinct_addrs": distinct,
        "events": events,
        "sample_ips": sample_ips or [],
        "event_ids": event_ids or [1, 2, 3],
        "country": None,
        "asn": None,
    }


# --- severity thresholds -----------------------------------------------------

def test_severity_floor_matches_the_measured_threshold():
    """The 24h window measured on the host has nothing below 3 distinct
    addresses worth an incident; below the floor this must stay silent, or a
    single opportunistic scanner pair would spam a proposal every day."""
    assert _severity_for(CIDR_MIN_DISTINCT - 1) is None
    assert _severity_for(CIDR_MIN_DISTINCT) == "high"
    assert _severity_for(202) == "critical"


# --- the operator's own most aggressive measured prefix ----------------------

def test_202_distinct_addresses_is_proposed():
    """65.49.1.0/24 (202 distinct hostile addresses, the most aggressive
    prefix measured) must produce a proposal — a detector that misses its own
    best example is not a detector."""
    specs = build_specs([_row(prefix="65.49.1.0/24", distinct=202)], protected=[])
    assert len(specs) == 1
    spec = specs[0]
    assert spec.actor_key == "65.49.1.0/24"
    assert spec.severity == "critical"
    assert spec.src_ip is None
    assert "/" in spec.fingerprint


# --- density, not volume -----------------------------------------------------

def test_single_address_with_huge_event_count_is_not_proposed():
    """A prefix with ONE hostile address and 30 000 events is a loud host, not
    a coordinated /24 — this rule counts distinct addresses, never events. A
    detector that read `events` instead would have proposed blocking the
    entire /24 around every noisy scanner on the internet."""
    specs = build_specs(
        [_row(prefix="198.51.100.0/24", distinct=1, events=30_000)], protected=[])
    assert specs == []


# --- allowlist covers the whole interval, not one address in it -------------

def test_prefix_containing_an_allowlisted_address_is_never_proposed():
    """A protected address anywhere inside the /24 must veto the whole
    proposal, however many hostile addresses the rest of the range has —
    checking only the reporting address (as `is_allowlisted` does for a single
    IP) would still fire on an operator's own subnet the moment three OTHER
    hosts in it misbehaved."""
    specs = build_specs(
        [_row(prefix="185.53.199.0/24", distinct=50, events=5000)],
        protected=["185.53.199.7/32"],
    )
    assert specs == []


def test_prefix_with_no_allowlist_overlap_is_unaffected():
    """Falsifies the allowlist guard the other way: an unrelated allowlist
    entry must not suppress a real proposal — a guard that matches everything
    would pass the previous test for the wrong reason."""
    specs = build_specs(
        [_row(prefix="185.53.199.0/24", distinct=50, events=5000)],
        protected=["86.35.255.0/24"],
    )
    assert len(specs) == 1


def test_wider_allowlisted_network_also_vetoes():
    """`overlaps()` must catch containment in both directions: an allowlisted
    /20 that swallows the candidate /24 is exactly as protective as a single
    address inside it."""
    specs = build_specs(
        [_row(prefix="185.53.199.0/24", distinct=50)],
        protected=["185.53.192.0/20"],
    )
    assert specs == []


# --- never wider than /24 ----------------------------------------------------

def test_a_wider_than_24_candidate_is_refused_even_if_it_qualifies():
    """Defense in depth against a future bug in the query that masks wider
    than /24: a /16 covers 65 536 addresses on the strength of a few dozen —
    an outage waiting to be armed, not a defense — so build_specs refuses it
    independently of what the SQL is supposed to have already enforced."""
    specs = build_specs([_row(prefix="65.49.0.0/16", distinct=202)], protected=[])
    assert specs == []


def test_an_unaligned_candidate_is_refused():
    """A network string with host bits set (e.g. a masking bug that kept the
    original host octet) is not a valid /24 and must not become a firewall
    rule for the wrong range."""
    specs = build_specs([_row(prefix="65.49.1.5/24", distinct=202)], protected=[])
    assert specs == []


# --- _overlaps_any in isolation ----------------------------------------------

def test_overlaps_any_ignores_unparsable_allowlist_rows():
    """A garbled allowlist row must not crash the whole detection pass — it is
    skipped, not fatal, the same posture as a rule that fails elsewhere in the
    engine."""
    import ipaddress

    candidate = ipaddress.ip_network("65.49.1.0/24")
    assert _overlaps_any(candidate, ["not-a-network", "65.49.1.128/25"]) is True
    assert _overlaps_any(candidate, ["not-a-network"]) is False
