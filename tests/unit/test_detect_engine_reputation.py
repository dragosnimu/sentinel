"""`detect/engine.py:_apply` looks up reputation once per DETECTION and splits
it into the two things the rest of the system consumes: `is_known_scanner`
(guard 5 of the decider) and `reputation` (guard 2's threshold-lowering, see
`respond/decider.py`). Each test names the operator-visible failure a wrong
split or a swallowed lookup failure would cause.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

from sentinel.detect import engine
from sentinel.detect.spec import DetectionSpec


def run(coro):
    return asyncio.run(coro)


def _spec(src_ip="198.51.100.7", severity="high"):
    return DetectionSpec(
        rule_id="auth.ssh_bruteforce", rule_family="auth", severity=severity,
        src_ip=src_ip, fingerprint=f"auth.ssh_bruteforce:{src_ip}",
        title="Brute-force SSH", summary="8 auth failures", evidence={},
        event_ids=[1])


class _FakeDB:
    """`_apply` itself never touches SQL directly — every DB call it makes
    goes through `inc_repo`/`decider`/`intel_reputation`, all monkeypatched
    below. This object only needs to exist as a placeholder to pass around."""


def _patch_common(monkeypatch, *, upsert_actor, lookup=None):
    from sentinel.db.repo import incidents as inc_repo
    from sentinel.respond import decider

    async def _false(*a, **kw):
        return False

    async def _none(*a, **kw):
        return None

    async def _record(db, **kw):
        return 1

    async def _upsert_incident(db, **kw):
        return 7, True

    async def _consider(*a, **kw):
        return "observed"

    monkeypatch.setattr(inc_repo, "actor_is_allowlisted", _false)
    monkeypatch.setattr(inc_repo, "upsert_actor", upsert_actor)
    monkeypatch.setattr(inc_repo, "record_detection", _record)
    monkeypatch.setattr(inc_repo, "upsert_incident", _upsert_incident)
    monkeypatch.setattr(inc_repo, "link_detection", _none)
    monkeypatch.setattr(inc_repo, "add_timeline", _none)
    monkeypatch.setattr(decider, "consider", _consider)
    if lookup is not None:
        from sentinel.intel import reputation as intel_reputation
        monkeypatch.setattr(intel_reputation, "lookup", lookup)


def test_scanner_category_sets_is_known_scanner_not_reputation(monkeypatch):
    """`scanner` must land ONLY in `is_known_scanner` — landing it in
    `reputation` too would make it a hostile category at the decider's guard
    2, giving a research scanner an EARLIER block instead of the protection
    it is supposed to get."""
    seen: dict = {}

    async def _upsert_actor(db, actor_key, **kw):
        seen.update(kw)

    async def _lookup(db, ip):
        return ["scanner"]

    _patch_common(monkeypatch, upsert_actor=_upsert_actor, lookup=_lookup)
    cfg = SimpleNamespace(detection=SimpleNamespace(enabled=True))
    run(engine._apply(_FakeDB(), cfg, _spec()))
    assert seen["is_known_scanner"] is True
    assert seen["reputation"] == []


def test_hostile_category_sets_reputation_not_is_known_scanner(monkeypatch):
    """A hostile category (e.g. `botnet`) must land in `reputation` and leave
    `is_known_scanner` false — the inverse mistake would suppress a block on
    an address a feed says IS attacking people, exactly backwards."""
    seen: dict = {}

    async def _upsert_actor(db, actor_key, **kw):
        seen.update(kw)

    async def _lookup(db, ip):
        return ["botnet"]

    _patch_common(monkeypatch, upsert_actor=_upsert_actor, lookup=_lookup)
    cfg = SimpleNamespace(detection=SimpleNamespace(enabled=True))
    run(engine._apply(_FakeDB(), cfg, _spec()))
    assert seen["is_known_scanner"] is False
    assert seen["reputation"] == ["botnet"]


def test_no_src_ip_never_looks_up_reputation(monkeypatch):
    """An anomaly detection (subject is an asset, not an address —
    `src_ip=None`) must not attempt a reputation lookup at all, and must pass
    `None` through, not `[]`/`False`: there is no address to have looked up,
    which is a different fact from 'looked up and found nothing'."""
    seen: dict = {}
    lookup_called = {"n": 0}

    async def _upsert_actor(db, actor_key, **kw):
        seen.update(kw)

    async def _lookup(db, ip):
        lookup_called["n"] += 1
        return ["botnet"]

    _patch_common(monkeypatch, upsert_actor=_upsert_actor, lookup=_lookup)
    cfg = SimpleNamespace(detection=SimpleNamespace(enabled=True))
    spec = DetectionSpec(
        rule_id="anomaly.volume", rule_family="anomaly", severity="high",
        src_ip=None, actor_key="host:web", fingerprint="anomaly.volume:web",
        title="Volume anomaly", summary="spike", evidence={}, event_ids=[])
    run(engine._apply(_FakeDB(), cfg, spec))
    assert lookup_called["n"] == 0
    assert seen["reputation"] is None
    assert seen["is_known_scanner"] is None


def test_a_lookup_failure_passes_none_not_a_cleared_flag(monkeypatch):
    """The bug this pins: a reputation lookup that RAISES must never be read
    as 'no reputation' — `upsert_actor` treats `None` as 'leave alone' and
    `[]`/`False` as 'overwrite with clean'. Collapsing 'the query failed' into
    '[]' would erase a real `is_known_scanner` flag on the very detection
    where a transient database error happened to occur, and the actor it was
    protecting could be auto-blocked as a side effect of an unrelated fault."""
    seen: dict = {}

    async def _upsert_actor(db, actor_key, **kw):
        seen.update(kw)

    async def _boom(db, ip):
        raise OSError("db unreachable")

    _patch_common(monkeypatch, upsert_actor=_upsert_actor, lookup=_boom)
    cfg = SimpleNamespace(detection=SimpleNamespace(enabled=True))
    run(engine._apply(_FakeDB(), cfg, _spec()))
    assert seen["reputation"] is None
    assert seen["is_known_scanner"] is None


def test_no_hostile_or_scanner_match_clears_to_empty_not_none(monkeypatch):
    """Falsifies the failure-handling test the other way: a lookup that
    SUCCEEDS and finds nothing must pass `[]`/`False`, not `None` — otherwise
    a previously-flagged actor that a feed update legitimately cleared would
    keep its stale flag forever."""
    seen: dict = {}

    async def _upsert_actor(db, actor_key, **kw):
        seen.update(kw)

    async def _lookup(db, ip):
        return []

    _patch_common(monkeypatch, upsert_actor=_upsert_actor, lookup=_lookup)
    cfg = SimpleNamespace(detection=SimpleNamespace(enabled=True))
    run(engine._apply(_FakeDB(), cfg, _spec()))
    assert seen["reputation"] == []
    assert seen["is_known_scanner"] is False
