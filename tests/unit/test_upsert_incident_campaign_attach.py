"""`incidents.upsert_incident` calling into the campaign layer.

Detection is the vital path; campaign grouping is a reading convenience
layered on top of it (see `CLAUDE.md` and `campaigns.py`'s module docstring).
Each test names the way that boundary breaks if it is not held: a grouping
failure taking the incident down with it, or the wrong key ever reaching the
campaign layer.
"""

from __future__ import annotations

import asyncio
import logging

from sentinel.db.repo import incident_campaigns as camp_repo
from sentinel.db.repo import incidents as inc_repo


def run(coro):
    return asyncio.run(coro)


class _FakeDB:
    """Only `upsert_incident`'s own INSERT touches the db directly —
    `attach_incident` is monkeypatched below, so this never needs a
    `transaction()`."""

    def __init__(self, row):
        self._row = row
        self.fetchrow_calls = 0

    async def fetchrow(self, sql, *args):
        self.fetchrow_calls += 1
        return self._row


def _kwargs(**over):
    kw = dict(fingerprint="auth.ssh_bruteforce:198.51.100.7", severity="high",
              title="Brute-force SSH", summary="8 auth failures",
              actor_key="198.51.100.7", asset_id=None)
    kw.update(over)
    return kw


def test_upsert_incident_survives_a_campaign_attach_failure(monkeypatch, caplog):
    """Before the try/except, a raise here propagated out of `upsert_incident`
    and the caller (`detect/engine.py:_apply`) never got the incident id it
    needed to link the detection and push to Telegram — a detection lost
    because grouping failed, which is exactly the outcome the docstring says
    must never happen."""
    async def _boom(db, incident_id, rule_family, severity):
        raise RuntimeError("campaign attach exploded")
    monkeypatch.setattr(camp_repo, "attach_incident", _boom)

    caplog.set_level(logging.WARNING, logger="sentinel.db.repo.incidents")
    db = _FakeDB({"id": 42, "is_new": True})
    incident_id, is_new = run(inc_repo.upsert_incident(db, **_kwargs()))

    assert (incident_id, is_new) == (42, True)
    assert any("campaign attach failed" in r.message for r in caplog.records)


def test_upsert_incident_passes_the_rule_family_not_the_full_fingerprint(monkeypatch):
    """The campaign key is the family — the part of `fingerprint` before the
    first `:` — not the whole fingerprint. The fingerprint is unique per
    actor (`auth.ssh_bruteforce:198.51.100.7`); passed whole, every actor
    would start its own one-member campaign and nothing would ever group."""
    seen = {}

    async def _record(db, incident_id, rule_family, severity):
        seen["args"] = (incident_id, rule_family, severity)
        return 1
    monkeypatch.setattr(camp_repo, "attach_incident", _record)

    db = _FakeDB({"id": 42, "is_new": True})
    run(inc_repo.upsert_incident(db, **_kwargs(
        fingerprint="auth.ssh_bruteforce:198.51.100.7")))

    assert seen["args"] == (42, "auth.ssh_bruteforce", "high")


def test_upsert_incident_still_returns_the_incident_when_attach_succeeds(monkeypatch):
    """The happy path must not regress: a successful attach must not change
    what the caller receives."""
    async def _ok(db, incident_id, rule_family, severity):
        return 9
    monkeypatch.setattr(camp_repo, "attach_incident", _ok)

    db = _FakeDB({"id": 5, "is_new": False})
    result = run(inc_repo.upsert_incident(db, **_kwargs()))
    assert result == (5, False)
