"""What the repositories and routers hand the templates, so "AI content" has something true to show.

`test_ai_content_badge.py` proves what the templates do with a row. This file proves the rows are
built from the right columns, because a template that is correct and fed a row without
`ai_analyzed_at` looks exactly like "the model never judged anything" — the operator's original
complaint. What goes wrong if each of these fails:

* **`ai_confidence` / `ai_analyzed_at` not selected.** Every incident would read as unjudged and
  the list would show no label at all, with every test of the template still green.
* **`numeric(3,2)` left as `Decimal`.** asyncpg returns it as `Decimal`; the first place that
  multiplies it by a float raises `TypeError`, which is a 500 on the incident list.
* **A hand-built row without the new keys.** Tests and callers that predate them build bare dicts;
  they must still construct (`None`), not `KeyError`.
* **`model` not selected for plans.** Every plan would read as hand-written and carry no label.
* **The router forgets the dot colour for the AI severity.** The template reads `ai_sev_dot`; absent,
  the dot is uncoloured, which looks like a style bug and is really a missing assignment.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace

from sentinel.db.repo import incidents as inc
from sentinel.db.repo import patches

NOW = datetime(2026, 10, 5, 1, 56, tzinfo=timezone.utc)


def run(coro):
    return asyncio.run(coro)


def _db_row(**over):
    row = {
        "id": 1, "fingerprint": "f", "status": "open", "severity": "high", "title": "t",
        "summary": None, "actor_key": "1.2.3.4", "detection_count": 3,
        "first_detection_at": NOW, "last_detection_at": NOW, "ai_severity": "medium",
        "notified_at": None, "auto_action": None,
        "ai_confidence": Decimal("0.85"), "ai_analyzed_at": NOW,
    }
    row.update(over)
    return row


class _DB:
    def __init__(self, rows):
        self.rows = rows
        self.sql: list[str] = []

    async def fetch(self, sql, *a):  # noqa: ANN001, ANN002, ANN202
        self.sql.append(sql)
        # Only the incident-row query gets rows; counts and the rule chooser get nothing.
        return self.rows if "id, fingerprint, status, severity" in " ".join(sql.split()) else []

    async def fetchrow(self, sql, *a):  # noqa: ANN001, ANN002, ANN202
        self.sql.append(sql)
        return self.rows[0] if self.rows else None

    async def fetchval(self, sql, *a):  # noqa: ANN001, ANN002, ANN202
        return None


def test_the_incident_row_carries_the_judgement_as_plain_numbers():
    row = inc._incident(_db_row())
    assert row.ai_analyzed_at == NOW
    assert row.ai_confidence == 0.85 and type(row.ai_confidence) is float


def test_a_hand_built_row_without_the_ai_keys_still_constructs():
    bare = _db_row()
    del bare["ai_confidence"], bare["ai_analyzed_at"]
    row = inc._incident(bare)
    assert row.ai_confidence is None and row.ai_analyzed_at is None


def test_a_missing_confidence_stays_none_not_zero():
    row = inc._incident(_db_row(ai_confidence=None, ai_analyzed_at=None))
    assert row.ai_confidence is None and row.ai_analyzed_at is None


def test_the_list_and_the_detail_queries_select_the_judgement_columns():
    db = _DB([_db_row()])
    run(inc.list_incidents(db))
    run(inc.get_incident(db, 1))
    assert len(db.sql) == 2
    for sql in db.sql:
        assert "ai_confidence" in sql and "ai_analyzed_at" in sql, sql


def _plan_row(**over):
    row = {
        "id": 1, "plan_id": uuid.uuid4(), "plan_hash": "h", "plan": "{}", "status": "validated",
        "risk_level": "low", "requires_reboot": False, "reversible": True,
        "estimated_downtime_s": 0, "asset_id": 1, "created_at": NOW, "approved_by": None,
        "approved_at": None, "validation_errors": None,
    }
    row.update(over)
    return row


def test_a_plan_row_carries_the_model_and_a_bare_dict_still_constructs():
    assert patches._plan(_plan_row(model="claude-opus-5")).model == "claude-opus-5"
    assert patches._plan(_plan_row()).model is None, "a row predating the column must still build"
    assert patches._plan(_plan_row(model=None)).model is None


def test_the_plan_queries_select_the_model_column():
    assert "model" in [c.strip() for c in patches._PLAN_COLS.replace("\n", " ").split(",")]


# ---------------------------------------------------------------------------- the routers


class _Templates:
    def __init__(self):
        self.context = None

    def TemplateResponse(self, *, request, name, context, status_code=200):  # noqa: N802
        self.context = context
        return "rendered"


def _request(templates):
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(templates=templates)),
        state=SimpleNamespace(session=SimpleNamespace(csrf_token="t")),
        query_params={})


def test_the_incident_list_route_gives_every_row_a_dot_for_the_ai_severity():
    from sentinel.web.routers import incidents as router

    templates = _Templates()
    db = _DB([_db_row(ai_severity="critical"), _db_row(id=2, ai_severity=None, ai_analyzed_at=None,
                                                       ai_confidence=None)])
    user = SimpleNamespace(role="owner", username="op")
    run(router.incidents_page(_request(templates), user, db, status=None, sort="recent", msg=None))
    first, second = templates.context["rows"]
    assert first.ai_sev_dot == "bad", "a critical AI severity must get the red dot"
    assert second.ai_sev_dot == "off", "no AI severity means the neutral dot, not a crash"


def test_the_incident_detail_route_gives_the_incident_a_dot_for_the_ai_severity():
    from sentinel.web.routers import incidents as router

    templates = _Templates()
    db = _DB([_db_row(ai_severity="high")])
    user = SimpleNamespace(role="viewer", username="op")
    run(router.incident_detail(_request(templates), 1, user, db))
    assert templates.context["inc"].ai_sev_dot == "bad"
