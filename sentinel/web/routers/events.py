"""The Events page: normalised events in near real time, with light filtering.

Everything shown here below the source column is attacker-controlled — usernames,
paths, user-agents. Jinja autoescaping (on for every template) is what keeps a
crafted path like `<script>` from executing in the operator's browser: it is
displayed as text, which is the whole point of collecting it. No value from an
event is ever put anywhere but escaped text.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse

from sentinel.db.engine import Database
from sentinel.db.repo import events as events_repo
from sentinel.db.repo import users as users_repo
from sentinel.logging_setup import get_logger
from sentinel.model.event import ACTIONS, SOURCES
from sentinel.web.deps import current_user, get_db

log = get_logger(__name__)
router = APIRouter()

_ACTION_CLASS = {
    "auth_fail": "bad", "deny": "bad", "error": "bad", "alert": "bad",
    "auth_ok": "ok", "accept": "ok",
}


@router.get("/events")
async def events_page(
    request: Request,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
    source: str | None = Query(None),
    action: str | None = Query(None),
    ip: str | None = Query(None),
    window: int = Query(60, ge=1, le=1440),
) -> Response:
    # Reject filter values that are not in the known vocabularies rather than
    # passing arbitrary text into a query — the SQL is parameterised regardless,
    # but an unknown source or action can only be a mistake or a probe.
    source = source if source in SOURCES else None
    action = action if action in ACTIONS else None

    rows = await events_repo.recent(
        db, limit=200, source=source, action=action, src_ip=ip, since_minutes=window
    )
    for r in rows:
        r["action_class"] = _ACTION_CLASS.get(r["action"], "")
    summary = await events_repo.summary(db, since_minutes=window)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="events.html",
        context={
            "user": user,
            "active": "events",
            "rows": rows,
            "summary": summary,
            "sources": SOURCES,
            "filter": {"source": source, "action": action, "ip": ip, "window": window},
        },
    )


@router.get("/api/events")
async def events_api(
    request: Request,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
    window: int = Query(60, ge=1, le=1440),
) -> Response:
    summary = await events_repo.summary(db, since_minutes=window)
    return JSONResponse(summary, headers={"Cache-Control": "no-store"})
