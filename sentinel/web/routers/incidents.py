"""The Incidents page: what detection raised, one detail view, and the actions
that close them.

Closing is not deletion — the row keeps its evidence and timeline, and every
change is written to `incident_timeline` with who did it. If the same actor
trips the same rule again a NEW incident is raised rather than the closed one
reopening quietly, because something you closed coming back is itself worth
seeing.

Only owner/operator may change status; a viewer reads. Incident titles and
summaries contain attacker-chosen text (usernames tried, paths probed) — Jinja
autoescaping renders all of it as text.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Query, Request, Response
from fastapi.responses import RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from sentinel.db.engine import Database
from sentinel.db.repo import incidents as inc_repo
from sentinel.db.repo import users as users_repo
from sentinel.logging_setup import get_logger
from sentinel.web.deps import current_user, get_db

log = get_logger(__name__)
router = APIRouter()

_SEV_DOT = {"info": "off", "low": "off", "medium": "warn", "high": "bad", "critical": "bad"}

# What each status is called on screen, and what closing it means.
STATUS_RO = {
    "open": "deschis",
    "acknowledged": "confirmat",
    "resolved": "rezolvat",
    "false_positive": "fals-pozitiv",
    "suppressed": "suprimat",
}


def _can_act(user: users_repo.User) -> bool:
    return user.role in ("owner", "operator")


@router.get("/incidents")
async def incidents_page(
    request: Request,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
    status: str | None = Query(None),
    sort: str = Query(inc_repo.DEFAULT_SORT),
    msg: str | None = Query(None),
) -> Response:
    status = status if status in ("open", "acknowledged", "resolved", "false_positive") else None
    sort = sort if sort in inc_repo.SORTS else inc_repo.DEFAULT_SORT
    rows = await inc_repo.list_incidents(db, status=status, limit=100, sort=sort)
    counts = await inc_repo.open_counts(db)
    for r in rows:
        r.sev_dot = _SEV_DOT.get(r.severity, "off")  # type: ignore[attr-defined]

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="incidents.html",
        context={"user": user, "active": "incidents", "rows": rows,
                 "counts": counts, "filter_status": status, "sort": sort,
                 "sorts": inc_repo.SORTS, "status_ro": STATUS_RO,
                 "can_act": _can_act(user), "msg": msg,
                 "open_rules": await inc_repo.open_rules(db),
                 "csrf_token": request.state.session.csrf_token},
    )


@router.get("/incidents/{incident_id}")
async def incident_detail(
    request: Request,
    incident_id: int,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
) -> Response:
    inc = await inc_repo.get_incident(db, incident_id)
    if inc is None:
        raise StarletteHTTPException(status_code=404, detail="Incident inexistent")
    templates = request.app.state.templates
    detections = await inc_repo.incident_detections(db, incident_id, limit=30)
    verdict = await inc_repo.get_ai_verdict(db, incident_id)
    inc.sev_dot = _SEV_DOT.get(inc.severity, "off")  # type: ignore[attr-defined]
    return templates.TemplateResponse(
        request=request,
        name="incident.html",
        context={"user": user, "active": "incidents", "inc": inc,
                 "detections": detections, "verdict": verdict,
                 "status_ro": STATUS_RO, "can_act": _can_act(user),
                 "csrf_token": request.state.session.csrf_token},
    )


@router.post("/incidents/{incident_id}/status")
async def change_status(
    incident_id: int,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
    status: Annotated[str, Form()] = "",
    note: Annotated[str, Form()] = "",
) -> Response:
    back = f"/incidents/{incident_id}"
    if not _can_act(user):
        return RedirectResponse(f"{back}?msg=Necesită+rol+operator", status_code=303)
    ok = await inc_repo.set_status(
        db, incident_id, status, by=f"web:{user.username}", note=(note.strip() or None))
    if not ok:
        return RedirectResponse(f"{back}?msg=Stare+invalidă", status_code=303)
    log.info("incident status changed",
             extra={"incident_id": incident_id, "status": status, "by": user.username})
    return RedirectResponse(f"{back}?msg=Stare+actualizată", status_code=303)


@router.post("/incidents/bulk-close")
async def bulk_close(
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
    rule: Annotated[str, Form()] = "",
    status: Annotated[str, Form()] = "resolved",
    older_than_hours: Annotated[int, Form()] = 0,
) -> Response:
    if not _can_act(user):
        return RedirectResponse("/incidents?msg=Necesită+rol+operator", status_code=303)
    if not rule:
        return RedirectResponse("/incidents?msg=Alege+o+regulă", status_code=303)
    n = await inc_repo.bulk_close(
        db, rule=rule, status=status, by=f"web:{user.username}",
        older_than_hours=max(0, older_than_hours),
        note=f"închise în masă din interfață ({rule})")
    log.warning("incidents bulk-closed",
                extra={"rule": rule, "status": status, "count": n, "by": user.username})
    return RedirectResponse(f"/incidents?msg={n}+incidente+închise", status_code=303)
