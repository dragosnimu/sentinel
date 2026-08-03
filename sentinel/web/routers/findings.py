"""The Findings page: what the scanners found, ranked by priority.

Read-only. Titles/descriptions come from scanner output and vendor advisories;
Jinja autoescaping renders all of it as text. Applying a fix is the patch
pipeline (P9), never a click here.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from sentinel.db.engine import Database
from sentinel.db.repo import findings as fx
from sentinel.db.repo import users as users_repo
from sentinel.logging_setup import get_logger
from sentinel.web.deps import current_user, get_db

log = get_logger(__name__)
router = APIRouter()

_SEV_DOT = {"info": "off", "low": "off", "medium": "warn", "high": "bad", "critical": "bad"}


@router.get("/findings")
async def findings_page(
    request: Request,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
) -> Response:
    rows = await fx.list_open(db, limit=200)
    counts = await fx.open_counts(db)
    for r in rows:
        r["sev_dot"] = _SEV_DOT.get(r["severity"], "off")
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="findings.html",
        context={"user": user, "active": "findings", "rows": rows, "counts": counts},
    )
