"""The Blocklist page: what is blocked, and an unblock action.

Deliberately asymmetric. Unblocking is offered here — it can only ever *restore*
access, so the worst case is that an attacker is no longer blocked, never that
someone is locked out. Blocking is NOT offered from the web: a compromised
dashboard must not be able to firewall people off, so new blocks go through
Telegram (authenticated out-of-band) or the detection engine, never a browser
form. The web can undo a block; it cannot create one.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import RedirectResponse

from sentinel.db.engine import Database
from sentinel.db.repo import blocklist as blocklist_repo
from sentinel.db.repo import users as users_repo
from sentinel.errors import ExecutorRejected, ExecutorUnavailable
from sentinel.logging_setup import get_logger
from sentinel.respond import actions
from sentinel.web.deps import current_user, get_db

log = get_logger(__name__)
router = APIRouter()


@router.get("/blocklist")
async def blocklist_page(
    request: Request,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
) -> Response:
    active = await blocklist_repo.list_active(db, limit=200)
    history = await blocklist_repo.recent(db, limit=50)
    live = await actions.live_count()
    session = request.state.session
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="blocklist.html",
        context={
            "user": user, "active": "blocklist",
            "blocks": active, "history": history, "live_count": live,
            "can_unblock": user.role in ("owner", "operator"),
            "csrf_token": session.csrf_token,
            "msg": request.query_params.get("msg"),
        },
    )


@router.post("/blocklist/unblock")
async def unblock_action(
    request: Request,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
    ip: Annotated[str, Form()] = "",
) -> Response:
    if user.role not in ("owner", "operator"):
        return RedirectResponse("/blocklist?msg=Necesită+rol+operator", status_code=303)
    ip = ip.strip()
    try:
        await actions.unblock(db, ip, by=f"operator:{user.username}")
        msg = f"Deblocat {ip}"
    except (ExecutorRejected, ExecutorUnavailable) as exc:
        log.warning("web unblock failed", extra={"ip": ip, "detail": str(exc)})
        msg = f"Eroare: {exc}"
    return RedirectResponse(f"/blocklist?msg={msg}", status_code=303)
