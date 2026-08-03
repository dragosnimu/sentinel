"""The Patches page: plans, what they would do, and their execution history.

Approving happens on Telegram, not here — deliberately. The two-stage token flow
binds an approval to a chat and a plan hash, and duplicating that in a second
surface would mean two places to get it wrong. What the web offers is the thing
a phone is bad at: reading a full plan, step by step, before deciding.

A dry run IS offered here, because it changes nothing and reading the output of
one on a real screen is far easier than in a chat bubble.
"""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import patches as repo
from sentinel.db.repo import users as users_repo
from sentinel.logging_setup import get_logger
from sentinel.web.deps import current_user, get_config, get_db

log = get_logger(__name__)
router = APIRouter()

STATUS_RO = {
    "draft": "ciornă", "validated": "validat", "rejected_invalid": "invalid",
    "approved": "aprobat", "scheduled": "programat", "applying": "se aplică",
    "applied": "aplicat", "rolled_back": "revenit", "failed": "eșuat",
    "rejected": "respins", "expired": "expirat",
}
STATUS_PILL = {
    "validated": "warn", "approved": "warn", "applying": "warn",
    "applied": "ok", "rolled_back": "warn",
    "rejected_invalid": "bad", "failed": "bad",
    "rejected": "off", "expired": "off", "draft": "off", "scheduled": "warn",
}


@router.get("/patches")
async def patches_page(
    request: Request,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
    msg: str | None = None,
) -> Response:
    rows = await repo.list_plans(db, limit=60)
    for r in rows:
        r.status_ro = STATUS_RO.get(r.status, r.status)      # type: ignore[attr-defined]
        r.pill = STATUS_PILL.get(r.status, "off")            # type: ignore[attr-defined]
        r.asset = r.plan.get("target", {}).get("asset_name", "?")  # type: ignore[attr-defined]
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request, name="patches.html",
        context={"user": user, "active": "patches", "rows": rows,
                 "restore_points": await repo.list_restore_points(db, limit=15),
                 "msg": msg, "csrf_token": request.state.session.csrf_token},
    )


@router.get("/patches/{plan_id}")
async def patch_detail(
    request: Request,
    plan_id: int,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
) -> Response:
    row = await repo.get_plan(db, plan_id)
    if row is None:
        raise StarletteHTTPException(status_code=404, detail="Plan inexistent")
    row.status_ro = STATUS_RO.get(row.status, row.status)   # type: ignore[attr-defined]
    row.pill = STATUS_PILL.get(row.status, "off")           # type: ignore[attr-defined]

    executions = await db.fetch(
        "SELECT id, mode, status, started_at, duration_ms, error "
        "FROM patch_executions WHERE plan_id = $1 ORDER BY started_at DESC LIMIT 10",
        plan_id)
    steps = []
    if executions:
        steps = await repo.execution_steps(db, executions[0]["id"])

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request, name="patch.html",
        context={"user": user, "active": "patches", "p": row,
                 "plan_json": json.dumps(row.plan, indent=2, ensure_ascii=False),
                 "executions": [dict(e) for e in executions], "steps": steps,
                 "can_act": user.role in ("owner", "operator"),
                 "csrf_token": request.state.session.csrf_token},
    )


@router.post("/patches/{plan_id}/dry-run")
async def dry_run(
    plan_id: int,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
    cfg: Annotated[Config, Depends(get_config)],
) -> Response:
    """A dry run executes nothing — the executor is asked what it WOULD do. That
    is why it needs no approval token, only a role."""
    if user.role not in ("owner", "operator"):
        return RedirectResponse(f"/patches/{plan_id}?msg=Necesită+rol+operator",
                                status_code=303)
    from sentinel.patch import runner
    try:
        result = await runner.run_plan(db, cfg, plan_id, mode="dry_run",
                                       triggered_by=f"web:{user.username}")
    except runner.PatchRefused as exc:
        return RedirectResponse(f"/patches/{plan_id}?msg=Refuzat:+{exc}", status_code=303)
    return RedirectResponse(
        f"/patches/{plan_id}?msg=Dry-run+{result.status}+({len(result.steps)}+pași)",
        status_code=303)


@router.post("/patches/{plan_id}/reject")
async def reject(
    plan_id: int,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
) -> Response:
    if user.role not in ("owner", "operator"):
        return RedirectResponse(f"/patches/{plan_id}?msg=Necesită+rol+operator",
                                status_code=303)
    from sentinel.db.repo import approvals
    await repo.reject_plan(db, plan_id, by=f"web:{user.username}",
                           reason="respins din interfața web")
    # Any button already sitting in a Telegram scrollback dies with it.
    await approvals.revoke_for_plan(db, plan_id)
    log.info("patch plan rejected", extra={"plan": plan_id, "by": user.username})
    return RedirectResponse("/patches?msg=Plan+respins", status_code=303)
