"""Dashboard and health.

The dashboard answers one question first — "am I OK?" — and only then offers
detail. Its order is deliberate: verdict, counters, interpreted insights, then
the tables the insights were derived from. Someone woken at 3 a.m. should be
able to stop reading after the first line if the answer is "yes".

Everything on it is computed by sentinel.analytics: aggregate.py counts,
insights.py says what the counts mean. Nothing here calls a model, so the page
renders instantly and says the same thing twice in a row.
"""

from __future__ import annotations

import os
import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response

from sentinel import __version__
from sentinel.analytics import page
from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import audit as audit_repo
from sentinel.db.repo import sessions as sessions_repo
from sentinel.db.repo import users as users_repo
from sentinel.logging_setup import get_logger
from sentinel.web.deps import current_user, get_config, get_db

log = get_logger(__name__)
router = APIRouter()


@router.get("/healthz")
async def healthz(
    request: Request, db: Annotated[Database, Depends(get_db)]
) -> Response:
    """Unauthenticated liveness probe.

    Deliberately unauthenticated and deliberately terse. The root watchdog polls
    this to decide whether Sentinel is alive enough to be trusted with the
    blocklist, so it must work when the database is down and it must not require
    a session.

    It reveals nothing: no version, no hostname, no component detail. A probe
    endpoint that returns a version string is a free reconnaissance gift.
    """
    from fastapi.responses import JSONResponse

    db_ok = await db.healthy()
    return JSONResponse(
        {"status": "ok" if db_ok else "degraded"},
        status_code=200 if db_ok else 503,
        headers={"Cache-Control": "no-store"},
    )


@router.get("/")
async def dashboard(
    request: Request,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
    cfg: Annotated[Config, Depends(get_config)],
) -> Response:
    templates = request.app.state.templates
    session = request.state.session

    # Panourile vin din `analytics.page`, nu de aici: autodiagnosticul măsoară
    # aceeași funcție, deci nu poate rămâne verde peste un panou pe care pagina
    # îl încarcă și sonda nu-l cunoaște. Vezi docstring-ul modulului.
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user": user,
            "csrf_token": session.csrf_token,
            "status": await _self_status(db, cfg),
            "phase_notice": _phase_notice(cfg),
            **await page.load(db),
        },
    )


@router.get("/account")
async def account(
    request: Request,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
) -> Response:
    templates = request.app.state.templates
    session = request.state.session
    return templates.TemplateResponse(
        request=request,
        name="account.html",
        context={
            "user": user,
            "csrf_token": session.csrf_token,
            "sessions": await sessions_repo.active_for_user(db, user.id),
            "current_session_id": session.id,
            "audit": await audit_repo.recent(db, hours=168, limit=25, source="web"),
        },
    )


# ---------------------------------------------------------------------------
async def _self_status(db: Database, cfg: Config) -> dict[str, Any]:
    """What Sentinel can honestly report about itself right now."""
    db_ok = await db.healthy()
    status: dict[str, Any] = {
        "version": __version__,
        "database": "ok" if db_ok else "down",
        "database_size_mb": round(await db.size_bytes() / 1024**2, 1) if db_ok else None,
        "schema_version": None,
        "auto_block": cfg.response.auto_block.enabled,
        "suricata": cfg.suricata.enabled,
        "ai": cfg.ai.enabled,
        "telegram": cfg.telegram.enabled,
        "totp_required": cfg.web.require_totp,
        "ip_allowlist": bool(cfg.web.ip_allowlist),
    }

    if db_ok:
        status["schema_version"] = await db.fetchval(
            "SELECT max(version) FROM schema_version"
        )

    # Host capacity, read straight from /proc. On a shared host this is the
    # number that predicts an unexplained outage: the OOM killer picks the
    # largest process, usually the application rather than Sentinel.
    try:
        meminfo = {
            k.strip(): int(v.split()[0])
            for k, _, v in (
                line.partition(":")
                for line in open("/proc/meminfo", encoding="utf-8").read().splitlines()
            )
            if v.strip()
        }
        status["mem_available_mb"] = meminfo.get("MemAvailable", 0) // 1024
        status["mem_total_mb"] = meminfo.get("MemTotal", 0) // 1024
    except OSError:
        status["mem_available_mb"] = None
        status["mem_total_mb"] = None

    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        status["disk_used_pct"] = round(100 * (1 - free / total), 1) if total else None
        status["disk_free_gb"] = round(free / 1024**3, 1)
    except OSError:
        status["disk_used_pct"] = None
        status["disk_free_gb"] = None

    try:
        load1, _, _ = os.getloadavg()
        status["load1"] = round(load1, 2)
        status["cpu_count"] = os.cpu_count()
    except OSError:
        status["load1"] = None
        status["cpu_count"] = None

    # The panic file means blocking is currently disabled. Anyone looking at the
    # dashboard needs to know that before they trust it to be defending anything.
    from pathlib import Path

    from sentinel.constants import PANIC_FILE

    status["panic_active"] = Path(PANIC_FILE).exists()

    return status


async def _recent_logins(db: Database, user: users_repo.User) -> list[dict[str, Any]]:
    """Recent attempts for this account, successful and not.

    On the dashboard rather than buried in a log: an unfamiliar successful login
    is the one thing a user can recognise instantly and no rule can.
    """
    rows = await db.fetch(
        """
        SELECT at, ip::text AS ip, result, stage, user_agent
          FROM login_attempts
         WHERE username = $1
         ORDER BY at DESC
         LIMIT 10
        """,
        user.username,
    )
    return [dict(r) for r in rows]


def _phase_notice(cfg: Config) -> dict[str, Any] | None:
    """Say plainly what is not collecting yet.

    A dashboard showing "0 incidents" when ingestion does not exist reads as "you
    are safe". It is not the same statement and should not look like it.
    """
    pending = []
    if cfg.response.auto_block.enabled:
        pending.append(None)  # placeholder; nothing to report when enabled
    return {
        "collecting": False,
        "message_ro": (
            "Colectarea de evenimente și detecția nu sunt încă active în această "
            "fază. Autentificarea, baza de date, firewall-ul și executorul "
            "funcționează. Un dashboard care ar arăta „0 incidente” acum ar "
            "însemna „nu monitorizez”, nu „ești în siguranță”."
        ),
        "auto_block": cfg.response.auto_block.enabled,
    }
