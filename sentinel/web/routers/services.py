"""The Services page: every monitored asset, up/down live, with a 24h uptime chart.

The data comes from the health prober (sentinel-health.timer, every 30s). This
router only reads it. The uptime sparkline is a server-rendered inline SVG — no
client-side charting library, so the strict CSP stays intact and the page needs
no JavaScript to show the graph. The page meta-refreshes every 30s for the "live"
part; a partial-update layer (HTMX) can replace that later without changing this.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import assets as assets_repo
from sentinel.db.repo import capacity as capacity_repo
from sentinel.db.repo import health as health_repo
from sentinel.db.repo import users as users_repo
from sentinel.logging_setup import get_logger
from sentinel.web.deps import current_user, get_config, get_db

log = get_logger(__name__)
router = APIRouter()

_STATUS_DOT = {"up": "ok", "degraded": "warn", "down": "bad", "unknown": "off"}
_STATUS_RO = {"up": "activ", "degraded": "degradat", "down": "picat", "unknown": "necunoscut"}


@dataclass
class ServiceRow:
    asset: assets_repo.Asset
    status: str
    latency_ms: int | None
    uptime_24h: float | None
    open_since: Any
    error: str | None
    dot: str
    status_ro: str
    sparkline: str          # an SVG <polyline> points string
    sparkline_gaps: bool


def _sparkline_points(buckets: list[dict], width: int = 220, height: int = 28) -> tuple[str, bool]:
    """Turn per-bucket up-percentages into SVG polyline points.

    A bucket with no samples (None) is a gap — the line is not drawn across it, so
    a stretch with no data reads as missing rather than as 100% uptime.
    """
    n = len(buckets)
    if n == 0:
        return "", False
    step = width / max(n - 1, 1)
    pts: list[str] = []
    gaps = False
    for i, b in enumerate(buckets):
        up = b.get("up")
        if up is None:
            gaps = True
            continue
        x = round(i * step, 1)
        y = round(height - (up / 100.0) * height, 1)
        pts.append(f"{x},{y}")
    return " ".join(pts), gaps


async def _rows(db: Database) -> list[ServiceRow]:
    assets = await assets_repo.list_all(db)
    live = await health_repo.live_status(db)
    rows: list[ServiceRow] = []
    for asset in assets:
        st = live.get(asset.id)
        status = st.status if st else "unknown"
        buckets = await health_repo.sparkline(db, asset.id, hours=24, buckets=48)
        points, gaps = _sparkline_points(buckets)
        rows.append(
            ServiceRow(
                asset=asset,
                status=status,
                latency_ms=st.latency_ms if st else None,
                uptime_24h=st.uptime_24h if st else None,
                open_since=st.open_since if st else None,
                error=st.error if st else None,
                dot=_STATUS_DOT.get(status, "off"),
                status_ro=_STATUS_RO.get(status, status),
                sparkline=points,
                sparkline_gaps=gaps,
            )
        )
    return rows


@router.get("/services")
async def services_page(
    request: Request,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
    cfg: Annotated[Config, Depends(get_config)],
) -> Response:
    templates = request.app.state.templates
    rows = await _rows(db)
    cap = await capacity_repo.latest(db)
    cap_history = await capacity_repo.history(db, hours=24, buckets=96)

    counts = {"up": 0, "degraded": 0, "down": 0, "unknown": 0}
    for r in rows:
        counts[r.status] = counts.get(r.status, 0) + 1

    return templates.TemplateResponse(
        request=request,
        name="services.html",
        context={
            "user": user,
            "active": "services",
            "rows": rows,
            "counts": counts,
            "capacity": cap,
            "cap_history": cap_history,
            "probing": any(r.status != "unknown" for r in rows),
        },
    )


@router.get("/api/services")
async def services_api(
    request: Request,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
) -> Response:
    """Live status as JSON, for a future partial-refresh layer or external checks."""
    rows = await _rows(db)
    return JSONResponse(
        {
            "services": [
                {
                    "name": r.asset.name,
                    "kind": r.asset.kind,
                    "status": r.status,
                    "latency_ms": r.latency_ms,
                    "uptime_24h": r.uptime_24h,
                    "internet_exposed": r.asset.is_internet_exposed,
                    "criticality": r.asset.criticality,
                }
                for r in rows
            ]
        },
        headers={"Cache-Control": "no-store"},
    )
