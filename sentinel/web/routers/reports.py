"""The Reports page: aggregated history, charted, with drill-down.

Read-only in the strongest sense — every handler here is a GET that runs SELECTs
and renders. The reports surface adds no action of any kind, so it cannot become
a second path to the executor (see the module docstring of `web/app.py`).

Two things about how this is drawn.

**No JavaScript, and no charting library.** The CSP is `script-src 'self'` with
no `unsafe-inline`, and the vendored bundle it would load is not in the
repository (`static/vendor/` holds a `.gitkeep`; `scripts/vendor-assets.sh`
ships with no pinned checksums and skips the download). Building the charts on
a library that is not there would produce a page of empty boxes that looks
exactly like "nothing happened". So the charts are inline SVG computed in
`analytics/reports.py`, in the same style as the availability sparkline on the
Services page, and a bar is clickable because it is wrapped in an `<a href>`.

**Every parameter is whitelisted before it reaches SQL.** The breakdown column
is an identifier, so it is selected from a fixed table rather than interpolated;
the bucket start must be an exact bucket boundary inside the charted span, which
is what stops a crafted query string from asking for a scan of five years of
`raw_events` while detection is trying to run.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from sentinel.analytics import reports
from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import incidents as inc_repo
from sentinel.db.repo import users as users_repo
from sentinel.logging_setup import get_logger
from sentinel.model.event import ACTIONS, SOURCES
from sentinel.web.deps import current_user, get_config, get_db, now_utc

log = get_logger(__name__)
router = APIRouter()

SEVERITY_RO = {
    "critical": "critic", "high": "ridicat", "medium": "mediu",
    "low": "scăzut", "info": "informativ",
}

SEVERITY_CLASS = {
    "critical": "rep-crit", "high": "rep-high", "medium": "rep-med",
    "low": "rep-low", "info": "rep-info",
}

RULE_FAMILY_RO = {
    "auth": "autentificare", "web": "web", "ids": "IDS",
    "intrusion": "intruziune", "anomaly": "anomalie",
    "novelty": "noutate", "exposure": "expunere",
}

# `patch_executions.status`, from the CHECK constraint in 0004_patch.sql.
EXEC_STATUS = ("running", "succeeded", "failed", "rolled_back",
               "rollback_failed", "aborted")
EXEC_STATUS_RO = {
    "running": "în curs", "succeeded": "reușit", "failed": "eșuat",
    "rolled_back": "revenit", "rollback_failed": "revenire eșuată",
    "aborted": "abandonat",
}
EXEC_STATUS_CLASS = {
    "succeeded": "rep-ok", "failed": "rep-crit", "rollback_failed": "rep-crit",
    "aborted": "rep-high", "rolled_back": "rep-med", "running": "rep-info",
}

# What a drill-down may filter on, and the vocabulary each accepts. A value
# outside its vocabulary is refused rather than passed through: the SQL is
# parameterised either way, but an unknown source or severity can only be a
# typo or a probe, and answering it with an empty table would look like a fact.
DRILL_VALUES: dict[tuple[str, str], tuple[str, ...] | None] = {
    ("incidents", "severity"): inc_repo.SEVERITIES,
    ("incidents", "rule_family"): None,          # derived from fingerprint; free text
    ("events", "source"): SOURCES,
    ("events", "action"): ACTIONS,
    ("patches", "status"): EXEC_STATUS,
}

DRILL_KINDS = {
    "incidents": reports.INCIDENT_DIMS,
    "events": reports.EVENT_DIMS,
    "patches": reports.PATCH_DIMS,
}

MAX_VALUE_LEN = 64


# ---------------------------------------------------------------------------
@router.get("/reports")
async def reports_page(
    request: Request,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
    cfg: Annotated[Config, Depends(get_config)],
    now: Annotated[datetime, Depends(now_utc)],
    window: str = Query(reports.DEFAULT_WINDOW),
    bucket: str = Query(reports.DEFAULT_BUCKET),
) -> Response:
    window = window if window in reports.WINDOWS else reports.DEFAULT_WINDOW
    bucket = bucket if bucket in reports.BUCKETS else reports.DEFAULT_BUCKET
    spec = reports.BUCKETS[bucket]

    # Fusul configurat, dat pe față fiecărei funcții care taie sau scrie o
    # margine. `analytics/reports.py` are implicit UTC — depozitarea — tocmai ca
    # o funcție chemată fără fus să dea același răspuns oriunde; deci pagina, care
    # desenează pentru un om, trebuie să-l treacă de fiecare dată. Că îl trece
    # chiar peste tot e ținut de `test_the_reports_page_aligns_in_the_configured_zone`.
    tz_name = cfg.timezone

    starts = reports.bucket_starts(spec.unit, now=now, count=spec.span, tz_name=tz_name)
    start, end = starts[0], reports.advance(starts[-1], spec.unit, 1, tz_name=tz_name)

    # What the store actually holds, read before anything is charted. Every
    # series is annotated with it, so a gap is drawn as a gap.
    coverage = await reports.rollup_coverage(db, now=now)
    fallbacks = reports.Fallbacks(
        raw_from=await reports.raw_coverage(db),
        minute_from=await reports.minute_coverage(db),
    )
    raw_from = fallbacks.raw_from
    since_install = await reports.installed_at(db)

    # The three coverage edges, computed once, in analytics, where a test can
    # call the same function with the same input. `event_rollup_1h.bucket` is a
    # bucket START, so the edge arithmetic is not obvious and must not be
    # re-derived by hand at each call site — that is exactly how the newest
    # bucket ended up drawn as "no data kept" while holding a hundred events.
    ev_from, ev_complete, ev_to = reports.event_edges(coverage, now=now)
    live_from, live_complete, live_to = reports.live_edges(
        since_install, now=now, unit=spec.unit, tz_name=tz_name)

    charts = []

    ev_source = reports.build_series(
        await reports.events_rows(db, unit=spec.unit, start=start, end=end,
                                  dim="source", tz_name=tz_name),
        unit=spec.unit, tz_name=tz_name, starts=starts,
        known_from=ev_from, complete_to=ev_complete, known_to=ev_to,
        fallbacks=fallbacks, top=7,
    )
    charts.append({
        "id": "ev-source",
        "title": "Evenimente pe sursă",
        "note": ("Din agregatul orar (event_rollup_1h). Numărul de adrese "
                 "distincte nu se poate reconstitui dintr-un agregat, deci nu e "
                 "afișat aici."),
        "series": ev_source,
        "chart": reports.build_chart(ev_source, drill={
            "kind": "events", "dim": "source", "bucket": bucket}, tick_fmt=spec.fmt),
    })

    ev_action = reports.build_series(
        await reports.events_rows(db, unit=spec.unit, start=start, end=end,
                                  dim="action", tz_name=tz_name),
        unit=spec.unit, tz_name=tz_name, starts=starts,
        known_from=ev_from, complete_to=ev_complete, known_to=ev_to,
        fallbacks=fallbacks, top=7,
    )
    charts.append({
        "id": "ev-action",
        "title": "Evenimente pe acțiune",
        "note": "Acțiunea normalizată, aceeași pe care o folosesc regulile de detecție.",
        "series": ev_action,
        "chart": reports.build_chart(ev_action, drill={
            "kind": "events", "dim": "action", "bucket": bucket}, tick_fmt=spec.fmt),
    })

    inc_sev = reports.build_series(
        await reports.incidents_rows(db, unit=spec.unit, start=start, end=end,
                                     dim="severity", tz_name=tz_name),
        unit=spec.unit, tz_name=tz_name, starts=starts,
        known_from=live_from, complete_to=live_complete, known_to=live_to,
        # Nothing sits below `incidents`: no hourly aggregate to be behind, no
        # raw table to fall back to. `live_edges` puts `known_to` at the end of
        # the current bucket, so a pending column cannot arise here — that is
        # arithmetic now, not the comment it used to be.
        fallbacks=reports.NO_FALLBACK,
        key_order=reports.SEVERITY_ORDER,
    )
    charts.append({
        "id": "inc-sev",
        "title": "Incidente pe severitate",
        "note": ("Plasate după momentul deschiderii, nu după ultima detecție: "
                 "un incident care ține trei săptămâni aparține săptămânii în "
                 "care a început."),
        "series": inc_sev,
        "chart": reports.build_chart(
            inc_sev, labels=SEVERITY_RO, palette=SEVERITY_CLASS,
            drill={"kind": "incidents", "dim": "severity", "bucket": bucket},
            tick_fmt=spec.fmt),
    })

    inc_fam = reports.build_series(
        await reports.incidents_rows(db, unit=spec.unit, start=start, end=end,
                                     dim="rule_family", tz_name=tz_name),
        unit=spec.unit, tz_name=tz_name, starts=starts,
        known_from=live_from, complete_to=live_complete, known_to=live_to,
        fallbacks=reports.NO_FALLBACK, top=7,
    )
    charts.append({
        "id": "inc-fam",
        "title": "Incidente pe familie de reguli",
        "note": ("Familia e prefixul regulii care a deschis incidentul — auth, "
                 "web, ids, intrusion, anomaly, novelty, exposure."),
        "series": inc_fam,
        "chart": reports.build_chart(
            inc_fam, labels=RULE_FAMILY_RO,
            drill={"kind": "incidents", "dim": "rule_family", "bucket": bucket},
            tick_fmt=spec.fmt),
    })

    patch_status = reports.build_series(
        await reports.patches_rows(db, unit=spec.unit, start=start, end=end,
                                   tz_name=tz_name),
        unit=spec.unit, tz_name=tz_name, starts=starts,
        known_from=live_from, complete_to=live_complete, known_to=live_to,
        fallbacks=reports.NO_FALLBACK,
    )
    charts.append({
        "id": "patch-status",
        "title": "Patch-uri pe stare",
        "note": ("Doar aplicările reale. Un dry-run nu schimbă nimic pe gazdă, "
                 "iar a-l număra aici ar raporta muncă ce nu s-a întâmplat."),
        "series": patch_status,
        "chart": reports.build_chart(
            patch_status, labels=EXEC_STATUS_RO, palette=EXEC_STATUS_CLASS,
            drill={"kind": "patches", "dim": "status", "bucket": bucket},
            tick_fmt=spec.fmt),
    })

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="reports.html",
        context={
            "user": user,
            # base.html puts the logout form in the sidebar of every page. A
            # page that forgets this renders that form with an empty token, and
            # the CSRF middleware then bounces the operator to /login?e=csrf
            # instead of logging them out — a broken button nobody notices until
            # they try to use it.
            "csrf_token": request.state.session.csrf_token,
            "active": "reports",
            "window": window,
            "windows": reports.WINDOWS,
            "bucket": bucket,
            "buckets": reports.BUCKETS,
            "spec": spec,
            # Numele zonei, nu marcajul: `EEST` e adevărat jumătate de an, iar
            # un grafic pe 30 de zile poate trece peste schimbare. Numele e
            # adevărat mereu, iar marcajul îl pune filtrul `ora` pe fiecare
            # moment în parte.
            "tz_name": tz_name,
            "range_from": start,
            "range_to": end,
            "coverage": coverage,
            "raw_from": raw_from,
            "since_install": since_install,
            "overview": await reports.overview(
                db, hours=reports.WINDOWS[window],
                rollup_from=coverage["earliest"], installed_from=since_install,
                now=now),
            "charts": charts,
            "severity_ro": SEVERITY_RO,
        },
    )


# ---------------------------------------------------------------------------
@router.get("/reports/drill")
async def reports_drill(
    request: Request,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
    cfg: Annotated[Config, Depends(get_config)],
    now: Annotated[datetime, Depends(now_utc)],
    kind: str = Query(...),
    bucket: str = Query(...),
    dim: str = Query(...),
    value: str = Query(""),
    scope: str = Query(""),
    start: str = Query(...),
) -> Response:
    """One bucket, one category, the rows behind the bar.

    Refuses anything it was not asked to answer. In particular the bucket start
    must be an exact boundary inside the charted span: without that check, a
    hand-written query string could ask for an arbitrary range and turn this
    page into a long scan competing with detection for the same database.
    """
    dims = DRILL_KINDS.get(kind)
    if dims is None or dim not in dims or bucket not in reports.BUCKETS:
        raise StarletteHTTPException(status_code=400, detail="Parametri de raport invalizi")

    # `scope=all` is the link on a `pending` column of the events chart: that
    # bucket has no categories yet because the rollup has not summed it, but the
    # rows are in `raw_events`. Only events have a raw table to fall back on, so
    # it is refused anywhere else rather than quietly ignored.
    all_categories = scope == "all"
    if scope not in ("", "all"):
        raise StarletteHTTPException(status_code=400, detail="Domeniu necunoscut")
    if all_categories and kind != "events":
        raise StarletteHTTPException(status_code=400, detail="Domeniu necunoscut")

    allowed = DRILL_VALUES.get((kind, dim))
    if not all_categories:
        if allowed is not None and value not in allowed:
            raise StarletteHTTPException(status_code=400, detail="Categorie necunoscută")
        if len(value) > MAX_VALUE_LEN:
            raise StarletteHTTPException(status_code=400, detail="Categorie necunoscută")

    spec = reports.BUCKETS[bucket]
    tz_name = cfg.timezone
    valid = set(reports.bucket_starts(spec.unit, now=now, count=spec.span,
                                      tz_name=tz_name))
    try:
        parsed = datetime.fromisoformat(start)
    except ValueError:
        raise StarletteHTTPException(status_code=400, detail="Interval invalid") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    if parsed not in valid:
        # Not a boundary of the chart the link came from — either a stale link
        # (the span has scrolled past it) or a hand-made one. Both get the same
        # answer, and the page says which it probably was.
        raise StarletteHTTPException(
            status_code=400,
            detail="Intervalul cerut nu mai este în raportul curent. Reia din grafic.")

    bucket_from, bucket_to = reports.drill_bounds(spec.unit, parsed, tz_name=tz_name)

    rows: list[dict[str, Any]] = []
    window = reports.RawWindow(start=bucket_from, end=bucket_to,
                               expired=False, capped=False, trimmed=False)
    raw_from: datetime | None = None

    if kind == "incidents":
        rows = await reports.drill_incidents(
            db, start=bucket_from, end=bucket_to, dim=dim, value=value)
    elif kind == "patches":
        rows = await reports.drill_patches(
            db, start=bucket_from, end=bucket_to, value=value)
    else:
        raw_from = await reports.raw_coverage(db)
        window = reports.clamp_raw_window(bucket_from, bucket_to, raw_from=raw_from)
        if not window.expired:
            rows = await reports.drill_events(
                db, start=window.start, end=window.end, dim=dim, value=value,
                all_categories=all_categories)

    label = "toate categoriile" if all_categories else (value or "necunoscut")
    if all_categories:
        pass
    elif kind == "incidents" and dim == "severity":
        label = SEVERITY_RO.get(value, label)
    elif kind == "incidents" and dim == "rule_family":
        label = RULE_FAMILY_RO.get(value, label)
    elif kind == "patches":
        label = EXEC_STATUS_RO.get(value, label)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="report_drill.html",
        context={
            "user": user,
            "csrf_token": request.state.session.csrf_token,
            "active": "reports",
            "kind": kind,
            "dim": dim,
            "value": value,
            "value_label": label,
            "all_categories": all_categories,
            "bucket": bucket,
            "spec": spec,
            "tz_name": tz_name,
            "bucket_from": bucket_from,
            "bucket_to": bucket_to,
            "window": window,
            "raw_from": raw_from,
            "rows": rows,
            "limit": reports.DRILL_LIMIT,
            "at_limit": len(rows) >= reports.DRILL_LIMIT,
            "severity_ro": SEVERITY_RO,
            "exec_status_ro": EXEC_STATUS_RO,
            "back": f"/reports?bucket={bucket}",
        },
    )
