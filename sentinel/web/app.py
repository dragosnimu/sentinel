"""FastAPI application factory.

The dashboard is read-only against the database plus a live event stream. It
**never** talks to the privileged executor: destructive actions go into
`action_requests` and require a Telegram confirmation. That is what keeps a
dashboard compromise to a data disclosure rather than a takeover.

Middleware order matters and is not alphabetical:

    1. security headers   — must apply even to error responses
    2. CSRF               — must run before any handler sees a mutating request
    3. request context    — logging correlation

The security headers are also set by nginx. Duplicating them here is deliberate:
if someone reaches uvicorn directly during debugging, or the nginx config is
replaced, the app still refuses to be framed and still declares a strict CSP.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sentinel import __version__
from sentinel.config import Config, Secrets, get_config, get_secrets
from sentinel.db.engine import Database
from sentinel.db.repo import sessions as sessions_repo
from sentinel.logging_setup import get_logger
from sentinel.web.security import Authenticator, PreAuthCSRF, csrf_valid

log = get_logger(__name__)

WEB_DIR = Path(__file__).parent
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"

# Methods that change state and therefore need a CSRF token.
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Reachable without a session. Everything else requires one, enforced per-route
# by the dependencies rather than by a path list here — a path allowlist for
# authentication is a maintenance trap.
PUBLIC_PATHS = frozenset({"/healthz", "/login", "/totp", "/static"})

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "object-src 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    ),
    # No page here is cacheable: every one is behind auth and shows security
    # data. A shared cache holding an incident list would be a leak.
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)

        # HSTS only over TLS. Sending it on a plaintext response is meaningless
        # and, on a bare-IP deployment, would pin something the operator did not
        # intend.
        if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )

        # Static assets are the one thing worth caching, and they are public.
        if request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "public, max-age=604800, immutable"
        return response


class CSRFMiddleware:
    """Rejects mutating requests without a valid CSRF token.

    Two token sources, because the login form needs protection before a session
    exists:

    * **With a session** — the session's own token. Bound to one session, so it
      cannot be lifted from another user's page.
    * **Without a session** (login, TOTP) — a signed, timestamped nonce in a
      cookie, double-submitted in the form. Stateless on purpose: issuing a
      database row per login-page view would let an attacker fill the sessions
      table by requesting the page in a loop.

    Runs as middleware rather than as a per-route dependency so a new handler
    cannot forget it. SameSite already blocks the common cross-site cases, but
    that is a browser behaviour, not a guarantee.

    Implemented as a PURE ASGI middleware, not BaseHTTPMiddleware. To find the
    token in a form post it must read the request body — and BaseHTTPMiddleware
    hands the endpoint a *fresh* receive channel, so a body consumed here reaches
    the handler empty, blanking out `username` and `password` (the login form
    submitted correctly, yet every attempt logged as an unknown, empty user).
    Only full control of the ASGI `receive` lets us buffer the body once and
    replay it to the endpoint.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    @staticmethod
    def _replay(body: bytes) -> Receive:
        # A fresh single-shot receive over the buffered body. One is handed to the
        # form parser here and another to the downstream app; each delivers the
        # whole body once, then reports disconnect.
        sent = False

        async def receive() -> Message:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        return receive

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        if request.method not in MUTATING_METHODS:
            await self.app(scope, receive, send)
            return

        # Buffer the whole body once so it can be both inspected and replayed.
        body = b""
        while True:
            message = await receive()
            if message["type"] == "http.request":
                body += message.get("body", b"")
                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                break

        db: Database = scope["app"].state.db
        from sentinel.web.security import COOKIE_NAME, PREAUTH_CSRF_COOKIE

        token = request.cookies.get(COOKIE_NAME)
        session = await sessions_repo.get_by_token(db, token) if token else None

        submitted = request.headers.get("x-csrf-token")
        if submitted is None:
            # Form posts carry it in a hidden field. Parse a throwaway Request over
            # a replay of the buffered body — the real body still reaches the
            # handler untouched.
            try:
                form = await Request(scope, self._replay(body)).form()
                value = form.get("csrf_token")
                submitted = value if isinstance(value, str) else None
            except Exception:  # noqa: BLE001 - a malformed body is simply invalid
                submitted = None

        if session is not None:
            ok = csrf_valid(session, submitted)
            source = "session"
        else:
            ok = scope["app"].state.preauth_csrf.validate(
                request.cookies.get(PREAUTH_CSRF_COOKIE), submitted
            )
            source = "preauth"

        if not ok:
            log.warning(
                "CSRF check failed",
                extra={
                    "path": request.url.path,
                    "source": source,
                    "has_token": bool(submitted),
                },
            )
            if "text/html" in request.headers.get("accept", ""):
                # Usually an expired token on a form left open, so send them
                # somewhere useful rather than showing a bare 403.
                response: Response = RedirectResponse(
                    "/login?e=csrf", status_code=status.HTTP_303_SEE_OTHER
                )
            else:
                response = JSONResponse(
                    {"error": "csrf_failed"}, status_code=status.HTTP_403_FORBIDDEN
                )
            await response(scope, self._replay(body), send)
            return

        # Belt-and-suspenders: the session dependencies set this too, but a POST
        # handler that reads it directly should still see it.
        scope.setdefault("state", {})["session"] = session
        await self.app(scope, self._replay(body), send)


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = uuid.uuid4().hex[:12]
        request.state.request_id = request_id
        started = time.monotonic()

        response = await call_next(request)

        duration_ms = int((time.monotonic() - started) * 1000)
        response.headers["X-Request-Id"] = request_id

        # Health checks run every 30 seconds from the watchdog; logging them
        # would bury everything else.
        if request.url.path != "/healthz":
            log.info(
                "request",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": duration_ms,
                },
            )
        return response


# ---------------------------------------------------------------------------
def create_app(
    config: Config | None = None, secrets_store: Secrets | None = None
) -> FastAPI:
    cfg = config or get_config()
    sec = secrets_store or get_secrets()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db = Database(cfg)
        await db.connect()
        app.state.db = db
        app.state.config = cfg
        app.state.secrets = sec
        app.state.authenticator = Authenticator(db, cfg, sec)
        app.state.preauth_csrf = PreAuthCSRF(sec.require("SENTINEL_SESSION_SECRET"))
        app.state.started_at = time.time()
        log.info("web service ready", extra={"version": __version__, "port": cfg.web.port})
        try:
            yield
        finally:
            await db.close()

    app = FastAPI(
        title="Sentinel",
        version=__version__,
        lifespan=lifespan,
        # The OpenAPI schema and Swagger UI are off. They document every
        # endpoint and parameter of a security dashboard to anyone who reaches
        # the login page, and nothing here needs them.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Added in reverse order of execution: the last added runs first.
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(CSRFMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.autoescape = True
    # From the shared factory, so a template that renders here renders in the
    # tests too. `_vuln.html` calls these globals directly; an environment
    # without them raises UndefinedError at render time, not at import.
    from sentinel.web.jinja import template_globals

    templates.env.globals.update(template_globals())
    app.state.templates = templates

    from sentinel.web.routers import (
        auth, blocklist, dashboard, events, findings, incidents, patches, services,
    )

    app.include_router(dashboard.router)
    app.include_router(services.router)
    app.include_router(events.router)
    app.include_router(incidents.router)
    app.include_router(findings.router)
    app.include_router(patches.router)
    app.include_router(blocklist.router)
    app.include_router(auth.router)

    # -- error handling ----------------------------------------------------
    # Registered on Starlette's HTTPException, not FastAPI's. FastAPI's subclasses
    # it, but the router raises Starlette's directly for an unmatched path — so
    # handling only the FastAPI class means a plain 404 bypasses this and answers
    # with raw JSON instead of the styled page.
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> Response:
        # The dependencies raise 303 with a Location header to redirect
        # unauthenticated requests. Honour it.
        if exc.status_code == status.HTTP_303_SEE_OTHER and "Location" in (exc.headers or {}):
            return RedirectResponse(exc.headers["Location"], status_code=303)

        if "text/html" in request.headers.get("accept", ""):
            return templates.TemplateResponse(
                request=request,
                name="error.html",
                context={"status": exc.status_code, "detail": exc.detail},
                status_code=exc.status_code,
            )
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception) -> Response:
        # The traceback goes to the journal; the response says nothing. A stack
        # trace in a 500 body on a public security dashboard tells an attacker
        # the file layout, the library versions and often the query.
        log.exception(
            "unhandled exception",
            extra={"path": request.url.path, "request_id": getattr(request.state, "request_id", "?")},
        )
        if "text/html" in request.headers.get("accept", ""):
            return HTMLResponse(
                "<h1>Eroare internă</h1><p>Detaliile sunt în jurnalul serverului.</p>",
                status_code=500,
            )
        return JSONResponse({"error": "internal_error"}, status_code=500)

    return app
