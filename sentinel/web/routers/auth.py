"""Login, second factor, logout.

The flow is two POSTs with a session state change between them:

    GET  /login   → form, with a signed stateless CSRF token
    POST /login   → password checked → session created with pending_totp=true
    GET  /totp    → form (requires the pending session)
    POST /totp    → code checked → token rotated, pending_totp=false
    POST /logout  → session revoked

No database row is created until a password has actually been accepted. The
login form's CSRF token is signed rather than stored, so requesting the page in
a loop costs nothing — the obvious alternative, a throwaway session row per page
view, is a denial of service against the sessions table.

Every failure path returns the same generic message. Distinguishing "no such
user" from "wrong password" hands over the username list one guess at a time.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import RedirectResponse

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import sessions as sessions_repo
from sentinel.db.repo import users as users_repo
from sentinel.logging_setup import get_logger
from sentinel.web.deps import (
    client_ip,
    get_authenticator,
    get_config,
    get_db,
    optional_session,
    pending_session,
    user_agent,
)
from sentinel.web.security import (
    COOKIE_NAME,
    PREAUTH_CSRF_COOKIE,
    Authenticator,
    cookie_params,
    preauth_cookie_params,
)

log = get_logger(__name__)
router = APIRouter()

_ERROR_MESSAGES = {
    "csrf": "Sesiunea a expirat. Încearcă din nou.",
    "expired": "Sesiunea a expirat.",
    "logout": "Ai fost deconectat.",
}


def _render(request: Request, name: str, status_code: int = 200, **context: object) -> Response:
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request, name=name, context=context, status_code=status_code
    )


def _set_session_cookie(response: Response, token: str, cfg: Config, max_age: int) -> None:
    response.set_cookie(
        COOKIE_NAME, token, max_age=max_age, **cookie_params(cfg)  # type: ignore[arg-type]
    )


def _issue_preauth_csrf(request: Request, response: Response) -> str:
    """Set the signed CSRF cookie and return the value for the form field."""
    cookie_value, form_value = request.app.state.preauth_csrf.issue()
    response.set_cookie(
        PREAUTH_CSRF_COOKIE, cookie_value, **preauth_cookie_params()  # type: ignore[arg-type]
    )
    return form_value


def _login_page(
    request: Request,
    cfg: Config,
    *,
    error: str | None = None,
    username: str = "",
    status_code: int = 200,
) -> Response:
    # The token has to be generated before the template renders, but set on the
    # response afterwards. Render with a placeholder-free two-step instead of
    # guessing: build the response, then attach the cookie.
    cookie_value, form_value = request.app.state.preauth_csrf.issue()
    response = _render(
        request,
        "login.html",
        status_code=status_code,
        csrf_token=form_value,
        error=error,
        username=username,
        domain=cfg.web.domain,
    )
    response.set_cookie(
        PREAUTH_CSRF_COOKIE, cookie_value, **preauth_cookie_params()  # type: ignore[arg-type]
    )
    return response


# ---------------------------------------------------------------------------
@router.get("/login")
async def login_form(
    request: Request,
    cfg: Annotated[Config, Depends(get_config)],
    db: Annotated[Database, Depends(get_db)],
) -> Response:
    # Already signed in? Send them where they were going rather than showing a
    # form that would start a second session.
    token = request.cookies.get(COOKIE_NAME)
    if token:
        existing = await sessions_repo.get_by_token(db, token)
        if existing and existing.authenticated:
            return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        if existing and existing.pending_totp:
            return RedirectResponse("/totp", status_code=status.HTTP_303_SEE_OTHER)

    return _login_page(
        request, cfg, error=_ERROR_MESSAGES.get(request.query_params.get("e", ""))
    )


@router.post("/login")
async def login_submit(
    request: Request,
    auth: Annotated[Authenticator, Depends(get_authenticator)],
    cfg: Annotated[Config, Depends(get_config)],
    username: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    result = await auth.login(
        username=username,
        password=password,
        ip=client_ip(request),
        user_agent=user_agent(request),
    )

    if not result.ok:
        response = _login_page(
            request,
            cfg,
            error=result.detail_ro or "Autentificare eșuată.",
            username=username,
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
        if result.retry_after_s:
            response.headers["Retry-After"] = str(result.retry_after_s)
        return response

    assert result.session_token is not None

    if result.outcome == "needs_totp":
        response = RedirectResponse("/totp", status_code=status.HTTP_303_SEE_OTHER)
        _set_session_cookie(
            response, result.session_token, cfg, sessions_repo.PENDING_TOTP_TTL_S
        )
        # The pre-auth token has done its job; the session's own token takes over.
        response.delete_cookie(PREAUTH_CSRF_COOKIE, path="/")
        return response

    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookie(
        response,
        result.session_token,
        cfg,
        sessions_repo.cookie_max_age(cfg.web.session_ttl_s),
    )
    response.delete_cookie(PREAUTH_CSRF_COOKIE, path="/")
    return response


# ---------------------------------------------------------------------------
@router.get("/totp")
async def totp_form(
    request: Request,
    session: Annotated[sessions_repo.Session, Depends(pending_session)],
    db: Annotated[Database, Depends(get_db)],
) -> Response:
    user = await users_repo.get_by_id(db, session.user_id)
    if user is None:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    return _render(
        request, "totp.html", csrf_token=session.csrf_token, username=user.username
    )


@router.post("/totp")
async def totp_submit(
    request: Request,
    auth: Annotated[Authenticator, Depends(get_authenticator)],
    cfg: Annotated[Config, Depends(get_config)],
    db: Annotated[Database, Depends(get_db)],
    session: Annotated[sessions_repo.Session, Depends(pending_session)],
    code: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    result = await auth.verify_second_factor(
        session=session,
        code=code,
        ip=client_ip(request),
        user_agent=user_agent(request),
    )

    if not result.ok:
        # A lockout revokes the session. If that happened, back to /login.
        still_valid = await sessions_repo.get_by_token(
            db, request.cookies.get(COOKIE_NAME) or ""
        )
        if still_valid is None:
            response = RedirectResponse(
                "/login?e=expired", status_code=status.HTTP_303_SEE_OTHER
            )
            response.delete_cookie(COOKIE_NAME, path="/")
            return response

        user = await users_repo.get_by_id(db, session.user_id)
        return _render(
            request,
            "totp.html",
            status_code=status.HTTP_401_UNAUTHORIZED,
            csrf_token=still_valid.csrf_token,
            username=user.username if user else "",
            error=result.detail_ro or "Cod incorect.",
        )

    assert result.session_token is not None
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookie(
        response,
        result.session_token,
        cfg,
        sessions_repo.cookie_max_age(cfg.web.session_ttl_s),
    )
    return response


# ---------------------------------------------------------------------------
@router.post("/logout")
async def logout(
    request: Request,
    auth: Annotated[Authenticator, Depends(get_authenticator)],
    db: Annotated[Database, Depends(get_db)],
    session: Annotated[sessions_repo.Session | None, Depends(optional_session)],
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    # Deliberately `optional_session`, not `current_session`. The "Anulează"
    # button on the TOTP page posts here while the session is still pending, and
    # `current_session` would redirect a pending session back to /totp — an
    # infinite loop with no way to abandon a half-finished login.
    #
    # Logging out with no session at all is also fine: it is idempotent.
    if session is not None:
        user = await users_repo.get_by_id(db, session.user_id)
        await auth.logout(session, user.username if user else None)

    response = RedirectResponse("/login?e=logout", status_code=status.HTTP_303_SEE_OTHER)
    # Explicitly cleared rather than left to expire: a shared machine should not
    # keep a revoked token in the cookie jar.
    response.delete_cookie(COOKIE_NAME, path="/")
    response.delete_cookie(PREAUTH_CSRF_COOKIE, path="/")
    return response
