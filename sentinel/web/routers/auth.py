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
    # The one failure a retry can never fix. Saying "expired" here sent the
    # operator round the login loop until nginx rate-limited them with a 429,
    # and nothing on screen ever mentioned the real cause.
    "totp_key": (
        "Secretul TOTP stocat nu mai poate fi decriptat — cheia de sesiune a "
        "serverului s-a schimbat. Reînrolează pe server: "
        "sudo sentinel web --enroll-totp --username <utilizator>"
    ),
    # "locked" is NOT here: its message needs the minute count carried in the
    # `m` query param, which a fixed string in this dict cannot hold. See
    # `_login_error` below.
}

# Bounds for the `m` query param a `locked` redirect carries. It is this
# server that puts the value there, one redirect earlier -- but the browser
# hands it back on the follow-up GET, so by the time `_login_error` reads it,
# it is untrusted input like any other query param and gets validated like
# one rather than interpolated straight into the page.
_MIN_LOCK_MINUTES = 1
_MAX_LOCK_MINUTES = 1440  # a day; real lockouts (`cfg.web.lockout_minutes`) are far below this


def _lock_minutes_from_query(raw: str | None) -> int | None:
    """Parse and bound-check the `m` param on `/login?e=locked&m=N`.

    None (not an exception) for anything not a small positive integer -- a
    missing, tampered or absurd value falls back to a generic phrase in
    `_login_error` rather than showing "None minute" or blowing up the page.
    """
    if raw is None or len(raw) > 6:
        return None
    try:
        minutes = int(raw)
    except ValueError:
        return None
    return minutes if _MIN_LOCK_MINUTES <= minutes <= _MAX_LOCK_MINUTES else None


def _lock_minutes(retry_after_s: int | None) -> int:
    """Seconds to whole minutes, rounded up -- the same conversion
    `security.py` uses for `detail_ro`, so the number this redirect's `m=`
    carries is the number the operator would have been told had the session
    survived long enough to render the message directly instead of via a
    redirect.
    """
    if not retry_after_s or retry_after_s <= 0:
        return _MIN_LOCK_MINUTES
    return min((retry_after_s // 60) + 1, _MAX_LOCK_MINUTES)


def _login_error(request: Request) -> str | None:
    code = request.query_params.get("e", "")
    if code == "locked":
        minutes = _lock_minutes_from_query(request.query_params.get("m"))
        phrase = f"{minutes} minute" if minutes is not None else "câteva minute"
        return f"Cont blocat temporar. Reîncearcă în {phrase}."
    return _ERROR_MESSAGES.get(code)


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

    return _login_page(request, cfg, error=_login_error(request))


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
        if result.outcome == "locked":
            # `verify_second_factor` already revoked the session for both
            # ways a `locked` outcome can happen here -- a lock inherited
            # from another session's wrong codes, or this session's own 5th
            # wrong code just tripping it. Route straight to the locked
            # message instead of falling into the "is the session still
            # there?" check below: that check cannot tell a lock from an
            # ordinary expiry, since both leave no valid session behind, and
            # answering "expired" for a lock is what sent a locked-out
            # operator round the retry loop with no idea how long to wait
            # (S1). `retry_after_s` is always set on this outcome (both
            # branches in `security.py` set it) -- `_lock_minutes` degrading
            # to 1 is defensive, not something this path is expected to hit.
            minutes = _lock_minutes(result.retry_after_s)
            response = RedirectResponse(
                f"/login?e=locked&m={minutes}", status_code=status.HTTP_303_SEE_OTHER
            )
            if result.retry_after_s:
                response.headers["Retry-After"] = str(result.retry_after_s)
            response.delete_cookie(COOKIE_NAME, path="/")
            return response

        # The remaining failure paths revoke the session too (an
        # undecryptable secret, or the session being gone/for the wrong user
        # already) -- if that happened, back to /login.
        still_valid = await sessions_repo.get_by_token(
            db, request.cookies.get(COOKIE_NAME) or ""
        )
        if still_valid is None:
            # An undecryptable secret revokes the session too, so it arrives
            # here looking exactly like an ordinary expiry. It is not: no code
            # the operator types will ever work, and only re-enrolment fixes it.
            reason = ("totp_key" if result.outcome == "totp_undecryptable"
                      else "expired")
            response = RedirectResponse(
                f"/login?e={reason}", status_code=status.HTTP_303_SEE_OTHER
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
