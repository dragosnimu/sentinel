"""Request dependencies: session resolution and role gates.

Two rules that the rest of the web layer relies on:

* A **pending** session (password accepted, second factor not yet) resolves to
  no user anywhere except the `/totp` route. It is not "partly logged in".
* Role checks are dependencies, not inline `if` statements in handlers. A
  forgotten check in one handler is a hole; a missing dependency is a 500 during
  development and gets noticed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from sentinel.config import Config, Secrets
from sentinel.db.engine import Database
from sentinel.db.repo import sessions, users
from sentinel.web.security import COOKIE_NAME, Authenticator


def now_utc() -> datetime:
    """The request's clock, read exactly once, as a dependency.

    A handler that calls `datetime.now()` inline cannot be tested across a time
    boundary: the test picks a moment, the handler picks another a few
    milliseconds later, and once in a while those two land on opposite sides of
    an hour. On the reports page that difference decides whether the newest
    bucket has data, so the guard tests for a shipped blocker would fail at
    random — an alarm that says "the blocker is back" when it is not. A test
    that cries wolf 0.4% of the time is a test that gets ignored, and this
    repository has already paid for one that "passed for exactly three days".

    Overridable through `app.dependency_overrides`, which is the only reason it
    is a dependency and not a module function.
    """
    return datetime.now(timezone.utc)


def get_db(request: Request) -> Database:
    return request.app.state.db


def get_config(request: Request) -> Config:
    return request.app.state.config


def get_secrets(request: Request) -> Secrets:
    return request.app.state.secrets


def get_authenticator(request: Request) -> Authenticator:
    return request.app.state.authenticator


async def optional_session(
    request: Request, db: Annotated[Database, Depends(get_db)]
) -> sessions.Session | None:
    """Resolve the session cookie. Returns None if absent, expired or revoked."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    session = await sessions.get_by_token(db, token)
    if session is not None:
        request.state.session = session
    return session


async def pending_session(
    session: Annotated[sessions.Session | None, Depends(optional_session)],
) -> sessions.Session:
    """A session awaiting its second factor. Only `/totp` uses this."""
    if session is None or not session.pending_totp:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"},
        )
    return session


async def current_session(
    session: Annotated[sessions.Session | None, Depends(optional_session)],
) -> sessions.Session:
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"}
        )
    if session.pending_totp:
        # Password accepted but the second factor is outstanding. Send them to
        # finish it rather than treating this as authenticated.
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/totp"}
        )
    return session


async def current_user(
    request: Request,
    db: Annotated[Database, Depends(get_db)],
    session: Annotated[sessions.Session, Depends(current_session)],
) -> users.User:
    user = await users.get_by_id(db, session.user_id)
    if user is None or user.disabled:
        # The account was deleted or disabled while the session was live.
        # Revoke rather than serving a page to a user that no longer exists.
        await sessions.revoke(db, session.id, reason="user gone or disabled")
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"}
        )

    await sessions.touch(db, session.id)
    request.state.user = user
    return user


def require_role(*allowed: str):
    """Dependency factory gating a route on role.

    Returns 403 rather than redirecting: the user is authenticated, they simply
    may not do this. Redirecting to /login would be a confusing loop.
    """

    async def _check(user: Annotated[users.User, Depends(current_user)]) -> users.User:
        if not user.has_role(*allowed):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Rolul '{user.role}' nu are acces la această resursă.",
            )
        return user

    return _check


require_owner = require_role("owner")
require_operator = require_role("owner", "operator")
require_viewer = require_role("owner", "operator", "viewer")


def client_ip(request: Request) -> str | None:
    """The client address.

    `request.client.host` is the peer address as nginx presented it. nginx sets
    X-Real-IP from `$remote_addr` — its own peer — and never from a
    client-supplied header, so this cannot be forged by the client. If another
    proxy is ever placed in front, `set_real_ip_from` must be configured in
    nginx first; trusting the header without pinning the source would let an
    attacker choose the address that appears in the audit log and in the rate
    limiter.
    """
    forwarded = request.headers.get("x-real-ip")
    if forwarded:
        candidate = forwarded.split(",")[0].strip()
        if candidate:
            return candidate
    return request.client.host if request.client else None


def user_agent(request: Request) -> str | None:
    return request.headers.get("user-agent")
