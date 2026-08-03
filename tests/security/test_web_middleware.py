"""The HTTP middleware, exercised through real requests.

These use Starlette's TestClient against a minimal app wrapped in Sentinel's
actual middleware classes, with a stub database. No PostgreSQL required — the
point is the middleware behaviour, and the middleware is the layer a new handler
can silently bypass if it is wrong.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from sentinel.web.app import (
    CSP,
    SECURITY_HEADERS,
    CSRFMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from sentinel.web.security import COOKIE_NAME, PREAUTH_CSRF_COOKIE, PreAuthCSRF

pytestmark = pytest.mark.security

MASTER = "0" * 64


class StubSession:
    def __init__(self, csrf_token: str) -> None:
        self.id = "stub-session"
        self.user_id = 1
        self.pending_totp = False
        self.csrf_token = csrf_token


class StubDB:
    """Enough of Database for the middleware. Sessions are looked up by token."""

    def __init__(self, sessions: dict[str, StubSession] | None = None) -> None:
        self._sessions = sessions or {}

    def add_session(self, token: str, csrf_token: str) -> None:
        self._sessions[token] = StubSession(csrf_token)


async def _fake_get_by_token(db, token):  # noqa: ANN001
    return db._sessions.get(token) if token else None


@pytest.fixture
def app(monkeypatch) -> FastAPI:
    # The middleware resolves sessions through the repo; swap it for the stub.
    monkeypatch.setattr(
        "sentinel.db.repo.sessions.get_by_token", _fake_get_by_token, raising=True
    )

    application = FastAPI()
    application.add_middleware(RequestContextMiddleware)
    application.add_middleware(CSRFMiddleware)
    application.add_middleware(SecurityHeadersMiddleware)

    application.state.db = StubDB()
    application.state.preauth_csrf = PreAuthCSRF(MASTER)

    @application.get("/read")
    async def read() -> JSONResponse:
        return JSONResponse({"ok": True})

    @application.post("/write")
    async def write() -> JSONResponse:
        return JSONResponse({"written": True})

    return application


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
def test_security_headers_are_present_on_success(client):
    response = client.get("/read")
    assert response.status_code == 200
    for header in SECURITY_HEADERS:
        assert header in response.headers, f"{header} missing"


def test_csp_forbids_inline_script_and_external_origins():
    """This policy is why an XSS in the dashboard would have nowhere to go.

    It holds only because there is no CDN and no inline JavaScript. If a `<script>`
    tag or a CDN link is ever added, the correct fix is to vendor the asset, not
    to weaken this.
    """
    assert "script-src 'self'" in CSP
    assert "unsafe-inline" not in CSP
    assert "unsafe-eval" not in CSP
    assert "frame-ancestors 'none'" in CSP
    assert "object-src 'none'" in CSP
    assert "https://" not in CSP, "no external origin may appear in the CSP"


def test_headers_are_present_on_error_responses_too(client):
    """A 404 or a 500 must not be a hole in the policy."""
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert "Content-Security-Policy" in response.headers
    assert response.headers["X-Frame-Options"] == "DENY"


def test_pages_are_not_cacheable(client):
    """Every page is behind auth and shows security data.

    A shared cache holding an incident list, or a browser back-button revealing
    it after logout, would both be leaks.
    """
    response = client.get("/read")
    cache = response.headers["Cache-Control"]
    assert "no-store" in cache
    assert "private" in cache


def test_hsts_only_over_tls(client):
    """Sending HSTS over plaintext is meaningless, and on a bare-IP deployment
    would pin something the operator did not intend."""
    plain = client.get("/read")
    assert "Strict-Transport-Security" not in plain.headers

    forwarded = client.get("/read", headers={"x-forwarded-proto": "https"})
    assert "max-age=31536000" in forwarded.headers["Strict-Transport-Security"]


def test_request_id_is_returned(client):
    a = client.get("/read").headers["X-Request-Id"]
    b = client.get("/read").headers["X-Request-Id"]
    assert a and b and a != b


# ---------------------------------------------------------------------------
# CSRF — reads
# ---------------------------------------------------------------------------
def test_get_requests_need_no_token(client):
    assert client.get("/read").status_code == 200


# ---------------------------------------------------------------------------
# CSRF — session-backed
# ---------------------------------------------------------------------------
def test_post_with_a_valid_session_token_succeeds(app, client):
    app.state.db.add_session("session-token", "csrf-value")
    client.cookies.set(COOKIE_NAME, "session-token")

    response = client.post("/write", data={"csrf_token": "csrf-value"})
    assert response.status_code == 200
    assert response.json() == {"written": True}


def test_post_with_the_token_in_a_header_succeeds(app, client):
    """The header form is what an HTMX or fetch call would use."""
    app.state.db.add_session("session-token", "csrf-value")
    client.cookies.set(COOKIE_NAME, "session-token")

    response = client.post("/write", headers={"x-csrf-token": "csrf-value"})
    assert response.status_code == 200


def test_post_with_a_wrong_token_is_refused(app, client):
    app.state.db.add_session("session-token", "csrf-value")
    client.cookies.set(COOKIE_NAME, "session-token")

    response = client.post(
        "/write", data={"csrf_token": "not-the-right-one"}, headers={"accept": "application/json"}
    )
    assert response.status_code == 403
    assert response.json()["error"] == "csrf_failed"


def test_post_with_no_token_is_refused(app, client):
    app.state.db.add_session("session-token", "csrf-value")
    client.cookies.set(COOKIE_NAME, "session-token")

    response = client.post("/write", headers={"accept": "application/json"})
    assert response.status_code == 403


def test_post_with_another_sessions_token_is_refused(app, client):
    """Bound to one session, so a token lifted from another page does not work."""
    app.state.db.add_session("session-a", "csrf-a")
    app.state.db.add_session("session-b", "csrf-b")
    client.cookies.set(COOKIE_NAME, "session-a")

    response = client.post(
        "/write", data={"csrf_token": "csrf-b"}, headers={"accept": "application/json"}
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# CSRF — pre-auth (the login form, before a session exists)
# ---------------------------------------------------------------------------
def test_preauth_post_with_a_valid_signed_pair_succeeds(app, client):
    cookie_value, form_value = app.state.preauth_csrf.issue()
    client.cookies.set(PREAUTH_CSRF_COOKIE, cookie_value)

    response = client.post("/write", data={"csrf_token": form_value})
    assert response.status_code == 200


def test_preauth_post_with_no_cookie_is_refused(client):
    response = client.post(
        "/write", data={"csrf_token": "anything"}, headers={"accept": "application/json"}
    )
    assert response.status_code == 403


def test_preauth_post_with_a_forged_cookie_is_refused(app, client):
    """The cookie is signed, so a value the server never issued is refused."""
    _, form_value = app.state.preauth_csrf.issue()
    client.cookies.set(PREAUTH_CSRF_COOKIE, "i-made-this-up")

    response = client.post(
        "/write", data={"csrf_token": form_value}, headers={"accept": "application/json"}
    )
    assert response.status_code == 403


def test_preauth_post_with_mismatched_halves_is_refused(app, client):
    cookie_a, _ = app.state.preauth_csrf.issue()
    _, form_b = app.state.preauth_csrf.issue()
    client.cookies.set(PREAUTH_CSRF_COOKIE, cookie_a)

    response = client.post(
        "/write", data={"csrf_token": form_b}, headers={"accept": "application/json"}
    )
    assert response.status_code == 403


def test_preauth_cookie_signed_with_a_different_key_is_refused(app, client):
    """Simulates an attacker who knows the format but not the secret."""
    other = PreAuthCSRF("9" * 64)
    cookie_value, form_value = other.issue()
    client.cookies.set(PREAUTH_CSRF_COOKIE, cookie_value)

    response = client.post(
        "/write", data={"csrf_token": form_value}, headers={"accept": "application/json"}
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# CSRF — every mutating method, not just POST
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_all_mutating_methods_are_gated(app, method):
    """A handler added later with PUT or DELETE must not bypass the check."""
    application = FastAPI()
    application.add_middleware(CSRFMiddleware)
    application.state.db = StubDB()
    application.state.preauth_csrf = PreAuthCSRF(MASTER)

    @application.api_route("/mutate", methods=["POST", "PUT", "PATCH", "DELETE"])
    async def mutate() -> JSONResponse:
        return JSONResponse({"ok": True})

    with TestClient(application) as c:
        response = c.request(method, "/mutate", headers={"accept": "application/json"})
        assert response.status_code == 403, f"{method} was not gated by the CSRF check"


def test_html_requests_are_redirected_rather_than_shown_a_bare_403(app, client):
    """An expired token on a form left open is the common case, not an attack."""
    response = client.post(
        "/write",
        data={"csrf_token": "stale"},
        headers={"accept": "text/html"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login?e=csrf"
