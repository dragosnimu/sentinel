"""End-to-end request tests against the real application.

The database is stubbed, so no PostgreSQL is needed, but everything else is
genuine: the real middleware stack, the real routers, the real Jinja2 templates.
This catches the class of mistake that unit tests miss — a template that renders
in isolation but references a variable the handler does not pass, a route the
nginx vhost proxies but the app does not serve, a dependency that redirects in a
loop.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.config import Config, Secrets
from sentinel.web.security import COOKIE_NAME

SESSION_SECRET = "f" * 64


class StubDB:
    """Enough of Database for the routes exercised here."""

    def __init__(self, *, healthy: bool = True) -> None:
        self._healthy = healthy
        self.sessions: dict[str, object] = {}

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def healthy(self) -> bool:
        return self._healthy

    async def size_bytes(self) -> int:
        return 12 * 1024 * 1024

    async def fetchval(self, sql: str, *args: object):  # noqa: ANN401
        if "schema_version" in sql:
            return 9
        return None

    async def fetchrow(self, sql: str, *args: object):
        return None

    async def fetch(self, sql: str, *args: object):
        return []

    async def execute(self, sql: str, *args: object) -> str:
        return "UPDATE 1"


@pytest.fixture
def client(monkeypatch) -> TestClient:
    from sentinel.web import app as app_module

    # The lifespan builds a real Database; swap the class for the stub so the
    # app starts without PostgreSQL.
    monkeypatch.setattr(app_module, "Database", lambda cfg: StubDB())

    cfg = Config()
    cfg.web.domain = "sentinel.example.com"
    secrets = Secrets({"SENTINEL_SESSION_SECRET": SESSION_SECRET})

    # https, not http. Every cookie Sentinel sets carries `Secure`, and an HTTP
    # client will refuse to send those back over plaintext — so a test on
    # http://testserver would silently lose the session and the CSRF cookie and
    # look like a CSRF bug. In production nginx terminates TLS, so https is also
    # the accurate simulation.
    with TestClient(
        app_module.create_app(cfg, secrets), base_url="https://testserver"
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# Routes the nginx vhost proxies must actually exist
# ---------------------------------------------------------------------------
def test_healthz_is_unauthenticated_and_terse(client):
    """The root watchdog polls this to decide whether Sentinel can be trusted
    with the blocklist. It must answer without a session."""
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_healthz_reveals_nothing_useful(client):
    """A probe endpoint returning a version string is free reconnaissance."""
    body = client.get("/healthz").text
    for leak in ("sentinel", "version", "postgres", "0.", "host"):
        assert leak not in body.lower(), f"/healthz leaks {leak!r}"


def test_healthz_reports_degraded_when_the_database_is_down(monkeypatch):
    from sentinel.web import app as app_module

    monkeypatch.setattr(app_module, "Database", lambda cfg: StubDB(healthy=False))
    secrets = Secrets({"SENTINEL_SESSION_SECRET": SESSION_SECRET})
    with TestClient(app_module.create_app(Config(), secrets)) as c:
        response = c.get("/healthz")
    # 503 so the watchdog's countdown starts: a Sentinel that cannot read its
    # own database is not reasoning about the blocks it placed.
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"


def test_login_page_renders(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert "Utilizator" in response.text
    assert "Parolă" in response.text
    # The domain is shown so an operator can tell which host they are on.
    assert "sentinel.example.com" in response.text


def test_login_page_sets_a_signed_preauth_csrf_cookie(client):
    from sentinel.web.security import PREAUTH_CSRF_COOKIE

    response = client.get("/login")
    assert PREAUTH_CSRF_COOKIE in response.cookies
    # The form must carry the matching half.
    assert 'name="csrf_token"' in response.text


def test_login_page_creates_no_database_rows(client, monkeypatch):
    """Requesting the login page must not write anything.

    The obvious way to hold a CSRF token before a session exists is a throwaway
    session row — and that turns `GET /login` into an INSERT, so an attacker
    requesting the page in a loop fills the table.
    """
    calls: list[str] = []

    async def spy(sql: str, *args: object) -> str:
        calls.append(sql)
        return "INSERT 0 1"

    client.app.state.db.execute = spy  # type: ignore[attr-defined]
    client.get("/login")
    assert not calls, f"the login page issued writes: {calls}"


def test_login_page_has_no_script_tags(client):
    """P1 ships zero JavaScript, which is what lets the CSP forbid inline script
    with no exceptions."""
    body = client.get("/login").text
    assert "<script" not in body.lower()
    assert "onclick" not in body.lower()
    assert "javascript:" not in body.lower()


# ---------------------------------------------------------------------------
# Authentication is required
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", ["/", "/account"])
def test_protected_pages_redirect_to_login(client, path):
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_a_bogus_session_cookie_redirects_to_login(client):
    client.cookies.set(COOKIE_NAME, "not-a-real-token")
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_totp_page_without_a_pending_session_redirects_to_login(client):
    response = client.get("/totp", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


# ---------------------------------------------------------------------------
# Login rejections
# ---------------------------------------------------------------------------
def test_login_with_no_csrf_token_is_refused_for_a_browser(client):
    """A browser sends `Accept: text/html`, so it is bounced back to the form
    rather than shown a bare 403 — the common cause is a page left open until the
    token expired, not an attack."""
    response = client.post(
        "/login",
        data={"username": "admin", "password": "whatever"},
        headers={"accept": "text/html"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login?e=csrf"


def test_login_with_no_csrf_token_is_refused_for_an_api_client(client):
    """A non-browser client gets a plain 403; redirecting it would be useless."""
    response = client.post(
        "/login",
        data={"username": "admin", "password": "whatever"},
        headers={"accept": "application/json"},
    )
    assert response.status_code == 403
    assert response.json()["error"] == "csrf_failed"


def test_login_with_an_unknown_user_says_nothing_specific(client):
    """The message must not distinguish "no such user" from "wrong password"."""
    page = client.get("/login")
    import re

    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)

    response = client.post(
        "/login",
        data={"username": "nobody", "password": "definitely wrong", "csrf_token": token},
    )
    assert response.status_code == 401
    assert "Utilizator sau parolă incorectă" in response.text
    for leak in ("nu există", "unknown", "not found"):
        assert leak not in response.text.lower()


# ---------------------------------------------------------------------------
# Logout is reachable from a half-finished login
# ---------------------------------------------------------------------------
def test_logout_works_without_any_session(client):
    """The TOTP page's "Anulează" button posts here while the session is still
    pending. Requiring a *complete* session would redirect a pending one back to
    /totp — an infinite loop with no way to abandon a half-finished login."""
    page = client.get("/login")
    import re

    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)

    response = client.post(
        "/logout", data={"csrf_token": token}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login?e=logout"


# ---------------------------------------------------------------------------
# Error pages
# ---------------------------------------------------------------------------
def test_unknown_path_renders_the_error_page(client):
    response = client.get("/no-such-page", headers={"accept": "text/html"})
    assert response.status_code == 404
    assert "Pagina nu există" in response.text


def test_openapi_and_docs_are_disabled(client):
    """The schema would document every endpoint and parameter of a security
    dashboard to anyone who can reach the login page."""
    for path in ("/openapi.json", "/docs", "/redoc"):
        assert client.get(path).status_code == 404, f"{path} is exposed"
