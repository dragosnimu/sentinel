"""Route-level proof that a TOTP-stage lock reaches the operator as a lock.

`test_web_login_lockout.py` exercises `Authenticator` directly and proves what
`LoginResult` carries. This file goes one layer further, through the real
FastAPI app -- middleware, router, Jinja2 templates included -- because the
round-2 defect (S1) lived entirely in `totp_submit` (`sentinel/web/routers/
auth.py`), not in `Authenticator`: `verify_second_factor` already returned
the right `LoginResult`, but the handler discarded it. It checked whether the
session was still valid (a lockout revokes it, same as an expired one) and,
finding it gone, always answered "Sesiunea a expirat." -- correct for an
expired session, wrong for a locked account, which the operator was never
told to wait for at all. A test against `Authenticator` alone cannot see that
defect; it lives entirely in what the router does with a result that was
already correct.

Both routes into `outcome == "locked"` are covered:

  * a pending session that predates a lock set by ANOTHER session's wrong
    codes (`verify_second_factor`'s `user.is_locked` branch), and
  * the 5th wrong code on THIS session, which trips the lock itself
    (`security.py`'s `record_failure` branch).

Both must end at the same place: `303` to `/login?e=locked&m=<minutes>`, a
`Retry-After` header, and a follow-up `GET` that actually shows the minute
count -- not a generic "come back later".
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pyotp
from fastapi.testclient import TestClient

from sentinel.config import Config, Secrets
from sentinel.web import security
from sentinel.web.security import COOKIE_NAME

SESSION_SECRET = "f" * 64
PASSWORD_HASH = security.hash_password("correct horse battery staple 9")
TOTP_SECRET = pyotp.random_base32()
ENCRYPTED_SECRET = security.TOTPCipher(SESSION_SECRET).encrypt(TOTP_SECRET)
PENDING_TOKEN = "pending-token"  # noqa: S105 - test fixture, not a real credential
CSRF = "csrf-tok"


def _wrong_code() -> str:
    """A six-digit code guaranteed not to match any of the currently valid
    ones for `TOTP_SECRET` (`TOTP_VALID_WINDOW` accepts three of them)."""
    for candidate in ("000000", "111111", "222222", "333333"):
        if security.verify_totp_code(TOTP_SECRET, candidate) is None:
            return candidate
    raise AssertionError("no wrong TOTP code found -- suspiciously unlucky")


class StubDB:
    """A `users` row and a `sessions` row, mutable the way Postgres would be.

    Not a general SQL engine (same rationale as the other web-route stubs in
    this repository): it answers only the queries the `/totp` and `/login`
    paths issue here, and raises on anything else so an unmodelled query
    fails loudly instead of being silently misread.
    """

    def __init__(self, *, locked_until: datetime | None, failed_attempts: int) -> None:
        self.user = {
            "id": 1, "username": "owner", "password_hash": PASSWORD_HASH,
            "password_algo": "argon2id", "totp_secret": ENCRYPTED_SECRET,
            "totp_confirmed": True, "totp_last_counter": None, "role": "owner",
            "failed_attempts": failed_attempts, "locked_until": locked_until,
            "disabled": False,
        }
        self.revoked: set[str] = set()
        self.login_attempts: list[tuple] = []

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def healthy(self) -> bool:
        return True

    async def size_bytes(self) -> int:
        return 1

    async def fetch(self, sql: str, *args: object) -> list:
        return []

    async def fetchval(self, sql: str, *args: object):
        if "schema_version" in sql:
            return 45
        return None

    async def fetchrow(self, sql: str, *args: object):
        if "SET failed_attempts = failed_attempts + 1" in sql:
            _user_id, max_attempts, lockout_minutes = args
            self.user["failed_attempts"] += 1
            if self.user["failed_attempts"] >= max_attempts:
                self.user["locked_until"] = (
                    datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
                )
            return {
                "failed_attempts": self.user["failed_attempts"],
                "locked_until": self.user["locked_until"],
            }
        if "FROM users WHERE" in sql:
            return dict(self.user)
        if "FROM sessions" in sql and "token_hash" in sql:
            if PENDING_TOKEN in self.revoked:
                return None
            now = datetime.now(timezone.utc)
            return {
                "id": "sess-1", "user_id": 1, "pending_totp": True,
                "csrf_token": CSRF, "expires_at": now + timedelta(minutes=5),
                "created_at": now, "last_seen_at": now, "ip": "1.2.3.4",
            }
        raise NotImplementedError(f"StubDB.fetchrow does not model: {sql!r}")

    async def execute(self, sql: str, *args: object) -> str:
        if "INSERT INTO login_attempts" in sql:
            self.login_attempts.append(args)
            return "INSERT 0 1"
        if "UPDATE sessions SET revoked_at" in sql:
            self.revoked.add(PENDING_TOKEN)
            return "UPDATE 1"
        raise NotImplementedError(f"StubDB.execute does not model: {sql!r}")


def _app(db: StubDB, monkeypatch):
    from sentinel.web import app as app_module

    monkeypatch.setattr(app_module, "Database", lambda cfg: db)
    cfg = Config()
    cfg.web.domain = "sentinel.example.com"
    cfg.web.max_failed_logins = 5
    cfg.web.lockout_minutes = 7
    secrets = Secrets({"SENTINEL_SESSION_SECRET": SESSION_SECRET})
    return app_module.create_app(cfg, secrets)


def _post_totp(client: TestClient, code: str):
    client.cookies.set(COOKIE_NAME, PENDING_TOKEN)
    return client.post(
        "/totp",
        data={"code": code, "csrf_token": CSRF},
        headers={"accept": "text/html"},
        follow_redirects=False,
    )


def _assert_locked_redirect(response, *, min_retry_s: int, max_retry_s: int) -> None:
    """Retry-After must fall in the given bound, and the redirect's `m=` must
    agree with it via `_lock_minutes`'s own rule (seconds -> whole minutes,
    rounded up) -- not a hardcoded minute count, which would flake the rare
    run where the lock's remaining time lands on an exact minute boundary
    (`retry_after_s == 420` rounds up to 8, same as `security.py`'s own
    `user.is_locked` branch would for the same remaining time).
    """
    assert response.status_code == 303
    retry_after = response.headers.get("retry-after")
    assert retry_after is not None, "no Retry-After header on a locked redirect"
    retry_after_s = int(retry_after)
    assert min_retry_s <= retry_after_s <= max_retry_s, retry_after_s
    expected_minutes = (retry_after_s // 60) + 1
    location = response.headers["location"]
    assert location == f"/login?e=locked&m={expected_minutes}", location


# ---------------------------------------------------------------------------
def test_totp_lock_from_a_prior_session_redirects_with_retry_time(monkeypatch):
    """A pending session that predates the lock must not be told "Sesiunea a
    expirat." -- it must be told to come back, and when.

    Falsify by reverting `totp_submit`'s `result.outcome == "locked"` branch:
    without it, this lands on `e=expired` and the follow-up page never
    mentions minutes at all.
    """
    locked_until = datetime.now(timezone.utc) + timedelta(minutes=7)
    db = StubDB(locked_until=locked_until, failed_attempts=5)
    with TestClient(_app(db, monkeypatch), base_url="https://testserver") as client:
        response = _post_totp(client, "000000")
        _assert_locked_redirect(response, min_retry_s=6 * 60, max_retry_s=7 * 60)
        location = response.headers["location"]

        client.cookies.clear()
        followup = client.get(location)
        assert followup.status_code == 200
        alert = re.search(r'role="alert">([^<]*)<', followup.text)
        assert alert is not None, "the locked redirect landed but showed no message"
        expected_minutes = int(re.search(r"m=(\d+)", location).group(1))
        assert f"{expected_minutes} minute" in alert.group(1)
        assert "expirat" not in alert.group(1).lower()


def test_totp_lock_from_the_fifth_wrong_code_redirects_with_retry_time(monkeypatch):
    """The lock tripped by THIS session's own 5th wrong code must reach the
    operator the same way as one inherited from another session.

    Falsify by dropping `retry_after_s` from `security.py`'s wrong-code
    branch (reverting it to `LoginResult("locked", detail_ro="Cont blocat
    temporar.")`): `_lock_minutes` then has nothing to compute from and the
    redirect degrades to `m=1`, understating a 7-minute lock as one.
    """
    db = StubDB(locked_until=None, failed_attempts=4)
    with TestClient(_app(db, monkeypatch), base_url="https://testserver") as client:
        response = _post_totp(client, _wrong_code())
        _assert_locked_redirect(response, min_retry_s=6 * 60, max_retry_s=7 * 60)
        assert db.user["locked_until"] is not None, (
            "the 5th wrong code did not lock the account"
        )
        location = response.headers["location"]

        client.cookies.clear()
        followup = client.get(location)
        alert = re.search(r'role="alert">([^<]*)<', followup.text)
        assert alert is not None
        expected_minutes = int(re.search(r"m=(\d+)", location).group(1))
        assert f"{expected_minutes} minute" in alert.group(1)


# ---------------------------------------------------------------------------
def test_login_locked_error_falls_back_to_a_generic_phrase_without_a_valid_m(monkeypatch):
    """A tampered, missing or out-of-range `m` must not show a literal `None`
    or blow up the login page -- it degrades to "câteva minute" rather than
    trusting whatever the query string says.
    """
    db = StubDB(locked_until=None, failed_attempts=0)
    with TestClient(_app(db, monkeypatch), base_url="https://testserver") as client:
        for bogus in ("/login?e=locked", "/login?e=locked&m=-3", "/login?e=locked&m=nine"):
            page = client.get(bogus)
            assert page.status_code == 200
            alert = re.search(r'role="alert">([^<]*)<', page.text)
            assert alert is not None, bogus
            assert "câteva minute" in alert.group(1), bogus
