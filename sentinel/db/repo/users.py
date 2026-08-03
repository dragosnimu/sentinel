"""User accounts and the login-attempt ledger.

Nothing here decides whether a login succeeds — that is `web/security.py`. This
module only reads and writes rows, so that the policy and the storage can be
reviewed separately.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinel.db.engine import Database

ROLES = ("owner", "operator", "viewer")


@dataclass
class User:
    id: int
    username: str
    password_hash: str
    password_algo: str
    totp_secret: str | None
    totp_confirmed: bool
    totp_last_counter: int | None
    role: str
    failed_attempts: int
    locked_until: datetime | None
    disabled: bool

    @property
    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > datetime.now(timezone.utc)

    @property
    def can_log_in(self) -> bool:
        return not self.disabled and not self.is_locked

    def has_role(self, *roles: str) -> bool:
        return self.role in roles


_COLUMNS = """
    id, username, password_hash, password_algo, totp_secret, totp_confirmed,
    totp_last_counter, role, failed_attempts, locked_until, disabled
"""


def _to_user(row: Any) -> User:
    return User(**dict(row))


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------
async def get_by_username(db: Database, username: str) -> User | None:
    row = await db.fetchrow(f"SELECT {_COLUMNS} FROM users WHERE username = $1", username)
    return _to_user(row) if row else None


async def get_by_id(db: Database, user_id: int) -> User | None:
    row = await db.fetchrow(f"SELECT {_COLUMNS} FROM users WHERE id = $1", user_id)
    return _to_user(row) if row else None


async def count(db: Database) -> int:
    return int(await db.fetchval("SELECT count(*) FROM users") or 0)


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------
async def create(
    db: Database,
    *,
    username: str,
    password_hash: str,
    role: str = "owner",
    totp_secret: str | None = None,
) -> int:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    return int(
        await db.fetchval(
            """
            INSERT INTO users (username, password_hash, role, totp_secret)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            """,
            username,
            password_hash,
            role,
            totp_secret,
        )
    )


async def set_password(db: Database, user_id: int, password_hash: str) -> None:
    await db.execute(
        """
        UPDATE users
           SET password_hash = $2, password_changed_at = now(),
               failed_attempts = 0, locked_until = NULL
         WHERE id = $1
        """,
        user_id,
        password_hash,
    )


async def set_totp_secret(db: Database, user_id: int, encrypted_secret: str) -> None:
    """Store a freshly generated secret. Confirmation is a separate step.

    Until `confirm_totp` runs, the account still has `totp_confirmed = false`,
    so an interrupted enrolment cannot leave a user needing a second factor
    nobody successfully scanned.
    """
    await db.execute(
        """
        UPDATE users
           SET totp_secret = $2, totp_confirmed = false,
               totp_enrolled_at = NULL, totp_last_counter = NULL
         WHERE id = $1
        """,
        user_id,
        encrypted_secret,
    )


async def confirm_totp(db: Database, user_id: int) -> None:
    await db.execute(
        "UPDATE users SET totp_confirmed = true, totp_enrolled_at = now() WHERE id = $1",
        user_id,
    )


async def record_totp_counter(db: Database, user_id: int, counter: int) -> bool:
    """Consume a TOTP counter, refusing reuse.

    The UPDATE only matches when the new counter is strictly greater than the
    stored one, so the same code cannot be accepted twice inside its 30-second
    window — long enough for someone reading it over a shoulder, or replaying a
    captured form post. Doing the comparison in SQL rather than in Python makes
    it atomic: two simultaneous requests with the same code cannot both win.
    """
    result = await db.execute(
        """
        UPDATE users SET totp_last_counter = $2
         WHERE id = $1
           AND (totp_last_counter IS NULL OR totp_last_counter < $2)
        """,
        user_id,
        counter,
    )
    return result.endswith("1")


async def record_success(db: Database, user_id: int, ip: str | None) -> None:
    await db.execute(
        """
        UPDATE users
           SET last_login_at = now(), last_login_ip = $2::inet,
               failed_attempts = 0, locked_until = NULL
         WHERE id = $1
        """,
        user_id,
        ip,
    )


async def record_failure(
    db: Database, user_id: int, *, max_attempts: int, lockout_minutes: int
) -> tuple[int, datetime | None]:
    """Increment the failure counter and lock the account if it crosses the cap.

    Done in one statement so concurrent attempts cannot race past the threshold.
    """
    row = await db.fetchrow(
        """
        UPDATE users
           SET failed_attempts = failed_attempts + 1,
               locked_until = CASE
                   WHEN failed_attempts + 1 >= $2
                   THEN now() + make_interval(mins => $3)
                   ELSE locked_until
               END
         WHERE id = $1
        RETURNING failed_attempts, locked_until
        """,
        user_id,
        max_attempts,
        lockout_minutes,
    )
    return (row["failed_attempts"], row["locked_until"]) if row else (0, None)


# ---------------------------------------------------------------------------
# Login attempts
# ---------------------------------------------------------------------------
async def log_attempt(
    db: Database,
    *,
    username: str | None,
    ip: str | None,
    user_agent: str | None,
    result: str,
    stage: str | None = None,
    detail: str | None = None,
    session_id: str | None = None,
) -> None:
    """Record every attempt, successful or not.

    This is what answers "was that unfamiliar successful login me, travelling?"
    before anyone declares a compromise — and a run of `bad_totp` against a
    correct password is the signal that someone already has the password.
    """
    await db.execute(
        """
        INSERT INTO login_attempts (username, ip, user_agent, result, stage, detail, session_id)
        VALUES ($1, $2::inet, $3, $4, $5, $6, $7)
        """,
        username,
        ip,
        (user_agent or "")[:512] or None,
        result,
        stage,
        (detail or "")[:512] or None,
        session_id,
    )


async def recent_failures_from_ip(db: Database, ip: str | None, window_minutes: int) -> int:
    """Per-source failure count.

    Per-user lockout alone lets an attacker lock out a known username as a
    denial of service. Per-source alone lets a distributed attempt through.
    Both are checked, and the stricter one wins.
    """
    if not ip:
        return 0
    return int(
        await db.fetchval(
            """
            SELECT count(*) FROM login_attempts
             WHERE ip = $1::inet AND result <> 'ok'
               AND at >= now() - make_interval(mins => $2)
            """,
            ip,
            window_minutes,
        )
        or 0
    )


async def unlock(db: Database, username: str) -> bool:
    """Clear a lockout. The operator's escape hatch when locked out of the UI."""
    result = await db.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = $1",
        username,
    )
    return result.endswith("1")


def lockout_remaining(user: User) -> timedelta | None:
    if not user.is_locked or user.locked_until is None:
        return None
    return user.locked_until - datetime.now(timezone.utc)
