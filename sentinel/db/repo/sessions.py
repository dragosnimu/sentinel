"""Dashboard sessions.

The cookie carries an opaque 256-bit token. The database stores only its
SHA-256. A database dump therefore yields no usable sessions — the same reason
passwords are hashed, applied to the thing that is just as good as a password.

Two-stage login is a real state here (`pending_totp`), not a flag in a signed
cookie. A password-only session can reach `/totp` and nothing else, and no
amount of cookie tampering changes that, because the row itself says the
session is half-finished.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sentinel.db.engine import Database

TOKEN_BYTES = 32          # 256 bits
CSRF_BYTES = 32
# A password-only session is useless after this: enough time to read a code off
# a phone, not enough to be worth stealing.
PENDING_TOTP_TTL_S = 300


@dataclass
class Session:
    id: str
    user_id: int
    pending_totp: bool
    csrf_token: str
    expires_at: datetime
    created_at: datetime
    last_seen_at: datetime
    ip: str | None

    @property
    def expired(self) -> bool:
        return self.expires_at <= datetime.now(timezone.utc)

    @property
    def authenticated(self) -> bool:
        """Fully authenticated: both factors done, not expired."""
        return not self.pending_totp and not self.expired


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(CSRF_BYTES)


# ---------------------------------------------------------------------------
async def create(
    db: Database,
    *,
    user_id: int,
    ip: str | None,
    user_agent: str | None,
    ttl_s: int,
    pending_totp: bool,
) -> tuple[str, Session]:
    """Create a session and return (plaintext token, session).

    The plaintext token is returned exactly once, to be put in the cookie. It
    is never stored and cannot be recovered.
    """
    token = new_token()
    csrf = new_csrf_token()
    # A pending session gets a short TTL of its own: an abandoned half-login
    # should not sit around for twelve hours waiting to be picked up.
    effective_ttl = PENDING_TOTP_TTL_S if pending_totp else ttl_s

    row = await db.fetchrow(
        """
        INSERT INTO sessions (id, token_hash, csrf_token, user_id, expires_at,
                              ip, created_ip, user_agent, pending_totp)
        VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5),
                $6::inet, $6::inet, $7, $8)
        RETURNING id, user_id, pending_totp, csrf_token, expires_at,
                  created_at, last_seen_at, ip::text
        """,
        secrets.token_hex(16),          # opaque row id, not the credential
        hash_token(token),
        csrf,
        user_id,
        effective_ttl,
        ip,
        (user_agent or "")[:512] or None,
        pending_totp,
    )
    return token, Session(**dict(row))


async def get_by_token(db: Database, token: str) -> Session | None:
    """Look a session up by its plaintext token.

    Filters on `revoked_at IS NULL` and on expiry in SQL, so an expired or
    revoked session is indistinguishable from one that never existed.
    """
    if not token:
        return None
    row = await db.fetchrow(
        """
        SELECT id, user_id, pending_totp, csrf_token, expires_at,
               created_at, last_seen_at, ip::text
          FROM sessions
         WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
        """,
        hash_token(token),
    )
    return Session(**dict(row)) if row else None


async def touch(db: Database, session_id: str) -> None:
    """Update last_seen_at. Deliberately does NOT extend expiry.

    A sliding expiry means a stolen cookie stays valid for as long as the thief
    keeps using it. An absolute one puts a ceiling on the damage.
    """
    await db.execute("UPDATE sessions SET last_seen_at = now() WHERE id = $1", session_id)


async def promote(db: Database, session_id: str, ttl_s: int) -> str:
    """Second factor verified: clear `pending_totp` and issue a fresh token.

    The token is rotated rather than reused. If the pending-session cookie
    leaked between the two stages — a shared terminal, a proxy log, browser
    history — the leaked value is now worthless.

    Returns the new plaintext token.
    """
    token = new_token()
    await db.execute(
        """
        UPDATE sessions
           SET pending_totp = false,
               token_hash = $2,
               csrf_token = $3,
               expires_at = now() + make_interval(secs => $4),
               last_seen_at = now()
         WHERE id = $1
        """,
        session_id,
        hash_token(token),
        new_csrf_token(),
        ttl_s,
    )
    return token


async def revoke(db: Database, session_id: str, reason: str | None = None) -> None:
    await db.execute(
        "UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
        session_id,
    )


async def revoke_all_for_user(db: Database, user_id: int) -> int:
    """Revoke every session for a user.

    Called on password change and available to the operator when a device is
    lost. A password reset that leaves old sessions alive has not actually
    locked anyone out.
    """
    result = await db.execute(
        "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
        user_id,
    )
    return int(result.rsplit(" ", 1)[-1]) if result.startswith("UPDATE") else 0


async def active_for_user(db: Database, user_id: int) -> list[dict[str, object]]:
    rows = await db.fetch(
        """
        SELECT id, created_at, last_seen_at, expires_at, ip::text AS ip, user_agent
          FROM sessions
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
         ORDER BY last_seen_at DESC
        """,
        user_id,
    )
    return [dict(r) for r in rows]


async def purge_expired(db: Database, keep_days: int = 30) -> int:
    """Delete long-dead session rows.

    Expired rows are kept for a while on purpose: they are evidence of who was
    logged in when. Beyond `keep_days` that value is gone and they are just rows.
    """
    result = await db.execute(
        """
        DELETE FROM sessions
         WHERE (expires_at < now() - make_interval(days => $1))
            OR (revoked_at IS NOT NULL AND revoked_at < now() - make_interval(days => $1))
        """,
        keep_days,
    )
    return int(result.rsplit(" ", 1)[-1]) if result.startswith("DELETE") else 0


def cookie_max_age(ttl_s: int) -> int:
    return max(60, min(ttl_s, int(timedelta(days=30).total_seconds())))
