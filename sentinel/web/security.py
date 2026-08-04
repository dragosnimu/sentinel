"""Authentication and session policy for the dashboard.

The dashboard is publicly reachable over HTTPS, which makes this the most
exposed decision-making code in Sentinel. Everything here is written to fail
closed.

Five properties worth understanding before changing anything:

1. **Constant-work login.** An unknown username still costs a full Argon2
   verification against a dummy hash. Otherwise the response time tells an
   attacker which usernames exist, and user enumeration is the first step of
   every credential attack.

2. **TOTP secrets are encrypted at rest**, with a key derived from
   `SENTINEL_SESSION_SECRET` — not stored in plaintext. A database dump alone
   therefore does not yield working second factors, which is the entire point of
   having a second factor.

3. **TOTP codes cannot be replayed.** The accepted counter is consumed in the
   database with a strictly-greater-than check, so the same code cannot be used
   twice inside its 30-second window.

4. **Two-stage login is a database state**, not a cookie flag. A password-only
   session can reach `/totp` and nothing else.

5. **Lockout is per-user AND per-source.** Per-user alone is a denial-of-service
   vector against a known username; per-source alone lets a distributed attempt
   through.
"""

from __future__ import annotations

import base64
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from argon2.low_level import Type
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sentinel.config import Config, Secrets
from sentinel.db.repo import audit, sessions, users
from sentinel.errors import ConfigError
from sentinel.logging_setup import get_logger

if TYPE_CHECKING:
    # Only needed for an annotation. Keeping it behind TYPE_CHECKING means the
    # password, TOTP and CSRF primitives below can be imported — and reviewed,
    # and unit-tested — without a database driver present.
    from sentinel.db.engine import Database

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
# Argon2id, tuned for a small shared VPS. 64 MB and 3 passes takes roughly
# 100-200 ms on a modest core — slow enough that offline cracking is expensive,
# fast enough that a login is not noticeable.
#
# Memory is the constraint that matters here: 64 MB is allocated per concurrent
# verification. nginx rate-limits /login to 5/min per address, and the lockout
# below caps it further, so the worst realistic case is a handful at once. Do
# not raise memory_cost without re-checking that arithmetic against the host's
# available RAM.
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,      # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

# Verified when the username does not exist, so the work done is the same either
# way. Generated once at import from a random password — never a real hash.
_DUMMY_HASH = _HASHER.hash(secrets.token_urlsafe(32))

MIN_PASSWORD_LENGTH = 12

TOTP_DIGITS = 6
TOTP_INTERVAL = 30
# Accept the adjacent window on each side: phone clocks drift, and a user typing
# a code as it rolls over should not be told their password is wrong.
TOTP_VALID_WINDOW = 1

# Per-source failure ceiling, independent of per-user lockout.
IP_FAILURE_WINDOW_MINUTES = 15
IP_FAILURE_LIMIT = 20

LoginOutcome = Literal[
    "ok", "needs_totp", "bad_credentials", "locked", "disabled", "ip_throttled",
    "no_totp_enrolled", "totp_undecryptable",
]


@dataclass
class LoginResult:
    outcome: LoginOutcome
    user: users.User | None = None
    session_token: str | None = None
    csrf_token: str | None = None
    detail_ro: str | None = None
    retry_after_s: int | None = None

    @property
    def ok(self) -> bool:
        return self.outcome in ("ok", "needs_totp")


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------
def _derive_key(master: str, info: bytes) -> bytes:
    """HKDF-SHA256 subkey from the master secret.

    One master secret in `secrets.env`, separate subkeys per purpose. Reusing
    the same bytes for cookie signing and for TOTP encryption would mean a
    weakness in one context becomes a weakness in the other.
    """
    if len(master) < 32:
        raise ConfigError(
            "SENTINEL_SESSION_SECRET must be at least 32 characters. "
            "install.sh generates one with `openssl rand -hex 32`."
        )
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(master.encode())
    return base64.urlsafe_b64encode(derived)


class TOTPCipher:
    """Encrypts TOTP secrets at rest."""

    def __init__(self, master_secret: str) -> None:
        self._fernet = Fernet(_derive_key(master_secret, b"sentinel-totp-v1"))

    def encrypt(self, secret: str) -> str:
        return self._fernet.encrypt(secret.encode()).decode()

    def decrypt(self, token: str) -> str | None:
        """Returns None on failure rather than raising.

        A secret that cannot be decrypted means the session secret was rotated
        or the row was tampered with. Either way the correct behaviour is to
        refuse the login, not to crash the request handler.
        """
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except (InvalidToken, ValueError):
            log.error(
                "a stored TOTP secret could not be decrypted; "
                "SENTINEL_SESSION_SECRET may have been rotated"
            )
            return None


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    validate_password_strength(password)
    return _HASHER.hash(password)


def verify_password(stored_hash: str | None, password: str) -> tuple[bool, bool]:
    """Verify a password. Returns (ok, needs_rehash).

    When `stored_hash` is None — an unknown username — a dummy verification runs
    anyway so the timing is indistinguishable.
    """
    target = stored_hash or _DUMMY_HASH
    try:
        _HASHER.verify(target, password)
    except (VerifyMismatchError, InvalidHashError):
        return False, False
    except Exception:  # noqa: BLE001 - a hashing failure must not 500 the login
        log.exception("password verification raised")
        return False, False

    if stored_hash is None:
        # The dummy matched, which can only happen if someone guessed a
        # 32-byte urlsafe token. Treat as failure regardless.
        return False, False

    return True, _HASHER.check_needs_rehash(stored_hash)


def validate_password_strength(password: str) -> None:
    """Length only, deliberately.

    Composition rules ("one uppercase, one symbol") push people towards
    `Password1!` and are not what NIST has recommended since 2017. Length plus
    a slow hash plus lockout is the combination that actually helps.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > 1024:
        # Bounded so an enormous input cannot be used to burn CPU in Argon2.
        raise ValueError("password must be at most 1024 characters")


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------
def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, username: str, issuer: str) -> str:
    return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL).provisioning_uri(
        name=username, issuer_name=issuer
    )


def verify_totp_code(secret: str, code: str) -> int | None:
    """Verify a code. Returns the consumed counter, or None.

    The counter is returned so the caller can consume it in the database and
    refuse a replay. Verifying without consuming leaves the code valid for the
    remainder of its window.
    """
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return None

    totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL)
    now = int(time.time())

    # Check the accepted window explicitly rather than relying on
    # `verify(valid_window=...)`, because we need to know WHICH counter matched.
    for offset in range(-TOTP_VALID_WINDOW, TOTP_VALID_WINDOW + 1):
        at = now + offset * TOTP_INTERVAL
        if hmac.compare_digest(totp.at(at), code):
            return at // TOTP_INTERVAL
    return None


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
class Authenticator:
    def __init__(self, db: "Database", cfg: Config, secrets_store: Secrets) -> None:
        self.db = db
        self.cfg = cfg
        self.cipher = TOTPCipher(secrets_store.require("SENTINEL_SESSION_SECRET"))

    async def login(
        self, *, username: str, password: str, ip: str | None, user_agent: str | None
    ) -> LoginResult:
        """Stage one: username and password."""
        username = (username or "").strip()[:64]

        # Per-source throttle first, before any expensive work. A distributed
        # attempt against many usernames never trips a per-user lockout.
        ip_failures = await users.recent_failures_from_ip(
            self.db, ip, IP_FAILURE_WINDOW_MINUTES
        )
        if ip_failures >= IP_FAILURE_LIMIT:
            await users.log_attempt(
                self.db, username=username, ip=ip, user_agent=user_agent,
                result="locked", stage="password", detail="ip throttled",
            )
            return LoginResult(
                "ip_throttled",
                detail_ro="Prea multe încercări din această rețea. Reîncearcă mai târziu.",
                retry_after_s=IP_FAILURE_WINDOW_MINUTES * 60,
            )

        user = await users.get_by_username(self.db, username)

        # Always verify, even with no user, so the timing is flat.
        password_ok, needs_rehash = verify_password(
            user.password_hash if user else None, password
        )

        if user is None or not password_ok:
            if user is not None:
                attempts, locked_until = await users.record_failure(
                    self.db,
                    user.id,
                    max_attempts=self.cfg.web.max_failed_logins,
                    lockout_minutes=self.cfg.web.lockout_minutes,
                )
                detail = f"attempt {attempts}/{self.cfg.web.max_failed_logins}"
                if locked_until is not None:
                    detail += " (locked)"
            else:
                detail = "unknown user"

            await users.log_attempt(
                self.db, username=username, ip=ip, user_agent=user_agent,
                result="bad_password" if user else "unknown_user",
                stage="password", detail=detail,
            )
            # One message for both cases. "No such user" would give away the
            # username list one guess at a time.
            return LoginResult(
                "bad_credentials", detail_ro="Utilizator sau parolă incorectă."
            )

        if user.disabled:
            await users.log_attempt(
                self.db, username=username, ip=ip, user_agent=user_agent,
                result="locked", stage="password", detail="account disabled",
            )
            return LoginResult("disabled", detail_ro="Cont dezactivat.")

        if user.is_locked:
            remaining = users.lockout_remaining(user)
            minutes = int((remaining.total_seconds() // 60) + 1) if remaining else 1
            await users.log_attempt(
                self.db, username=username, ip=ip, user_agent=user_agent,
                result="locked", stage="password", detail="locked out",
            )
            return LoginResult(
                "locked",
                detail_ro=f"Cont blocat temporar. Reîncearcă în {minutes} minute.",
                retry_after_s=int(remaining.total_seconds()) if remaining else 60,
            )

        if needs_rehash:
            # The cost parameters changed since this password was set. Upgrade
            # transparently — the alternative is asking everyone to reset.
            await users.set_password(self.db, user.id, _HASHER.hash(password))
            log.info("password hash upgraded", extra={"user": username})

        # ---- second factor ----
        if self.cfg.web.require_totp:
            if not user.totp_confirmed or not user.totp_secret:
                await users.log_attempt(
                    self.db, username=username, ip=ip, user_agent=user_agent,
                    result="locked", stage="password", detail="totp not enrolled",
                )
                # Refuse rather than letting them in with one factor. An account
                # that skipped enrolment is a hole, not a convenience.
                return LoginResult(
                    "no_totp_enrolled",
                    detail_ro=(
                        "Contul nu are al doilea factor configurat. "
                        "Rulează pe server: sentinel web --enroll-totp "
                        f"--username {username}"
                    ),
                )

            token, session = await sessions.create(
                self.db, user_id=user.id, ip=ip, user_agent=user_agent,
                ttl_s=self.cfg.web.session_ttl_s, pending_totp=True,
            )
            await users.log_attempt(
                self.db, username=username, ip=ip, user_agent=user_agent,
                result="ok", stage="password", detail="awaiting totp",
                session_id=session.id,
            )
            return LoginResult(
                "needs_totp", user=user,
                session_token=token, csrf_token=session.csrf_token,
            )

        # TOTP disabled in config. Supported, but the installer sets it true and
        # the docs say to leave it that way.
        token, session = await sessions.create(
            self.db, user_id=user.id, ip=ip, user_agent=user_agent,
            ttl_s=self.cfg.web.session_ttl_s, pending_totp=False,
        )
        await self._finish_login(user, ip, user_agent, session.id, single_factor=True)
        return LoginResult(
            "ok", user=user, session_token=token, csrf_token=session.csrf_token
        )

    async def verify_second_factor(
        self,
        *,
        session: sessions.Session,
        code: str,
        ip: str | None,
        user_agent: str | None,
    ) -> LoginResult:
        """Stage two: the TOTP code."""
        user = await users.get_by_id(self.db, session.user_id)
        if user is None or not user.can_log_in:
            await sessions.revoke(self.db, session.id)
            return LoginResult("bad_credentials", detail_ro="Sesiune invalidă.")

        secret = self.cipher.decrypt(user.totp_secret) if user.totp_secret else None
        if secret is None:
            # Not a wrong code and not an expired session: the stored secret
            # cannot be decrypted at all, which means SENTINEL_SESSION_SECRET
            # changed under it. No retry will ever succeed, so the operator has
            # to be told that rather than left guessing — `totp_undecryptable`
            # is what carries that fact past the session revocation below.
            await sessions.revoke(self.db, session.id)
            return LoginResult(
                "totp_undecryptable",
                detail_ro="Secretul TOTP nu poate fi decriptat. Trebuie reînrolat pe server.",
            )

        counter = verify_totp_code(secret, code)
        if counter is None:
            attempts, locked_until = await users.record_failure(
                self.db,
                user.id,
                max_attempts=self.cfg.web.max_failed_logins,
                lockout_minutes=self.cfg.web.lockout_minutes,
            )
            await users.log_attempt(
                self.db, username=user.username, ip=ip, user_agent=user_agent,
                result="bad_totp", stage="totp",
                detail=f"attempt {attempts}/{self.cfg.web.max_failed_logins}",
                session_id=session.id,
            )
            if locked_until is not None:
                await sessions.revoke(self.db, session.id)
                return LoginResult("locked", detail_ro="Cont blocat temporar.")
            return LoginResult("bad_credentials", detail_ro="Cod incorect.")

        # Consume the counter. If this fails the code was already used — a
        # replay inside the same 30-second window.
        if not await users.record_totp_counter(self.db, user.id, counter):
            await users.log_attempt(
                self.db, username=user.username, ip=ip, user_agent=user_agent,
                result="bad_totp", stage="totp", detail="code reuse",
                session_id=session.id,
            )
            return LoginResult(
                "bad_credentials",
                detail_ro="Cod deja folosit. Așteaptă următorul cod.",
            )

        # Rotate the token: a pending cookie that leaked between stages is now
        # worthless.
        new_token = await sessions.promote(
            self.db, session.id, self.cfg.web.session_ttl_s
        )
        refreshed = await sessions.get_by_token(self.db, new_token)

        await self._finish_login(user, ip, user_agent, session.id, single_factor=False)
        return LoginResult(
            "ok",
            user=user,
            session_token=new_token,
            csrf_token=refreshed.csrf_token if refreshed else None,
        )

    async def _finish_login(
        self,
        user: users.User,
        ip: str | None,
        user_agent: str | None,
        session_id: str,
        *,
        single_factor: bool,
    ) -> None:
        await users.record_success(self.db, user.id, ip)
        await users.log_attempt(
            self.db, username=user.username, ip=ip, user_agent=user_agent,
            result="ok", stage="totp" if not single_factor else "password",
            session_id=session_id,
        )
        await audit.record(
            self.db,
            actor=f"web:{user.username}",
            source="web",
            operation="login",
            target=ip,
            params={"single_factor": single_factor, "role": user.role},
            result="ok",
        )

    async def logout(self, session: sessions.Session, username: str | None = None) -> None:
        await sessions.revoke(self.db, session.id, reason="logout")
        await audit.record(
            self.db,
            actor=f"web:{username or session.user_id}",
            source="web",
            operation="logout",
            result="ok",
        )


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
def csrf_valid(session: sessions.Session | None, submitted: str | None) -> bool:
    """Compare the submitted token with the session's, in constant time."""
    if session is None or not session.csrf_token or not submitted:
        return False
    return hmac.compare_digest(session.csrf_token, submitted)


PREAUTH_CSRF_COOKIE = "sentinel_csrf"
PREAUTH_CSRF_TTL_S = 900


class PreAuthCSRF:
    """Stateless CSRF for the login and TOTP forms.

    The login form needs a CSRF token before a session exists. The obvious
    approach — create a throwaway session row to hold one — is a denial of
    service: every `GET /login` becomes an INSERT, and an attacker requesting
    the page ten thousand times a minute fills the table.

    So the pre-auth token is signed rather than stored. The cookie holds a
    signed, timestamped nonce; the form holds the bare nonce; both must agree
    and the signature must verify. No database write, nothing to exhaust.

    Post-authentication forms use the session's own token instead, which is
    strictly better because it is bound to one specific session.
    """

    def __init__(self, master_secret: str) -> None:
        from itsdangerous import URLSafeTimedSerializer

        key = _derive_key(master_secret, b"sentinel-preauth-csrf-v1")
        self._serializer = URLSafeTimedSerializer(key.decode(), salt="preauth-csrf")

    def issue(self) -> tuple[str, str]:
        """Returns (cookie_value, form_value)."""
        nonce = secrets.token_urlsafe(24)
        return self._serializer.dumps(nonce), nonce

    def validate(self, cookie_value: str | None, form_value: str | None) -> bool:
        if not cookie_value or not form_value:
            return False
        try:
            nonce = self._serializer.loads(cookie_value, max_age=PREAUTH_CSRF_TTL_S)
        except Exception:  # noqa: BLE001 - bad signature, expired, malformed: all invalid
            return False
        return hmac.compare_digest(str(nonce), form_value)


# ---------------------------------------------------------------------------
# Cookie
# ---------------------------------------------------------------------------
COOKIE_NAME = "sentinel_session"


def cookie_params(cfg: Config) -> dict[str, object]:
    """Cookie flags. `secure` is unconditional.

    nginx redirects HTTP to HTTPS and the app only ever sits behind it, so there
    is no legitimate plaintext case. Making `secure` conditional on a config
    value is how a development shortcut ends up in production.
    """
    return {
        "httponly": True,      # no JavaScript access, so an XSS cannot read it
        "secure": True,
        "samesite": "strict",  # not sent on cross-site navigation
        "path": "/",
    }


def preauth_cookie_params() -> dict[str, object]:
    # Same flags. `samesite=lax` rather than `strict` so the cookie survives a
    # redirect back to /login from an external link; the signature is what makes
    # it safe, not the SameSite mode.
    return {
        "httponly": True,
        "secure": True,
        "samesite": "lax",
        "path": "/",
        "max_age": PREAUTH_CSRF_TTL_S,
    }
