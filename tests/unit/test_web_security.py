"""The dashboard's auth primitives.

These test the pure functions — hashing, TOTP, CSRF, cipher. The login flow
itself needs a database and lives in tests/integration/.
"""

from __future__ import annotations

import time

import pytest

from sentinel.web import security


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
def test_hash_and_verify_roundtrip():
    h = security.hash_password("correct horse battery staple")
    ok, needs_rehash = security.verify_password(h, "correct horse battery staple")
    assert ok
    assert not needs_rehash


def test_wrong_password_is_rejected():
    h = security.hash_password("correct horse battery staple")
    ok, _ = security.verify_password(h, "Correct horse battery staple")
    assert not ok


def test_hash_is_argon2id_and_salted():
    a = security.hash_password("same password twice")
    b = security.hash_password("same password twice")
    assert a.startswith("$argon2id$")
    # Different salts, so identical passwords do not produce identical hashes —
    # otherwise a dump reveals which accounts share a password.
    assert a != b


def test_unknown_user_still_does_the_work():
    """A None hash must still cost a full verification.

    Otherwise the response time distinguishes "no such user" from "wrong
    password", and username enumeration is the first step of a credential attack.
    """
    real = security.hash_password("a genuine password here")

    t0 = time.perf_counter()
    security.verify_password(real, "wrong guess entirely")
    known_user_duration = time.perf_counter() - t0

    t0 = time.perf_counter()
    ok, _ = security.verify_password(None, "wrong guess entirely")
    unknown_user_duration = time.perf_counter() - t0

    assert not ok
    # Generous ratio: CI timing is noisy and the point is that the dummy
    # verification actually runs, not that it takes exactly as long.
    assert unknown_user_duration > known_user_duration * 0.3, (
        "verifying an unknown user was far too fast — the dummy hash path is "
        "probably being skipped, which leaks which usernames exist"
    )


def test_unknown_user_phantom_hash_timing_closely_tracks_a_real_verification():
    """The dummy-hash path must cost close to what a real one costs, not just
    "not suspiciously fast".

    `test_unknown_user_still_does_the_work` above only guards against the
    dummy path being skipped outright (a floor of 0.3x). That leaves room for
    a "fix" that still runs the dummy hash but with cheaper parameters, or
    caches it — either would leave a gap an attacker can recover by averaging
    enough requests, which is exactly the enumeration channel this design
    exists to close.

    Failed once in a full-suite run (8 Sep 2026): Argon2 at 64 MiB is enough
    to notice memory pressure from whatever else is running on the box at the
    same moment, and that run's outlier was under 20% on medians of 5 —
    tight enough that one slow tick decided the result. Two changes here:

      * samples for the two arms are INTERLEAVED (known, unknown, known,
        unknown, ...) rather than taken as two separate blocks, so a
        transient stall lands in both arms' samples instead of skewing only
        whichever arm happened to be running through it;
      * the summary statistic is a trimmed mean over 9 samples (drop the
        single highest and lowest), not a median of 5 — one real outlier no
        longer decides the result on its own, but the bulk of the
        distribution still has to agree.

    The bound is widened to 35% to match: it is deliberately looser than the
    20% used before, in exchange for being robust to the exact failure that
    was actually observed, rather than tighter and re-flaky.
    """
    real_hash = security.hash_password("a genuine password used only for timing")

    known_samples: list[float] = []
    unknown_samples: list[float] = []
    n = 9
    for _ in range(n):
        t0 = time.perf_counter()
        security.verify_password(real_hash, "wrong guess entirely")
        known_samples.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        security.verify_password(None, "wrong guess entirely")
        unknown_samples.append(time.perf_counter() - t0)

    def _trimmed_mean(samples: list[float]) -> float:
        ordered = sorted(samples)
        trimmed = ordered[1:-1]  # drop the single highest and lowest
        return sum(trimmed) / len(trimmed)

    known = _trimmed_mean(known_samples)
    unknown = _trimmed_mean(unknown_samples)

    ratio = abs(known - unknown) / known
    assert ratio < 0.35, (
        f"known-user verification took {known:.4f}s, unknown-user (dummy hash) "
        f"took {unknown:.4f}s — a {ratio:.0%} gap is enough for an attacker "
        "averaging requests to tell which usernames exist"
    )


@pytest.mark.parametrize("password", ["", "short", "elevenchars"])
def test_short_passwords_are_refused(password):
    with pytest.raises(ValueError, match="at least"):
        security.validate_password_strength(password)


def test_absurdly_long_password_is_refused():
    """Bounded so a huge input cannot be used to burn CPU inside Argon2."""
    with pytest.raises(ValueError, match="at most"):
        security.validate_password_strength("x" * 2000)


def test_exactly_minimum_length_is_accepted():
    security.validate_password_strength("x" * security.MIN_PASSWORD_LENGTH)


# ---------------------------------------------------------------------------
# TOTP secret encryption
# ---------------------------------------------------------------------------
MASTER = "0" * 64


def test_totp_secret_is_encrypted_at_rest():
    cipher = security.TOTPCipher(MASTER)
    secret = security.generate_totp_secret()
    stored = cipher.encrypt(secret)

    # A database dump must not yield a working second factor.
    assert secret not in stored
    assert cipher.decrypt(stored) == secret


def test_totp_ciphertext_differs_each_time():
    cipher = security.TOTPCipher(MASTER)
    secret = security.generate_totp_secret()
    assert cipher.encrypt(secret) != cipher.encrypt(secret)


def test_decrypt_with_a_different_master_returns_none():
    """A rotated session secret must fail the login, not crash the handler."""
    stored = security.TOTPCipher(MASTER).encrypt("JBSWY3DPEHPK3PXP")
    assert security.TOTPCipher("1" * 64).decrypt(stored) is None


def test_decrypt_of_garbage_returns_none():
    assert security.TOTPCipher(MASTER).decrypt("not-a-fernet-token") is None


def test_short_master_secret_is_refused():
    from sentinel.errors import ConfigError

    with pytest.raises(ConfigError, match="at least 32"):
        security.TOTPCipher("tooshort")


def test_derived_keys_differ_per_purpose():
    """The TOTP key and the CSRF key must not be the same bytes.

    Reusing one secret across contexts means a weakness in one becomes a
    weakness in the other.
    """
    totp_key = security._derive_key(MASTER, b"sentinel-totp-v1")
    csrf_key = security._derive_key(MASTER, b"sentinel-preauth-csrf-v1")
    assert totp_key != csrf_key


# ---------------------------------------------------------------------------
# TOTP verification
# ---------------------------------------------------------------------------
def test_current_code_verifies_and_returns_a_counter():
    import pyotp

    secret = security.generate_totp_secret()
    code = pyotp.TOTP(secret).now()
    counter = security.verify_totp_code(secret, code)
    assert counter is not None
    assert counter == int(time.time()) // security.TOTP_INTERVAL


def test_adjacent_window_is_accepted():
    """Phone clocks drift. A user typing a code as it rolls over is not an attack."""
    import pyotp

    secret = security.generate_totp_secret()
    totp = pyotp.TOTP(secret)
    previous = totp.at(int(time.time()) - security.TOTP_INTERVAL)
    assert security.verify_totp_code(secret, previous) is not None


def test_far_out_of_window_is_rejected():
    import pyotp

    secret = security.generate_totp_secret()
    stale = pyotp.TOTP(secret).at(int(time.time()) - 600)
    assert security.verify_totp_code(secret, stale) is None


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "12 34 56", None, "  "])
def test_malformed_codes_are_rejected(code):
    secret = security.generate_totp_secret()
    assert security.verify_totp_code(secret, code) is None


def test_wrong_code_is_rejected():
    secret = security.generate_totp_secret()
    import pyotp

    actual = pyotp.TOTP(secret).now()
    wrong = "000000" if actual != "000000" else "111111"
    assert security.verify_totp_code(secret, wrong) is None


def test_counter_is_returned_so_replay_can_be_prevented():
    """Verification must expose WHICH counter matched.

    Verifying without consuming leaves the code valid for the rest of its
    30-second window — long enough to replay a captured form post.
    """
    import pyotp

    secret = security.generate_totp_secret()
    counter = security.verify_totp_code(secret, pyotp.TOTP(secret).now())
    assert isinstance(counter, int)


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
class _FakeSession:
    def __init__(self, token: str | None) -> None:
        self.csrf_token = token


def test_session_csrf_accepts_the_matching_token():
    assert security.csrf_valid(_FakeSession("abc123"), "abc123")


@pytest.mark.parametrize(
    "session_token,submitted",
    [("abc123", "wrong"), ("abc123", ""), ("abc123", None), (None, "abc"), ("", "")],
)
def test_session_csrf_rejects_everything_else(session_token, submitted):
    assert not security.csrf_valid(_FakeSession(session_token), submitted)


def test_session_csrf_rejects_when_there_is_no_session():
    assert not security.csrf_valid(None, "anything")


def test_preauth_csrf_roundtrip():
    csrf = security.PreAuthCSRF(MASTER)
    cookie, form = csrf.issue()
    assert csrf.validate(cookie, form)


def test_preauth_csrf_rejects_a_mismatched_pair():
    csrf = security.PreAuthCSRF(MASTER)
    cookie_a, _ = csrf.issue()
    _, form_b = csrf.issue()
    assert not csrf.validate(cookie_a, form_b)


def test_preauth_csrf_rejects_a_forged_cookie():
    """The cookie is signed, so a value the server did not issue is refused."""
    csrf = security.PreAuthCSRF(MASTER)
    _, form = csrf.issue()
    assert not csrf.validate("made-up-cookie-value", form)


def test_preauth_csrf_rejects_a_cookie_signed_with_another_key():
    _, form = security.PreAuthCSRF(MASTER).issue()
    cookie_other, form_other = security.PreAuthCSRF("2" * 64).issue()
    assert not security.PreAuthCSRF(MASTER).validate(cookie_other, form_other)


@pytest.mark.parametrize("cookie,form", [(None, "x"), ("x", None), (None, None), ("", "")])
def test_preauth_csrf_rejects_missing_halves(cookie, form):
    assert not security.PreAuthCSRF(MASTER).validate(cookie, form)


def test_preauth_csrf_expires():
    import itsdangerous

    csrf = security.PreAuthCSRF(MASTER)
    cookie, form = csrf.issue()
    # Force expiry by validating against a serializer with a zero max_age.
    serializer = csrf._serializer
    with pytest.raises(itsdangerous.SignatureExpired):
        serializer.loads(cookie, max_age=-1)


# ---------------------------------------------------------------------------
# Cookie flags
# ---------------------------------------------------------------------------
def test_session_cookie_flags_are_hardened():
    from sentinel.config import Config

    params = security.cookie_params(Config())
    assert params["httponly"] is True, "an XSS must not be able to read the session"
    assert params["secure"] is True, "the cookie must never travel in plaintext"
    assert params["samesite"] == "strict"


def test_secure_flag_is_not_configurable():
    """`secure` must be unconditional.

    Making it depend on a config value is how a development shortcut reaches
    production. nginx terminates TLS and the app only ever sits behind it, so
    there is no legitimate plaintext case.
    """
    import inspect

    source = inspect.getsource(security.cookie_params)
    assert '"secure": True' in source
    assert "cfg.web" not in source.split('"secure"')[1].split(",")[0]


def test_csrf_middleware_is_pure_asgi_not_basehttp():
    """CSRFMiddleware MUST NOT be a BaseHTTPMiddleware.

    It reads the request body to find the CSRF token in a form post.
    BaseHTTPMiddleware gives the endpoint a fresh receive channel, so a body
    consumed in the middleware reaches the handler empty — which blanked out
    username and password on every real login while TestClient masked it. Only a
    pure ASGI middleware can buffer the body and replay it downstream. Keep it
    that way.
    """
    from starlette.middleware.base import BaseHTTPMiddleware

    from sentinel.web.app import CSRFMiddleware

    assert not issubclass(CSRFMiddleware, BaseHTTPMiddleware), (
        "CSRFMiddleware reverted to BaseHTTPMiddleware — form bodies will reach "
        "handlers empty. It must stay a pure ASGI middleware."
    )
    # A pure ASGI middleware is constructed with the inner app and is callable as
    # (scope, receive, send).
    import inspect

    params = list(inspect.signature(CSRFMiddleware.__call__).parameters)
    assert params[1:] == ["scope", "receive", "send"], (
        f"CSRFMiddleware.__call__ must take (scope, receive, send), got {params}"
    )
