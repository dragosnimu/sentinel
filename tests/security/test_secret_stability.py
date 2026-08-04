"""Secrets that outlive an install must survive re-installing.

Two of the keys in `/etc/sentinel/secrets.env` encrypt or sign things that
persist between deploys:

    SENTINEL_SESSION_SECRET     encrypts every stored TOTP secret
    TELEGRAM_CALLBACK_HMAC_KEY  signs approval buttons sitting in a chat

Regenerating either one destroys credentials the operator still holds, and does
it silently — the dashboard says "TOTP incorrect" and gives no hint that the key
underneath it changed.

That shipped. `step_secrets` looked for an existing value in the *empty temp
file it had just created* rather than in the secrets file on disk, so the check
never matched and both keys were rewritten on **every install run**. Every
re-deploy locked the operator out of their own dashboard.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INSTALL = (REPO / "deploy" / "install.sh").read_text(encoding="utf-8")


def _func(source: str, name: str) -> str:
    m = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", source, re.S | re.M)
    assert m, f"function {name} not found"
    return m.group(0)


def test_existing_secrets_are_read_from_disk_not_from_the_new_temp_file():
    """The whole bug in one assertion: the lookup has to consult the file that
    already exists, not the one being written."""
    helper = _func(INSTALL, "existing_secret")
    assert '"${SENTINEL_CONFIG_DIR}/secrets.env"' in helper
    assert ".tmp" not in helper, "reads the temp file — the check can never match"


def test_step_secrets_consults_the_existing_file():
    body = _func(INSTALL, "step_secrets")
    assert "existing_secret" in body


def test_generated_keys_are_only_generated_when_absent():
    """`openssl rand` must sit on the else branch of "do we already have one",
    never on the straight-line path."""
    body = _func(INSTALL, "step_secrets")
    for line in body.splitlines():
        if "openssl rand" in line and not line.strip().startswith("#"):
            # The only acceptable place is inside the `else` of the presence
            # check, which the loop below verifies structurally.
            assert "value=" in line, f"unconditional key generation: {line.strip()}"
    gen = body.split("GENERATED_SECRET_KEYS[@]", 1)[1]
    assert 'if [[ -n "$value" ]]' in gen
    assert gen.index('if [[ -n "$value" ]]') < gen.index("openssl rand")


def test_both_long_lived_keys_are_covered():
    assert "GENERATED_SECRET_KEYS=(TELEGRAM_CALLBACK_HMAC_KEY SENTINEL_SESSION_SECRET)" in INSTALL


def test_an_upgrade_that_supplies_nothing_does_not_erase_working_secrets():
    """A re-run with no secrets on stdin must keep the API key and bot token
    already on the host, not drop the lines entirely."""
    body = _func(INSTALL, "step_secrets")
    operator_block = body.split("ANTHROPIC_API_KEY TELEGRAM_BOT_TOKEN", 1)[1]
    assert 'value="$(existing_secret "$key"' in operator_block


def test_generating_a_new_key_says_what_it_just_broke():
    """On a genuinely fresh host this is silent-and-correct. On a host that had
    enrolments, the operator needs to be told before they discover it at a login
    prompt."""
    body = _func(INSTALL, "step_secrets")
    assert "enroll-totp" in body
    assert "re-enrolled" in body or "reînrolat" in body


# --- and the message the operator actually sees ----------------------------
def test_an_undecryptable_secret_is_not_reported_as_an_expired_session():
    """These are opposite situations. An expired session is fixed by logging in
    again; an undecryptable secret is fixed by nothing the operator can do from
    a browser — and telling them "expired" sends them round the login loop until
    nginx answers 429."""
    auth = (REPO / "sentinel" / "web" / "routers" / "auth.py").read_text(encoding="utf-8")
    assert "totp_undecryptable" in auth
    assert '"totp_key"' in auth
    assert "enroll-totp" in auth, "the message does not say how to fix it"


# --- and the limiter that turned a bad code into a locked door -------------
NGINX = [REPO / "deploy" / "nginx" / "sentinel.conf.tmpl",
         REPO / "deploy" / "nginx" / "sentinel-shared.conf.tmpl"]


def test_a_normal_login_never_trips_the_limiter():
    """One clean login is FOUR requests: GET /login, POST /login, GET /totp,
    POST /totp. At 5r/m with burst 3 a single mistyped code earned a 429 — a
    control that locks out the defender and nobody else.

    Limiting only POSTs would be better. The documented way is a `map` that
    returns an empty key for other methods; on nginx 1.20.1 the GETs were still
    counted, so it is not used. A rate limit whose behaviour cannot be
    demonstrated does not belong in front of a login page."""
    import re as _re

    for path in NGINX:
        conf = path.read_text(encoding="utf-8")
        assert "$sentinel_login_key" not in conf, "the map that did not work is back"
        rate = int(_re.search(r"zone=sentinel_login:\d+m\s+rate=(\d+)r/m", conf).group(1))
        burst = int(_re.search(r"zone=sentinel_login burst=(\d+)", conf).group(1))
        # Two full login attempts back to back, plus room for a re-render.
        assert burst >= 8, f"{path.name}: burst={burst} is under two login flows"
        assert rate >= 20, f"{path.name}: rate={rate}r/m"


def test_the_login_limit_is_still_a_limit():
    """Loosened, not removed. The real defences are Argon2 on every attempt and
    the per-account lockout after 5 failures; this stops hammering."""
    import re as _re

    for path in NGINX:
        conf = path.read_text(encoding="utf-8")
        rate = int(_re.search(r"zone=sentinel_login:\d+m\s+rate=(\d+)r/m", conf).group(1))
        assert rate <= 60, f"{path.name}: rate={rate}r/m is not a limit"


def test_both_login_endpoints_answer_429_rather_than_503():
    """nginx defaults to 503 for a limit hit, which reads as "the server is
    broken" instead of "you are going too fast"."""
    for path in NGINX:
        conf = path.read_text(encoding="utf-8")
        for endpoint in ("location = /login", "location = /totp"):
            block = conf.split(endpoint, 1)[1].split("}", 1)[0]
            assert "limit_req_status 429" in block, f"{path.name} {endpoint}"


def test_the_distinct_outcome_exists_in_the_authenticator():
    sec = (REPO / "sentinel" / "web" / "security.py").read_text(encoding="utf-8")
    assert '"totp_undecryptable"' in sec
    # It must not be lumped in with a wrong password/code, or the router cannot
    # tell them apart after the session is revoked.
    branch = sec.split("secret = self.cipher.decrypt", 1)[1].split("counter =", 1)[0]
    assert "totp_undecryptable" in branch
