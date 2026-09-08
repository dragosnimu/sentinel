"""The password-stage lockout, exercised through the real `Authenticator`.

CONFIRMED findings (audit, 8 Sep 2026, round 1):

  * W1 — `verify_password` ran before the lockout check, so "locked, wrong
    password" and "locked, right password" produced different outcomes. That
    makes lockout a password oracle, and because the lock was per-account
    (not per-source), anyone who knew the username could keep the real owner
    locked out with five POSTs every fifteen minutes from anywhere.
  * W2 — the per-source throttle wrote its own refusal into `login_attempts`,
    the very table it counts. One request every few minutes kept a source
    throttled forever with no password ever checked.

Round 1 fixed both, and round 2 (verifier findings, 8 Sep 2026) fixed three
more, all reproduced here:

  * W-F1 — `sentinel web --unlock`/`--set-password` reset the TOTP-stage
    columns on `users` but never touched the password-stage window, which
    lives entirely in `login_attempts`. The CLI reported the lockout gone
    while the very next correct login from the throttled source was still
    refused.
  * W-F2 — three mutations of the (account, source) window's SQL survived
    every round-1 test because `FakeDB` reimplemented the filter in Python
    instead of exercising the query text: dropping the account scope,
    skipping `verify_password` on the locked branch, and loosening the
    `result` predicate. `FakeDB` below still filters in Python (a real SQL
    engine is not worth the weight here for the tests that do not need
    Postgres semantics), but the dispatch that recognises each query now
    requires the exact clauses that matter, so a mutation that drops one
    stops matching and errors loudly instead of silently mis-dispatching.
    `tests/integration/test_login_attempts_sql_pg.py` runs the real SQL
    against real Postgres for the case that needs it.
  * W-F4 — with `locked_until` set, `login()` no longer checked `is_locked`
    at all, so a TOTP-locked owner reached `/totp` and was told "Sesiune
    invalidă." with no indication it was a lock, let alone for how long.

This file proves the fix with a fake database, not real Postgres — the
queries `sentinel/web/security.py` issues are fixed strings, so a small
in-memory model of `users` / `login_attempts` / `sessions` is enough to run
`Authenticator.login` and `Authenticator.verify_second_factor` for real and
observe what they actually do.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime, timedelta, timezone
from unittest import mock

import pyotp

from sentinel.config import Config, Secrets, WebConfig
from sentinel.db.repo import users
from sentinel.db.repo.sessions import Session
from sentinel.web import security

MASTER = "0" * 64
PASSWORD = "correct horse battery staple 9"


# ---------------------------------------------------------------------------
# A fake database, scoped to exactly the queries the login path issues.
# ---------------------------------------------------------------------------
_USER_COLUMNS = (
    "id", "username", "password_hash", "password_algo", "totp_secret",
    "totp_confirmed", "totp_last_counter", "role", "failed_attempts",
    "locked_until", "disabled",
)


class FakeDB:
    """An in-memory stand-in with the same call shape as `sentinel.db.engine.Database`.

    Deliberately NOT a general SQL engine: it recognises the handful of query
    shapes `security.py`/`users.py`/`sessions.py` actually send during a
    password-stage login, and raises on anything else. A query this test never
    expected to see is exactly the kind of surprise a mock should surface, not
    swallow.

    Time is virtual (`now_minutes`), so a 15-minute window can be aged past
    without a real `sleep`.
    """

    def __init__(self) -> None:
        self._users: dict[str, dict] = {}
        self._next_id = 1
        self.login_attempts: list[dict] = []
        self.sessions: dict[str, dict] = {}
        self.audit_log: list[dict] = []
        self.now_minutes = 1000.0

    def add_user(self, *, username: str, password_hash: str, **overrides) -> dict:
        row = {
            "id": self._next_id,
            "username": username,
            "password_hash": password_hash,
            "password_algo": "argon2id",
            "totp_secret": None,
            "totp_confirmed": False,
            "totp_last_counter": None,
            "role": "owner",
            "failed_attempts": 0,
            "locked_until": None,
            "disabled": False,
            # Not a real column read by `_COLUMNS` (`users.get_by_username`
            # never selects it), but tracked here in the same virtual-minutes
            # clock as `login_attempts` so the account-window query below can
            # honour it exactly as `recent_failures_for_account_from_ip` does.
            "lock_reset_at": None,
        }
        row.update(overrides)
        self._next_id += 1
        self._users[username] = row
        return row

    def seed_bad_password(self, *, username: str, ip: str, minutes_ago: float) -> None:
        """A REAL, verified wrong-password row -- the only kind that may count
        towards the per-(account, source) window (see `users.py`)."""
        self.login_attempts.append({
            "username": username, "ip": ip, "stage": "password",
            "result": "bad_password", "at_minutes": self.now_minutes - minutes_ago,
        })

    def add_pending_session(self, sid: str, user_id: int) -> Session:
        """A pending-TOTP session created outside `login()`.

        Used for the W-F4 test that reaches `verify_second_factor` directly
        with a session for an account that is ALREADY locked -- the case
        `login()`'s own guard (which now refuses before minting a session for
        a locked account) cannot cover, because this session is modelled as
        having existed since before the lock.
        """
        now = datetime.now(timezone.utc)
        self.sessions[sid] = {
            "id": sid, "user_id": user_id, "pending_totp": True,
            "revoked_at": None,
        }
        return Session(
            id=sid, user_id=user_id, pending_totp=True, csrf_token="csrf-tok",
            expires_at=now + timedelta(minutes=5), created_at=now,
            last_seen_at=now, ip="9.9.9.9",
        )

    # -- Database protocol --------------------------------------------------
    async def fetchrow(self, sql: str, *args):
        if "FROM users WHERE username" in sql:
            row = self._users.get(args[0])
            return {k: row[k] for k in _USER_COLUMNS} if row else None
        if "FROM users WHERE id" in sql:
            for row in self._users.values():
                if row["id"] == args[0]:
                    return {k: row[k] for k in _USER_COLUMNS}
            return None
        if "SET failed_attempts = failed_attempts + 1" in sql:
            # `users.record_failure` -- the TOTP-stage counter, bumped on a
            # wrong code. Real `locked_until` (wall clock), not the virtual
            # `now_minutes` used for aging `login_attempts` rows: the callers
            # that read it back (`security.py`'s wrong-code branch) compute a
            # retry time with `datetime.now(timezone.utc)`.
            user_id, max_attempts, lockout_minutes = args
            for row in self._users.values():
                if row["id"] == user_id:
                    row["failed_attempts"] += 1
                    if row["failed_attempts"] >= max_attempts:
                        row["locked_until"] = (
                            datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
                        )
                    return {
                        "failed_attempts": row["failed_attempts"],
                        "locked_until": row["locked_until"],
                    }
            return None
        if "INSERT INTO sessions" in sql:
            (sid, token_hash, csrf, user_id, ttl_s, ip, ua, pending) = args
            now = datetime.now(timezone.utc)
            session = {
                "id": sid, "user_id": user_id, "pending_totp": pending,
                "csrf_token": csrf, "expires_at": now, "created_at": now,
                "last_seen_at": now, "ip": ip,
            }
            self.sessions[sid] = {**session, "token_hash": token_hash}
            return dict(session)
        raise NotImplementedError(f"FakeDB.fetchrow does not model: {sql!r}")

    @contextlib.asynccontextmanager
    async def transaction(self):
        # `audit.record` writes inside a transaction it acquires on `db`; the
        # fake does not need real atomicity, only the same call shape.
        yield self

    async def fetchval(self, sql: str, *args):
        if "entry_hash FROM audit_log ORDER BY id DESC" in sql:
            return self.audit_log[-1]["entry_hash"] if self.audit_log else None
        if "INSERT INTO audit_log" in sql:
            entry = {"id": len(self.audit_log) + 1, "entry_hash": args[-1]}
            self.audit_log.append(entry)
            return entry["id"]
        if "FROM login_attempts la" in sql and "JOIN users u" in sql:
            # Dispatch requires each clause that the real (account, source)
            # window depends on to be present, verbatim, in the SQL text --
            # not just "some query against login_attempts and users". A
            # mutation that drops `la.username = $1` (W-F2 M1, source-only
            # scoping) or loosens `la.result = 'bad_password'` (W-F2 M3) stops
            # matching here and falls through to `NotImplementedError` below,
            # rather than being silently answered by a Python-side filter
            # that still enforces the predicate the SQL no longer has.
            required = (
                "la.username = $1", "la.ip = $2::inet",
                "la.stage = 'password'", "la.result = 'bad_password'",
                "la.at >= now() - make_interval(mins => $3)",
                "COALESCE(u.lock_reset_at", "-infinity",
            )
            if not all(clause in sql for clause in required):
                raise NotImplementedError(
                    f"FakeDB.fetchval: account-window query is missing an "
                    f"expected clause -- {sql!r}"
                )
            username, ip, window = args
            floor = self.now_minutes - window
            user_row = self._users.get(username)
            lock_reset = user_row.get("lock_reset_at") if user_row else None
            return sum(
                1 for a in self.login_attempts
                if a["username"] == username and a["ip"] == ip
                and a["stage"] == "password" and a["result"] == "bad_password"
                and a["at_minutes"] >= floor
                and (lock_reset is None or a["at_minutes"] >= lock_reset)
            )
        if "SELECT count(*) FROM login_attempts" in sql and "ip = $1::inet AND result" in sql:
            ip, window = args
            floor = self.now_minutes - window
            return sum(
                1 for a in self.login_attempts
                if a["ip"] == ip and a["result"] != "ok" and a["at_minutes"] >= floor
            )
        raise NotImplementedError(f"FakeDB.fetchval does not model: {sql!r}")

    async def execute(self, sql: str, *args) -> str:
        if "INSERT INTO login_attempts" in sql:
            username, ip, _ua, result, stage, _detail, _session_id = args
            self.login_attempts.append({
                "username": username, "ip": ip, "stage": stage,
                "result": result, "at_minutes": self.now_minutes,
            })
            return "INSERT 0 1"
        if "SET last_login_at = now()" in sql:
            return "UPDATE 1"
        if "SET failed_attempts = 0, locked_until = NULL, lock_reset_at = now()" in sql:
            # `users.unlock` (W-F1): the password-stage window's read side
            # (above) is what makes this bump matter -- without it, this
            # branch alone still leaves the account refused.
            (username,) = args
            row = self._users.get(username)
            if row is None:
                return "UPDATE 0"
            row["failed_attempts"] = 0
            row["locked_until"] = None
            row["lock_reset_at"] = self.now_minutes
            return "UPDATE 1"
        if "SET password_hash = $2" in sql and "lock_reset_at = now()" in sql:
            # `users.set_password` (W-F1 also applies here: a freshly reset
            # password must not inherit the old one's (account, source) lock).
            user_id, password_hash = args
            for row in self._users.values():
                if row["id"] == user_id:
                    row["password_hash"] = password_hash
                    row["failed_attempts"] = 0
                    row["locked_until"] = None
                    row["lock_reset_at"] = self.now_minutes
                    return "UPDATE 1"
            return "UPDATE 0"
        if "UPDATE sessions SET revoked_at = now()" in sql:
            (session_id,) = args
            row = self.sessions.get(session_id)
            if row is not None:
                row["revoked_at"] = self.now_minutes
            return "UPDATE 1" if row is not None else "UPDATE 0"
        raise NotImplementedError(f"FakeDB.execute does not model: {sql!r}")


def _auth(db: FakeDB, **web_overrides) -> security.Authenticator:
    # `setdefault`, not a literal kwarg, so a caller CAN override
    # `require_totp` (needed for the W-F4 tests below) without Python raising
    # "got multiple values for keyword argument" on the clash.
    web_overrides.setdefault("require_totp", False)
    web_overrides.setdefault("max_failed_logins", 5)
    cfg = Config(web=WebConfig(**web_overrides))
    return security.Authenticator(db, cfg, Secrets({"SENTINEL_SESSION_SECRET": MASTER}))


def _login(auth: security.Authenticator, **kw) -> security.LoginResult:
    return asyncio.run(auth.login(user_agent="pytest", **kw))


# ---------------------------------------------------------------------------
# W1 -- lockout must not be a password oracle
# ---------------------------------------------------------------------------
def test_locked_wrong_and_locked_right_are_byte_identical():
    """A locked source must get the SAME answer whether or not it happens to
    submit the correct password.

    Before the fix, `verify_password` ran first and the outcome branched on
    its result: `locked` + wrong password -> "bad_credentials", `locked` +
    right password -> "locked". That difference IS the account's password --
    an attacker who can force a lockout (five POSTs, no secret required) can
    then binary-search the real password by watching which message comes
    back for each guess.
    """
    db = FakeDB()
    real_hash = security.hash_password(PASSWORD)
    db.add_user(username="owner", password_hash=real_hash)
    for i in range(5):
        db.seed_bad_password(username="owner", ip="9.9.9.9", minutes_ago=i)
    auth = _auth(db)

    wrong = _login(auth, username="owner", password="not the password", ip="9.9.9.9")
    right = _login(auth, username="owner", password=PASSWORD, ip="9.9.9.9")

    assert wrong.outcome == right.outcome == "bad_credentials"
    assert wrong.detail_ro == right.detail_ro
    assert wrong.session_token is None
    assert right.session_token is None, (
        "a locked source was let in because the password happened to be correct"
    )


def test_correct_password_from_clean_source_succeeds_while_other_source_is_locked():
    """Lockout is per (account, source), not per account.

    Before the fix, `failed_attempts`/`locked_until` lived on the user row --
    one counter for the whole account. Anyone who knew the username could push
    it past the threshold from any address and the OWNER'S OWN address would
    then be refused too, with the correct password in hand. Scoping the count
    to (account, source) means a clean address is judged on its own record.
    """
    db = FakeDB()
    real_hash = security.hash_password(PASSWORD)
    db.add_user(username="owner", password_hash=real_hash)
    for i in range(5):
        db.seed_bad_password(username="owner", ip="9.9.9.9", minutes_ago=i)
    auth = _auth(db)

    attacker = _login(auth, username="owner", password=PASSWORD, ip="9.9.9.9")
    assert attacker.outcome == "bad_credentials", (
        "the source with 5 real failures against this account must stay locked "
        "even with the correct password"
    )

    owner = _login(auth, username="owner", password=PASSWORD, ip="5.5.5.5")
    assert owner.outcome == "ok", (
        f"a clean source with the correct password was refused: {owner!r}"
    )
    assert owner.session_token is not None


def test_wrong_password_from_a_clean_source_is_not_locked_out_by_someone_elses_failures():
    """The mirror of the test above: a WRONG password from a clean source
    still reads as a normal wrong guess, not as "this account is locked" --
    there is no separate `locked` message to leak that another source has
    been guessing."""
    db = FakeDB()
    real_hash = security.hash_password(PASSWORD)
    db.add_user(username="owner", password_hash=real_hash)
    for i in range(5):
        db.seed_bad_password(username="owner", ip="9.9.9.9", minutes_ago=i)
    auth = _auth(db)

    result = _login(auth, username="owner", password="nope", ip="5.5.5.5")
    assert result.outcome == "bad_credentials"
    assert result.detail_ro == "Utilizator sau parolă incorectă."


# ---------------------------------------------------------------------------
# W2 -- a refusal must not renew the window it was refused by
# ---------------------------------------------------------------------------
def test_ip_throttle_refusal_does_not_extend_its_own_window():
    """A source at the per-IP failure ceiling must age back out of the
    throttle on its own once the real failures behind it expire.

    Before the fix, the throttle branch wrote `result='locked'` into
    `login_attempts` -- the very table `recent_failures_from_ip` counts. One
    refused request every few minutes kept the count topped up and the source
    throttled forever, with no password ever verified again.
    """
    db = FakeDB()
    for i in range(security.IP_FAILURE_LIMIT):
        db.seed_bad_password(username=f"probe{i}", ip="6.6.6.6", minutes_ago=1)
    auth = _auth(db)
    before = len(db.login_attempts)

    for _ in range(5):
        result = _login(auth, username="whoever", password="x", ip="6.6.6.6")
        assert result.outcome == "ip_throttled"

    assert len(db.login_attempts) == before, (
        "the throttle refusal wrote to login_attempts, which is exactly what "
        "lets it renew its own window"
    )

    # The real failures behind the throttle age out of the 15-minute window.
    db.now_minutes += security.IP_FAILURE_WINDOW_MINUTES + 1
    result = _login(auth, username="whoever", password="x", ip="6.6.6.6")
    assert result.outcome != "ip_throttled", (
        "the source was still throttled after its real failures aged out -- "
        "something is renewing the window"
    )


def test_account_source_lock_refusal_does_not_extend_its_own_window():
    """Same property, for the per-(account, source) lock introduced by W1:
    a refusal on that branch must not itself count towards the window that
    produced the refusal."""
    db = FakeDB()
    real_hash = security.hash_password(PASSWORD)
    db.add_user(username="owner", password_hash=real_hash)
    for i in range(5):
        db.seed_bad_password(username="owner", ip="9.9.9.9", minutes_ago=i)
    auth = _auth(db)
    before = len(db.login_attempts)

    for _ in range(5):
        result = _login(auth, username="owner", password=PASSWORD, ip="9.9.9.9")
        assert result.outcome == "bad_credentials"

    assert len(db.login_attempts) == before, (
        "the locked-source refusal wrote a row that would feed its own count"
    )

    db.now_minutes += security.IP_FAILURE_WINDOW_MINUTES + 1
    result = _login(auth, username="owner", password=PASSWORD, ip="9.9.9.9")
    assert result.outcome == "ok", (
        "the account/source pair was still locked after the real failures aged out"
    )


# ---------------------------------------------------------------------------
# W-F1 -- `--unlock` / `--set-password` must clear the password-stage lock too
# ---------------------------------------------------------------------------
def test_unlock_clears_the_password_stage_lock_not_just_totp():
    """`sentinel web --unlock` must make the NEXT correct login succeed
    immediately -- not just report success.

    Before `lock_reset_at`, `users.unlock` reset only `failed_attempts`/
    `locked_until`, the TOTP-stage columns. The password-stage lock lives
    entirely in `login_attempts`, counted over a time window by
    `recent_failures_for_account_from_ip`; nothing about that count was
    touched by `unlock`. An operator running the documented command was told
    the account was unblocked and then refused for up to
    `IP_FAILURE_WINDOW_MINUTES` more minutes.
    """
    db = FakeDB()
    real_hash = security.hash_password(PASSWORD)
    db.add_user(username="owner", password_hash=real_hash)
    for i in range(5):
        db.seed_bad_password(username="owner", ip="9.9.9.9", minutes_ago=i)
    auth = _auth(db)

    still_locked = _login(auth, username="owner", password=PASSWORD, ip="9.9.9.9")
    assert still_locked.outcome == "bad_credentials", "setup: source must start locked"

    assert asyncio.run(users.unlock(db, "owner")) is True

    after_unlock = _login(auth, username="owner", password=PASSWORD, ip="9.9.9.9")
    assert after_unlock.outcome == "ok", (
        f"unlock() reported success but the next correct login from the same "
        f"source was still refused: {after_unlock!r}"
    )
    assert after_unlock.session_token is not None


def test_set_password_clears_the_password_stage_lock():
    """Same property for `sentinel web --set-password`: a freshly set
    password must not inherit the (account, source) lock left by attempts
    against the OLD one."""
    db = FakeDB()
    old_hash = security.hash_password(PASSWORD)
    db.add_user(username="owner", password_hash=old_hash)
    for i in range(5):
        db.seed_bad_password(username="owner", ip="9.9.9.9", minutes_ago=i)
    auth = _auth(db)
    user_id = db._users["owner"]["id"]

    new_password = "a brand new password entirely 42"
    asyncio.run(users.set_password(db, user_id, security.hash_password(new_password)))

    result = _login(auth, username="owner", password=new_password, ip="9.9.9.9")
    assert result.outcome == "ok", (
        f"set_password() reset the hash but left the (account, source) lock "
        f"in place: {result!r}"
    )


# ---------------------------------------------------------------------------
# W-F2 -- mutations that survived round 1
# ---------------------------------------------------------------------------
def test_lock_is_scoped_to_the_account_not_just_the_source():
    """Failures against account A from source S must not lock out account B
    from the same source.

    Every other test in this file uses a single account, so a mutation that
    drops the `username = $1` predicate from the (account, source) query --
    scoping the lock to the source alone -- would still pass all of them.
    This uses two accounts from the same source to catch exactly that (W-F2
    M1).
    """
    db = FakeDB()
    hash_a = security.hash_password(PASSWORD)
    password_b = "a completely different password 7"
    hash_b = security.hash_password(password_b)
    db.add_user(username="a", password_hash=hash_a)
    db.add_user(username="b", password_hash=hash_b)
    for i in range(5):
        db.seed_bad_password(username="a", ip="9.9.9.9", minutes_ago=i)
    auth = _auth(db)

    a_result = _login(auth, username="a", password=PASSWORD, ip="9.9.9.9")
    assert a_result.outcome == "bad_credentials", "setup: account a must be locked"

    b_result = _login(auth, username="b", password=password_b, ip="9.9.9.9")
    assert b_result.outcome == "ok", (
        "failures against a DIFFERENT account from this source locked this "
        f"account too -- the lock is scoped to the source alone: {b_result!r}"
    )


def test_locked_source_still_runs_a_real_password_verification():
    """Password verification must run BEFORE the lock decision, not be
    skipped once a source is already at the cap.

    A "fix" that checks `source_locked` first and only calls
    `verify_password` when it is false would still pass every outcome-based
    assertion in this file (the refusal looks identical either way) while
    quietly breaking the constant-work property the module docstring opens
    with: a locked source's requests would get cheaper than an unlocked
    one's, which is exactly the timing tell an unknown username already
    avoids, and reopens the exact "verify first" ordering W1 required (W-F2
    M2).
    """
    db = FakeDB()
    real_hash = security.hash_password(PASSWORD)
    db.add_user(username="owner", password_hash=real_hash)
    for i in range(5):
        db.seed_bad_password(username="owner", ip="9.9.9.9", minutes_ago=i)
    auth = _auth(db)

    with mock.patch.object(
        security, "verify_password", wraps=security.verify_password
    ) as spy:
        result = _login(auth, username="owner", password=PASSWORD, ip="9.9.9.9")

    assert result.outcome == "bad_credentials"
    spy.assert_called_once_with(real_hash, PASSWORD)


# ---------------------------------------------------------------------------
# W-F4 -- a TOTP-stage lock must say so, with a retry time, not "Sesiune
# invalidă."
# ---------------------------------------------------------------------------
def test_login_refuses_immediately_when_totp_stage_already_locked():
    """A correct password against an account already locked at the TOTP
    stage must be told so at once, and must not mint a new pending session.

    Before the fix, `login()` did not check `is_locked` at all: a locked
    owner retrying their (correct) password kept getting sent to `/totp`,
    where the real bug lived (see the next test). A pending session minted
    here for an account that cannot proceed past `/totp` anyway is also just
    dead weight in the sessions table.
    """
    db = FakeDB()
    real_hash = security.hash_password(PASSWORD)
    future_lock = datetime.now(timezone.utc) + timedelta(minutes=7)
    db.add_user(
        username="owner", password_hash=real_hash,
        totp_confirmed=True, totp_secret="unused-because-locked-first",
        failed_attempts=5, locked_until=future_lock,
    )
    auth = _auth(db, require_totp=True)

    result = _login(auth, username="owner", password=PASSWORD, ip="1.2.3.4")

    assert result.outcome == "locked"
    assert result.session_token is None
    # Not just ">0" -- a hollow `lockout_remaining` (e.g. always returning
    # `timedelta(seconds=1)`) would still pass a bare positivity check while
    # telling the operator to retry in a second instead of the ~7 minutes
    # actually left, and "minute" alone matches "1 minute" just as well as
    # "7 minute". Both are pinned to the 7-minute fixture above.
    assert result.retry_after_s is not None
    assert 6 * 60 < result.retry_after_s <= 7 * 60, (
        f"retry_after_s={result.retry_after_s} does not reflect the ~7-minute "
        f"lock set up above"
    )
    assert "7 minute" in (result.detail_ro or "")
    assert not db.sessions, (
        "a pending session was created for an account already locked at the "
        "TOTP stage"
    )


def test_verify_second_factor_reports_the_lock_instead_of_invalid_session():
    """A pending session for an account that is now TOTP-locked must get
    `locked` with a retry time, not the generic "Sesiune invalidă." that
    also covers a genuinely dead/unknown session.

    This models the session as having been minted BEFORE the lock (the case
    the guard in `login()` above cannot cover, since a lock created after a
    session already exists cannot retroactively stop that session from
    existing). Not an oracle: reaching `verify_second_factor` at all already
    required a correct password.
    """
    db = FakeDB()
    real_hash = security.hash_password(PASSWORD)
    future_lock = datetime.now(timezone.utc) + timedelta(minutes=3)
    row = db.add_user(
        username="owner", password_hash=real_hash,
        totp_confirmed=True, totp_secret="unused-because-locked-first",
        failed_attempts=5, locked_until=future_lock,
    )
    session = db.add_pending_session("sess-precedes-lock", row["id"])
    auth = _auth(db, require_totp=True)

    result = asyncio.run(
        auth.verify_second_factor(
            session=session, code="000000", ip="9.9.9.9", user_agent="pytest"
        )
    )

    assert result.outcome == "locked"
    assert result.detail_ro != "Sesiune invalidă."
    assert result.retry_after_s is not None and result.retry_after_s > 0
    assert "minute" in (result.detail_ro or "")
    assert db.sessions["sess-precedes-lock"]["revoked_at"] is not None, (
        "a session for a locked account must not remain usable"
    )


# ---------------------------------------------------------------------------
# S1 (round 3) -- the lock THIS session's own 5th wrong code trips must carry
# a retry time too, not just the one inherited from an earlier session
# ---------------------------------------------------------------------------
def _wrong_totp_code(secret: str) -> str:
    """A six-digit code guaranteed not to verify against `secret` right now.

    `TOTP_VALID_WINDOW` accepts three adjacent codes, so a literal constant
    picked at random would flake on the (small but real) chance it collides
    with one of them. Checking against `verify_totp_code` instead of trusting
    a hand-picked string keeps the test from being the once-in-a-blue-moon
    failure this repository has already been burned by.
    """
    for candidate in ("000000", "111111", "222222", "333333"):
        if security.verify_totp_code(secret, candidate) is None:
            return candidate
    raise AssertionError("no wrong TOTP code found -- suspiciously unlucky")


def test_fifth_wrong_totp_code_reports_a_retry_time_not_just_locked():
    """The lock tripped by THIS session's own 5th wrong code must carry
    `retry_after_s`, the same as a lock inherited from another session.

    Before this fix, `verify_second_factor`'s wrong-code branch returned
    `LoginResult("locked", detail_ro="Cont blocat temporar.")` with no
    `retry_after_s` at all -- `totp_submit` (auth.py) has nothing to build a
    `Retry-After` header or an `m=` redirect param from, so even a correctly
    routed "locked" page would have shown a contextless "câteva minute"
    (S1, round 3).
    """
    db = FakeDB()
    real_hash = security.hash_password(PASSWORD)
    secret = pyotp.random_base32()
    cipher = security.TOTPCipher(MASTER)
    row = db.add_user(
        username="owner", password_hash=real_hash,
        totp_confirmed=True, totp_secret=cipher.encrypt(secret),
        failed_attempts=4,  # one more wrong code trips the lock
    )
    session = db.add_pending_session("sess-fifth-wrong-code", row["id"])
    auth = _auth(db, require_totp=True, max_failed_logins=5, lockout_minutes=7)

    result = asyncio.run(
        auth.verify_second_factor(
            session=session, code=_wrong_totp_code(secret),
            ip="9.9.9.9", user_agent="pytest",
        )
    )

    assert result.outcome == "locked"
    assert result.retry_after_s is not None
    assert 6 * 60 < result.retry_after_s <= 7 * 60, (
        f"retry_after_s={result.retry_after_s} does not reflect the "
        f"7-minute lockout configured above"
    )
    # The exact minute figure in `detail_ro` is derived FROM `retry_after_s`
    # by the same "seconds to whole minutes, rounded up" rule the branch
    # above (`user.is_locked`) uses -- not re-asserted as a bare "7", which
    # would flake the rare run where `locked_until` lands on an exact minute
    # boundary (`remaining_s == 420` rounds up to 8, same as that branch
    # would). What must hold is that the two numbers AGREE, which a "fix"
    # that set `retry_after_s` without updating `detail_ro` (or vice versa)
    # would not.
    expected_minutes = (result.retry_after_s // 60) + 1
    assert f"{expected_minutes} minute" in (result.detail_ro or "")
    assert db.sessions["sess-fifth-wrong-code"]["revoked_at"] is not None, (
        "a session for a just-locked account must not remain usable"
    )
