-- 0009_web_session: the fields the dashboard's auth flow actually needs.
--
-- 0006 created `users`, `sessions` and `login_attempts` as a sketch. Building
-- the real login flow surfaced three things that were missing, and each one is
-- a security property rather than a convenience.

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------
-- The cookie carries an opaque 256-bit random token. What is stored here is its
-- SHA-256, not the token itself.
--
-- Why: a database dump — a backup left readable, a `pg_dump` in a shared
-- directory, an SQL injection somewhere else — would otherwise hand over every
-- live session. Hashing means a leaked dump yields nothing usable, exactly as
-- with passwords. The token is high-entropy and single-purpose, so a plain
-- SHA-256 is sufficient; there is nothing to brute force.
ALTER TABLE sessions ADD COLUMN token_hash text;

-- Per-session CSRF token, compared with secrets.compare_digest on every
-- state-changing form post.
--
-- SameSite=Strict already blocks the common cross-site cases, but it is a
-- browser behaviour, not a guarantee: older clients, and a few navigation
-- paths, do not honour it. A server-side token does not depend on the client
-- doing the right thing.
ALTER TABLE sessions ADD COLUMN csrf_token text;

-- Two-stage login. A password-only session is NOT authenticated: it may reach
-- /totp and nothing else.
--
-- Modelling this as a real state in the database, rather than as a flag in a
-- signed cookie, means the second factor cannot be skipped by replaying or
-- tampering with a cookie. The row itself says the session is half-finished.
ALTER TABLE sessions ADD COLUMN pending_totp boolean NOT NULL DEFAULT false;

-- Set when the session was created, so a stolen cookie used from elsewhere is
-- visible in the audit trail even if the address is not blocked.
ALTER TABLE sessions ADD COLUMN created_ip inet;

-- The token hash is what lookups go through, so it needs to be unique and
-- indexed. Partial: revoked rows are kept for the audit trail but never match.
CREATE UNIQUE INDEX sessions_token_hash_idx ON sessions (token_hash)
    WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------
-- Argon2 parameters are embedded in the hash string, so a future change to the
-- cost factors can be detected and the hash upgraded on the next successful
-- login rather than forcing a password reset.
ALTER TABLE users ADD COLUMN password_algo text NOT NULL DEFAULT 'argon2id';

-- TOTP enrolment is a two-step affair: generate a secret, show the QR, and only
-- mark it confirmed once the user has proved they can produce a code from it.
-- Without this an interrupted enrolment leaves an account that requires a
-- second factor nobody has.
ALTER TABLE users ADD COLUMN totp_enrolled_at timestamptz;

-- Replay protection. A TOTP code is valid for a 30-second window, and without
-- remembering the last accepted counter the same code works twice inside it —
-- which is exactly long enough for someone reading it over a shoulder, or
-- replaying a captured form post.
ALTER TABLE users ADD COLUMN totp_last_counter bigint;

-- ---------------------------------------------------------------------------
-- Login attempts
-- ---------------------------------------------------------------------------
-- Lockout is per-user (users.failed_attempts) AND per-source. Per-user alone
-- lets an attacker lock out a known username as a denial of service;
-- per-source alone lets a distributed attempt through. Both, and the stricter
-- one wins.
CREATE INDEX login_attempts_ip_recent_idx ON login_attempts (ip, at DESC)
    WHERE result <> 'ok';

-- Which stage failed, so "wrong password" and "wrong second factor" are
-- distinguishable in the audit trail. A run of bad_totp against a correct
-- password means someone has the password.
ALTER TABLE login_attempts ADD COLUMN stage text
    CHECK (stage IS NULL OR stage IN ('password', 'totp'));
ALTER TABLE login_attempts ADD COLUMN session_id text;
