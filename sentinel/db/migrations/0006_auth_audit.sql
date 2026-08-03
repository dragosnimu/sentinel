-- 0006_auth_audit: dashboard authentication, Telegram callback tokens, AI queue.
--
-- The dashboard is publicly reachable over HTTPS, so its auth schema is a real
-- attack surface: Argon2id hashes, mandatory TOTP, and lockout state that
-- survives a process restart.

CREATE TABLE users (
    id                bigserial   PRIMARY KEY,
    username          text        NOT NULL UNIQUE,

    -- Argon2id. Never bcrypt, never a fast hash, never unsalted.
    password_hash     text        NOT NULL,
    -- Encrypted at rest with a key from secrets.env, so a database dump alone
    -- does not yield working second factors.
    totp_secret       text,
    totp_confirmed    boolean     NOT NULL DEFAULT false,

    role              text        NOT NULL DEFAULT 'viewer'
                        CHECK (role IN ('owner','operator','viewer')),

    created_at        timestamptz NOT NULL DEFAULT now(),
    last_login_at     timestamptz,
    last_login_ip     inet,
    password_changed_at timestamptz NOT NULL DEFAULT now(),

    failed_attempts   integer     NOT NULL DEFAULT 0,
    locked_until      timestamptz,
    disabled          boolean     NOT NULL DEFAULT false
);

CREATE TABLE sessions (
    id            text        PRIMARY KEY,          -- opaque, CSPRNG
    user_id       bigint      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    ip            inet,
    user_agent    text,
    revoked_at    timestamptz
);

CREATE INDEX sessions_user_idx    ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expiry_idx  ON sessions (expires_at) WHERE revoked_at IS NULL;

-- Every login attempt, successful or not. Answers "was that unfamiliar
-- successful auth me, travelling?" before anyone calls it a compromise.
CREATE TABLE login_attempts (
    id          bigserial   PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    username    text,
    ip          inet,
    user_agent  text,
    result      text        NOT NULL
                  CHECK (result IN ('ok','bad_password','bad_totp','locked','unknown_user')),
    detail      text
);

CREATE INDEX login_attempts_ip_idx   ON login_attempts (ip, at DESC);
CREATE INDEX login_attempts_recent_idx ON login_attempts (at DESC);

-- ---------------------------------------------------------------------------
-- Telegram callback tokens
-- ---------------------------------------------------------------------------
-- Telegram callback_data is limited to 64 bytes and is echoed back by the
-- client, so it can be replayed and tampered with. Sentinel puts only an opaque
-- token in it and keeps the real payload here: single-use, TTL-bound,
-- HMAC-signed, and bound to plan_hash where a patch is involved. Regenerating
-- a plan changes the hash and kills every outstanding button.
CREATE TABLE telegram_callbacks (
    token       text        PRIMARY KEY,
    chat_id     bigint      NOT NULL,
    action      text        NOT NULL,
    params      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    plan_hash   text,
    incident_id bigint      REFERENCES incidents(id) ON DELETE CASCADE,

    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    used_by     bigint,

    -- Destructive actions need a second tap that restates the exact target, so
    -- a mis-tap on a stale message is visible before it does anything.
    requires_confirm boolean NOT NULL DEFAULT false,
    confirm_of  text        REFERENCES telegram_callbacks(token) ON DELETE CASCADE
);

CREATE INDEX telegram_callbacks_expiry_idx ON telegram_callbacks (expires_at)
    WHERE used_at IS NULL;

-- Per-chat role and rate-limiting state. The allowlist in sentinel.yaml is the
-- authority on *who*; this is the runtime state for those chats.
CREATE TABLE telegram_chats (
    chat_id        bigint      PRIMARY KEY,
    role           text        NOT NULL DEFAULT 'viewer'
                     CHECK (role IN ('owner','operator','viewer')),
    label          text,
    muted_until    timestamptz,
    commands_count bigint      NOT NULL DEFAULT 0,
    last_command_at timestamptz,
    first_seen     timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- AI queue and spend
-- ---------------------------------------------------------------------------
CREATE TABLE ai_jobs (
    id           bigserial   PRIMARY KEY,
    kind         text        NOT NULL
                   CHECK (kind IN ('triage','correlate','predict','report','patch_plan','ask','vuln_assess')),
    payload      jsonb       NOT NULL DEFAULT '{}'::jsonb,

    state        text        NOT NULL DEFAULT 'queued'
                   CHECK (state IN ('queued','running','done','failed','skipped')),
    priority     smallint    NOT NULL DEFAULT 5,

    -- An event storm must not generate hundreds of identical triage calls.
    -- Same fingerprint within the window collapses to one job.
    dedup_key    text,

    attempts     smallint    NOT NULL DEFAULT 0,
    max_attempts smallint    NOT NULL DEFAULT 2,

    enqueued_at  timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz,

    result       jsonb,
    error        text,
    -- Set when the budget circuit breaker or an API outage skipped the job, so
    -- the operator can see the analysis is missing rather than absent-by-choice.
    skip_reason  text,

    incident_id  bigint      REFERENCES incidents(id) ON DELETE CASCADE,
    finding_id   bigint      REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX ai_jobs_queue_idx ON ai_jobs (state, priority, enqueued_at)
    WHERE state = 'queued';
CREATE UNIQUE INDEX ai_jobs_dedup_idx ON ai_jobs (dedup_key)
    WHERE dedup_key IS NOT NULL AND state IN ('queued','running');

CREATE TABLE ai_usage (
    id                bigserial   PRIMARY KEY,
    job_id            bigint      REFERENCES ai_jobs(id) ON DELETE SET NULL,
    at                timestamptz NOT NULL DEFAULT now(),

    transport         text        NOT NULL DEFAULT 'api' CHECK (transport IN ('api','cli')),
    model             text        NOT NULL,
    input_tokens      integer     NOT NULL DEFAULT 0,
    output_tokens     integer     NOT NULL DEFAULT 0,
    cache_read_tokens integer     NOT NULL DEFAULT 0,
    cache_write_tokens integer    NOT NULL DEFAULT 0,
    cost_usd          numeric(10,6) NOT NULL DEFAULT 0,
    duration_ms       integer,
    kind              text
);

CREATE INDEX ai_usage_at_idx ON ai_usage (at DESC);

-- ---------------------------------------------------------------------------
-- Threat intel feed state
-- ---------------------------------------------------------------------------
CREATE TABLE intel_feeds (
    name          text        PRIMARY KEY,
    url           text        NOT NULL,
    format        text        NOT NULL,
    category      text        NOT NULL,       -- botnet | scanner | tor | compromised | drop
    confidence    smallint    NOT NULL DEFAULT 50,
    enabled       boolean     NOT NULL DEFAULT true,

    last_refresh  timestamptz,
    last_success  timestamptz,
    entry_count   integer     NOT NULL DEFAULT 0,
    -- Three consecutive failures trip a circuit breaker: the feed is disabled
    -- for an hour and logged once, rather than retried into a hot loop.
    failures      smallint    NOT NULL DEFAULT 0,
    disabled_until timestamptz,
    last_error    text
);
