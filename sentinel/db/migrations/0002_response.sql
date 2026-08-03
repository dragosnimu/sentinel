-- 0002_response: blocklist, allowlist, action requests, suppressions, audit log.
--
-- The kernel's nftables sets are the authority on what is actually blocked.
-- This schema is Sentinel's *record* of it, used to re-apply non-expired blocks
-- after a reboot (blocks are deliberately not persisted in nftables) and to
-- answer "did blocking help". A reconcile loop keeps the two consistent and
-- alerts on drift.

-- ---------------------------------------------------------------------------
-- Blocklist
-- ---------------------------------------------------------------------------
CREATE TABLE blocklist (
    id            bigserial   PRIMARY KEY,
    ip            inet        NOT NULL,
    prefix_len    smallint,                       -- NULL = single address

    reason        text        NOT NULL,
    rule_id       text,
    incident_id   bigint      REFERENCES incidents(id) ON DELETE SET NULL,
    actor_key     text        REFERENCES actors(actor_key) ON DELETE SET NULL,

    blocked_at    timestamptz NOT NULL DEFAULT now(),
    -- NULL means permanent. Only an operator can create one; auto-block never
    -- does. Permanent blocks still vanish on reboot, by design.
    expires_at    timestamptz,
    ttl_seconds   integer,

    -- Read back from the nftables counter. The honest answer to "was blocking
    -- this worth it": a block with zero hits stopped nothing.
    hit_count     bigint      NOT NULL DEFAULT 0,
    last_hit_at   timestamptz,

    created_by    text        NOT NULL DEFAULT 'auto',   -- auto | telegram:<id> | operator:<user>
    active        boolean     NOT NULL DEFAULT true,
    unblocked_at  timestamptz,
    unblocked_by  text,
    unblock_reason text
);

CREATE UNIQUE INDEX blocklist_active_ip_idx ON blocklist (ip) WHERE active;
CREATE INDEX blocklist_expiry_idx  ON blocklist (expires_at) WHERE active;
CREATE INDEX blocklist_recent_idx  ON blocklist (blocked_at DESC);
CREATE INDEX blocklist_incident_idx ON blocklist (incident_id) WHERE incident_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Allowlist
-- ---------------------------------------------------------------------------
-- Operator-managed additions only. The authoritative never-block list is
-- hard-coded in executor/policy.py — loopback, RFC1918, the SSH peer, the
-- server's own addresses, Telegram and Anthropic. It
-- lives in code precisely so that a database compromise cannot remove an entry
-- and then block the operator out of their own server.
CREATE TABLE allowlist (
    id          bigserial   PRIMARY KEY,
    cidr        cidr        NOT NULL UNIQUE,
    reason      text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text        NOT NULL,
    expires_at  timestamptz,
    -- Learned entries come from observed legitimate behaviour (a monitor, an
    -- ACME validator) and are proposed to the operator rather than applied.
    is_learned  boolean     NOT NULL DEFAULT false,
    confirmed   boolean     NOT NULL DEFAULT true
);

-- ---------------------------------------------------------------------------
-- Action requests
-- ---------------------------------------------------------------------------
-- The web UI never talks to the privileged executor. It writes a row here; the
-- responder picks it up and, for destructive classes, requires a Telegram
-- confirmation first. A compromised dashboard can therefore request, but not
-- perform, anything dangerous.
CREATE TABLE action_requests (
    id             bigserial   PRIMARY KEY,
    kind           text        NOT NULL,     -- block_ip | unblock_ip | restart_service | apply_patch | ...
    params         jsonb       NOT NULL DEFAULT '{}'::jsonb,

    state          text        NOT NULL DEFAULT 'pending'
                     CHECK (state IN ('pending','awaiting_confirmation','approved',
                                      'executing','done','failed','rejected','expired')),
    requires_confirmation boolean NOT NULL DEFAULT true,

    requested_by   text        NOT NULL,     -- web:<user> | telegram:<id> | ai | auto
    requested_at   timestamptz NOT NULL DEFAULT now(),
    confirmed_by   text,
    confirmed_at   timestamptz,
    executed_at    timestamptz,
    expires_at     timestamptz NOT NULL DEFAULT now() + interval '10 minutes',

    result         jsonb,
    error          text,
    incident_id    bigint      REFERENCES incidents(id) ON DELETE SET NULL
);

CREATE INDEX action_requests_open_idx ON action_requests (state, requested_at)
    WHERE state IN ('pending','awaiting_confirmation','approved');

-- ---------------------------------------------------------------------------
-- Suppressions
-- ---------------------------------------------------------------------------
-- Written when an operator taps "Fals pozitiv". Keyed narrowly on purpose:
-- a blanket rule-wide suppression hides real attacks later.
CREATE TABLE suppressions (
    id          bigserial   PRIMARY KEY,
    rule_id     text,                      -- NULL = applies to every rule
    pattern     jsonb       NOT NULL DEFAULT '{}'::jsonb,  -- {src_ip, asset_id, http_path, ...}
    reason      text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text        NOT NULL,
    expires_at  timestamptz,
    hit_count   bigint      NOT NULL DEFAULT 0,
    -- Set when the suppression came from an operator's false-positive tap, so
    -- the tuning data can be separated from manually authored suppressions.
    from_feedback boolean   NOT NULL DEFAULT false
);

-- Composite, not a partial index: `now()` is STABLE, not IMMUTABLE, and Postgres
-- refuses a non-IMMUTABLE function in an index predicate. Indexing
-- (rule_id, expires_at) serves the same lookup — the active-suppression query
-- filters `rule_id = ? AND (expires_at IS NULL OR expires_at > now())` at read
-- time, and this index covers both the equality and the range on expires_at.
CREATE INDEX suppressions_rule_idx ON suppressions (rule_id, expires_at);

-- Maintenance windows suppress availability.* and host.* for their duration.
CREATE TABLE maintenance_windows (
    id          bigserial   PRIMARY KEY,
    asset_id    bigint      REFERENCES assets(id) ON DELETE CASCADE,
    starts_at   timestamptz NOT NULL,
    ends_at     timestamptz NOT NULL,
    reason      text        NOT NULL,
    created_by  text        NOT NULL,
    CHECK (ends_at > starts_at)
);

CREATE INDEX maintenance_windows_active_idx ON maintenance_windows (starts_at, ends_at);

-- ---------------------------------------------------------------------------
-- Audit log
-- ---------------------------------------------------------------------------
-- Append-only and hash-chained. Written by the *executor* for privileged
-- operations, not by the caller, so a compromised daemon cannot forge or omit
-- an entry. A broken chain is detectable and alerts.
CREATE TABLE audit_log (
    id          bigserial   PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    actor       text        NOT NULL,      -- auto | telegram:<id> | web:<user> | executor
    source      text        NOT NULL,      -- executor | telegram | web | ai | scan
    operation   text        NOT NULL,
    target      text,
    params      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    result      text        NOT NULL CHECK (result IN ('ok','refused','error')),
    detail      text,

    prev_hash   text,
    entry_hash  text        NOT NULL
);

CREATE INDEX audit_log_at_idx        ON audit_log (at DESC);
CREATE INDEX audit_log_operation_idx ON audit_log (operation, at DESC);
CREATE INDEX audit_log_actor_idx     ON audit_log (actor, at DESC);

-- Deletes and updates are rejected at the database level, not merely avoided
-- in application code. Someone with the sentinel role still cannot rewrite
-- history.
CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only (attempted %)', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

-- ---------------------------------------------------------------------------
-- Notifications
-- ---------------------------------------------------------------------------
-- Outbound queue, so an event storm cannot generate 500 Telegram messages and
-- so alerts survive a Telegram outage instead of being lost.
CREATE TABLE notifications (
    id           bigserial   PRIMARY KEY,
    channel      text        NOT NULL DEFAULT 'telegram',
    severity     text        NOT NULL,
    dedup_key    text,
    title        text        NOT NULL,
    body         text        NOT NULL,
    buttons      jsonb       NOT NULL DEFAULT '[]'::jsonb,
    incident_id  bigint      REFERENCES incidents(id) ON DELETE SET NULL,

    state        text        NOT NULL DEFAULT 'queued'
                   CHECK (state IN ('queued','sent','failed','suppressed','digested')),
    enqueued_at  timestamptz NOT NULL DEFAULT now(),
    sent_at      timestamptz,
    attempts     integer     NOT NULL DEFAULT 0,
    error        text,
    message_id   bigint                    -- Telegram message id, for later edits
);

CREATE INDEX notifications_queue_idx ON notifications (state, enqueued_at)
    WHERE state = 'queued';
CREATE INDEX notifications_dedup_idx ON notifications (dedup_key, enqueued_at DESC)
    WHERE dedup_key IS NOT NULL;
