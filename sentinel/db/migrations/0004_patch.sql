-- 0004_patch: patch plans, executions, per-step audit trail, restore points.
--
-- Two properties this schema exists to guarantee:
--
--   1. plan_hash binds an approval to an exact plan. Regenerating a plan
--      changes the hash, which kills every outstanding Telegram button. You
--      cannot approve plan A and have plan B execute.
--
--   2. patch_steps rows are written BEFORE the next step starts. A crash, an
--      OOM kill or a power loss mid-patch leaves a complete forensic trail of
--      exactly how far it got.

CREATE TABLE patch_plans (
    id                    bigserial   PRIMARY KEY,
    plan_id               uuid        NOT NULL UNIQUE,

    -- sha256 over the plan's semantic content, excluding volatile fields.
    plan_hash             text        NOT NULL,
    plan                  jsonb       NOT NULL,

    asset_id              bigint      REFERENCES assets(id) ON DELETE SET NULL,
    finding_ids           bigint[]    NOT NULL DEFAULT '{}',

    status                text        NOT NULL DEFAULT 'draft'
                            CHECK (status IN ('draft','validated','rejected_invalid','approved',
                                              'scheduled','applying','applied','rolled_back',
                                              'failed','rejected','expired')),

    risk_level            text        CHECK (risk_level IN ('low','medium','high','critical')),
    blast_radius          text,
    requires_reboot       boolean     NOT NULL DEFAULT false,
    reversible            boolean     NOT NULL DEFAULT true,
    estimated_downtime_s  integer,
    estimated_backup_mb   integer,
    confidence            numeric(3,2),

    -- Populated when the deterministic validator rejects the plan. The operator
    -- is told the AI could not produce a safe procedure — an acceptable outcome,
    -- and a much better one than a plausible plan that breaks production.
    validation_errors     jsonb,
    validation_attempts   smallint    NOT NULL DEFAULT 0,

    generated_by          text,
    model                 text,
    prompt_version        text,
    generation_ms         integer,

    created_at            timestamptz NOT NULL DEFAULT now(),
    approved_by           text,
    approved_at           timestamptz,
    scheduled_for         timestamptz,
    rejected_by           text,
    rejected_reason       text
);

CREATE INDEX patch_plans_status_idx ON patch_plans (status, created_at DESC);
CREATE INDEX patch_plans_asset_idx  ON patch_plans (asset_id, created_at DESC);
CREATE INDEX patch_plans_hash_idx   ON patch_plans (plan_hash);

CREATE TABLE patch_executions (
    id                bigserial   PRIMARY KEY,
    plan_id           bigint      NOT NULL REFERENCES patch_plans(id) ON DELETE CASCADE,

    mode              text        NOT NULL DEFAULT 'apply' CHECK (mode IN ('dry_run','apply')),
    status            text        NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running','succeeded','failed','rolled_back',
                                          'rollback_failed','aborted')),

    started_at        timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz,
    duration_ms       integer,

    restore_point_id  bigint,                    -- FK added below
    triggered_by      text        NOT NULL,

    -- Which health check failed, or which step returned non-zero.
    rollback_reason   text,
    rollback_at       timestamptz,

    -- The post-verification re-runs the scanner's own check. If it still fires
    -- after a successful apply, that is recorded rather than glossed over.
    post_verification_passed boolean,
    result            jsonb,
    error             text
);

CREATE INDEX patch_executions_plan_idx   ON patch_executions (plan_id, started_at DESC);
CREATE INDEX patch_executions_status_idx ON patch_executions (status, started_at DESC);

CREATE TABLE patch_steps (
    id            bigserial   PRIMARY KEY,
    execution_id  bigint      NOT NULL REFERENCES patch_executions(id) ON DELETE CASCADE,

    phase         text        NOT NULL
                    CHECK (phase IN ('preflight','backup','apply','health_check',
                                     'rollback','post_verification')),
    step_id       text        NOT NULL,          -- the plan's own step id
    seq           integer     NOT NULL,

    argv          text[]      NOT NULL DEFAULT '{}',
    cwd           text,
    run_as        text,

    started_at    timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz,
    duration_ms   integer,
    exit_code     integer,
    timed_out     boolean     NOT NULL DEFAULT false,

    -- Truncated to 64 KB and passed through the credential redactor before
    -- storage. Command output is the most common accidental secret leak.
    stdout        text,
    stderr        text,

    status        text        NOT NULL DEFAULT 'running'
                    CHECK (status IN ('running','ok','failed','skipped'))
);

CREATE UNIQUE INDEX patch_steps_seq_idx ON patch_steps (execution_id, seq);
CREATE INDEX patch_steps_exec_idx       ON patch_steps (execution_id, started_at);

CREATE TABLE restore_points (
    id              bigserial   PRIMARY KEY,
    asset_id        bigint      REFERENCES assets(id) ON DELETE SET NULL,
    plan_id         bigint      REFERENCES patch_plans(id) ON DELETE SET NULL,

    path            text        NOT NULL UNIQUE,
    -- Every item with its size, sha256, method and restore command. Written
    -- alongside a standalone restore.sh that works with Sentinel stopped.
    manifest        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    size_bytes      bigint      NOT NULL DEFAULT 0,

    created_at      timestamptz NOT NULL DEFAULT now(),
    -- Checksums verified immediately after creation. A mismatch aborts the
    -- patch before any apply step runs.
    verified_at     timestamptz,
    verify_error    text,

    -- Protects the most recent successful restore point per asset from
    -- garbage collection, regardless of age. There is never zero ways back.
    retention_hold  boolean     NOT NULL DEFAULT false,

    restored_at     timestamptz,
    restored_by     text,
    deleted_at      timestamptz
);

CREATE INDEX restore_points_asset_idx ON restore_points (asset_id, created_at DESC)
    WHERE deleted_at IS NULL;
CREATE INDEX restore_points_hold_idx  ON restore_points (retention_hold)
    WHERE retention_hold AND deleted_at IS NULL;

ALTER TABLE patch_executions
    ADD CONSTRAINT patch_executions_restore_fk
    FOREIGN KEY (restore_point_id) REFERENCES restore_points(id) ON DELETE SET NULL;

-- An untested backup is not a backup. The drill restores a real restore point
-- onto the canary with all Sentinel units stopped, proving the manual path.
CREATE TABLE restore_drills (
    id                bigserial   PRIMARY KEY,
    restore_point_id  bigint      REFERENCES restore_points(id) ON DELETE SET NULL,
    performed_at      timestamptz NOT NULL DEFAULT now(),
    performed_by      text        NOT NULL,
    succeeded         boolean     NOT NULL,
    duration_ms       integer,
    notes             text
);
