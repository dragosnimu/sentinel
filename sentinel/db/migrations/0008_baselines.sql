-- 0008_baselines: statistical baselines, kill-chain transitions, scored predictions.
--
-- This is the "prediction" half of the system, and it is deliberately not
-- machine learning. It is robust statistics, a state machine, and empirical
-- frequencies computed from this host's own history — every one of which can be
-- explained to an operator at 3 a.m. and checked afterwards.

-- ---------------------------------------------------------------------------
-- Baselines
-- ---------------------------------------------------------------------------
CREATE TABLE baselines (
    asset_id      bigint      NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    metric        text        NOT NULL,   -- requests_per_min | error_rate | failed_auth_per_min | ...
    -- 0..167. Captures "1200 requests at 04:00 on a Sunday is abnormal even
    -- though 1200 at 14:00 on a Tuesday is not" — a flat threshold cannot.
    hour_of_week  smallint    NOT NULL CHECK (hour_of_week BETWEEN 0 AND 167),

    -- Median and MAD, not mean and stddev. Attack traffic destroys the mean;
    -- the median barely moves. Score = 0.6745 * (x - median) / MAD.
    median        numeric     NOT NULL DEFAULT 0,
    mad           numeric     NOT NULL DEFAULT 0,
    ewma          numeric     NOT NULL DEFAULT 0,

    sample_count  integer     NOT NULL DEFAULT 0,
    -- False during the 14-day warm-up. Anomaly rules are recorded but do not
    -- alert while false. Skipping this is how you get several hundred false
    -- positives on day one — if an obvious spike did not alert, check here first.
    warm          boolean     NOT NULL DEFAULT false,

    first_sample_at timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (asset_id, metric, hour_of_week)
);

CREATE INDEX baselines_warm_idx ON baselines (warm, metric);

-- ---------------------------------------------------------------------------
-- Kill-chain transitions
-- ---------------------------------------------------------------------------
-- Every stage change, with how long it took and what the evidence looked like.
-- The transition matrix is a plain aggregation over this table, which is why a
-- prediction can always be stated as "31 of 87 actors with a similar pattern".
CREATE TABLE killchain_transitions (
    id               bigserial   PRIMARY KEY,
    actor_key        text        NOT NULL REFERENCES actors(actor_key) ON DELETE CASCADE,
    from_stage       smallint    NOT NULL CHECK (from_stage BETWEEN 0 AND 6),
    to_stage         smallint    NOT NULL CHECK (to_stage BETWEEN 0 AND 6),
    at               timestamptz NOT NULL DEFAULT now(),
    elapsed_s        integer,                       -- time spent at from_stage

    -- Coarse signature of what triggered the advance, so the empirical
    -- probability can be conditioned on comparable actors rather than on every
    -- actor that ever reached this stage.
    evidence_pattern text,
    rule_ids         text[]      NOT NULL DEFAULT '{}',
    asset_id         bigint      REFERENCES assets(id) ON DELETE SET NULL,
    CHECK (to_stage > from_stage)
);

CREATE INDEX killchain_from_idx  ON killchain_transitions (from_stage, at DESC);
CREATE INDEX killchain_actor_idx ON killchain_transitions (actor_key, at);
CREATE INDEX killchain_to_idx    ON killchain_transitions (to_stage, at DESC);

-- ---------------------------------------------------------------------------
-- Predictions
-- ---------------------------------------------------------------------------
-- Every prediction is recorded and later scored. The analytics page shows a
-- Brier score computed from this table. That is the point: a prediction nobody
-- checks is marketing, and invented probabilities surface here within a week.
CREATE TABLE predictions (
    id               bigserial   PRIMARY KEY,
    made_at          timestamptz NOT NULL DEFAULT now(),

    actor_key        text        REFERENCES actors(actor_key) ON DELETE CASCADE,
    asset_id         bigint      REFERENCES assets(id) ON DELETE SET NULL,
    incident_id      bigint      REFERENCES incidents(id) ON DELETE SET NULL,

    kind             text        NOT NULL DEFAULT 'stage_advance'
                       CHECK (kind IN ('stage_advance','target_next','volume_band','exploit_attempt')),
    predicted_stage  smallint,
    probability      numeric(4,3) NOT NULL CHECK (probability BETWEEN 0 AND 1),
    horizon_minutes  integer     NOT NULL,

    -- The numerator, denominator and window the probability came from. A
    -- prediction whose basis cannot be reproduced is not a prediction.
    basis            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    narrative_ro     text,

    -- Scored by the maintenance job once the horizon has passed.
    outcome          boolean,
    scored_at        timestamptz,
    outcome_detail   jsonb
);

CREATE INDEX predictions_pending_idx ON predictions (made_at)
    WHERE scored_at IS NULL;
CREATE INDEX predictions_scored_idx  ON predictions (scored_at DESC)
    WHERE scored_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Campaigns
-- ---------------------------------------------------------------------------
-- Actors clustered by shared /24, ASN, user agent, JA4 fingerprint, path
-- sequence and inter-arrival timing. Set operations, not a clustering algorithm
-- with a threshold to tune badly.
CREATE TABLE campaigns (
    id             bigserial   PRIMARY KEY,
    fingerprint    text        NOT NULL UNIQUE,
    first_seen     timestamptz NOT NULL DEFAULT now(),
    last_seen      timestamptz NOT NULL DEFAULT now(),

    actor_keys     text[]      NOT NULL DEFAULT '{}',
    -- Ordered. A campaign that previously hit A then B then C predicts C when
    -- it is currently on A and B.
    targeted_assets bigint[]   NOT NULL DEFAULT '{}',
    asns           integer[]   NOT NULL DEFAULT '{}',
    countries      text[]      NOT NULL DEFAULT '{}',

    detection_count integer    NOT NULL DEFAULT 0,
    max_stage      smallint    NOT NULL DEFAULT 0,
    risk_score     smallint    NOT NULL DEFAULT 0,

    ai_narrative   text,
    ai_analyzed_at timestamptz,
    status         text        NOT NULL DEFAULT 'active'
                     CHECK (status IN ('active','dormant','concluded'))
);

CREATE INDEX campaigns_active_idx ON campaigns (last_seen DESC) WHERE status = 'active';

-- ---------------------------------------------------------------------------
-- Exposure crossings
-- ---------------------------------------------------------------------------
-- The join between "what an actor is probing" and "what we know is vulnerable
-- there". No statistics at all, and the single most actionable signal the
-- system produces — so it gets its own table rather than being recomputed.
CREATE TABLE exposure_crossings (
    id           bigserial   PRIMARY KEY,
    detected_at  timestamptz NOT NULL DEFAULT now(),
    -- The hour bucket used to dedup one crossing per (actor, finding, hour).
    -- It is a stored column, NOT `date_trunc('hour', detected_at)` inside the
    -- index: date_trunc on a timestamptz is STABLE (timezone-dependent), and
    -- Postgres refuses a non-IMMUTABLE function in an index expression. The
    -- writer sets this to date_trunc('hour', detected_at); the DEFAULT keeps a
    -- plain insert self-consistent.
    detected_hour timestamptz NOT NULL DEFAULT date_trunc('hour', now()),
    actor_key    text        NOT NULL REFERENCES actors(actor_key) ON DELETE CASCADE,
    asset_id     bigint      NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    finding_id   bigint      NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    incident_id  bigint      REFERENCES incidents(id) ON DELETE SET NULL,

    probe_evidence jsonb     NOT NULL DEFAULT '{}'::jsonb,
    match_reason   text      NOT NULL,       -- path_match | port_match | banner_match | cve_probe
    confidence     numeric(3,2) NOT NULL DEFAULT 0.5,
    notified_at    timestamptz
);

CREATE UNIQUE INDEX exposure_crossings_unique_idx
    ON exposure_crossings (actor_key, finding_id, detected_hour);
CREATE INDEX exposure_crossings_recent_idx ON exposure_crossings (detected_at DESC);
