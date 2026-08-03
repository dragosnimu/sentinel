-- 0001_core: assets, events, detections, actors, incidents.
--
-- This is the schema everything else is written against. Two decisions worth
-- knowing:
--
--   * raw_events is declaratively partitioned by day. Retention becomes
--     DETACH PARTITION + DROP TABLE, which is instant and does not bloat,
--     rather than a DELETE that leaves the table the same size.
--   * actor_key is a text key, not an IP. An "actor" may be a cluster of IPs
--     behaving as one (same /24 + ASN + UA/JA4). Joining detections to actors
--     on src_ip would split a single campaign into dozens of unrelated rows.

-- ---------------------------------------------------------------------------
-- Assets
-- ---------------------------------------------------------------------------
CREATE TABLE assets (
    id                    bigserial PRIMARY KEY,
    name                  text        NOT NULL UNIQUE,
    kind                  text        NOT NULL
                            CHECK (kind IN ('web','service','container','database','host')),
    bind_addr             inet,
    port                  integer     CHECK (port IS NULL OR port BETWEEN 1 AND 65535),

    -- Confirmed by an external reachability probe, not merely by a 0.0.0.0
    -- bind: a provider firewall may make a listening socket unreachable.
    is_internet_exposed   boolean     NOT NULL DEFAULT false,
    criticality           integer     NOT NULL DEFAULT 3 CHECK (criticality BETWEEN 1 AND 5),

    systemd_unit          text,
    container_id          text,
    container_image       text,
    vhost_file            text,
    webroot               text,
    repo_path             text,
    repo_remote           text,
    repo_branch           text,
    stack                 text,

    -- [{engine,name,host,port}] — what a patch plan's backup step must dump.
    databases             jsonb       NOT NULL DEFAULT '[]'::jsonb,

    -- Sentinel's own components, plus anything the operator declares off
    -- limits. No automated patch plan may target
    -- these, ever. Enforced in patch/validator.py, not only here.
    protected             boolean     NOT NULL DEFAULT false,

    -- Active scanning (DAST) requires the operator to have confirmed the asset
    -- is theirs. Discovery alone does not authorise attacking something.
    confirmed_by_operator boolean     NOT NULL DEFAULT false,

    tags                  text[]      NOT NULL DEFAULT '{}',
    notes                 text,
    first_seen            timestamptz NOT NULL DEFAULT now(),
    last_seen             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX assets_exposed_idx  ON assets (is_internet_exposed, criticality DESC);
CREATE INDEX assets_protected_idx ON assets (protected) WHERE protected;

-- Discovery findings that contradict the operator-maintained inventory.
-- Recorded and surfaced, never silently applied.
CREATE TABLE asset_drift (
    id                bigserial PRIMARY KEY,
    asset_id          bigint      NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    field             text        NOT NULL,
    discovered_value  text,
    inventory_value   text,
    detected_at       timestamptz NOT NULL DEFAULT now(),
    resolved_at       timestamptz,
    resolution        text
);

CREATE INDEX asset_drift_open_idx ON asset_drift (asset_id) WHERE resolved_at IS NULL;

-- ---------------------------------------------------------------------------
-- Events (partitioned daily)
-- ---------------------------------------------------------------------------
CREATE TABLE raw_events (
    id            bigserial,
    ts            timestamptz NOT NULL,
    source        text        NOT NULL,
    action        text        NOT NULL DEFAULT 'unknown',
    asset_id      bigint,

    src_ip        inet,
    src_port      integer,
    dst_ip        inet,
    dst_port      integer,
    proto         text,

    -- Attacker-controlled from here down. Stored verbatim: truncating evidence
    -- to make it tidy destroys the thing an investigation needs. Bounded at
    -- ingest (see model/event.py) so a 4 MB User-Agent cannot bloat a partition.
    username      text,
    http_method   text,
    http_path     text,
    http_query    text,
    http_status   integer,
    http_ua       text,
    http_host     text,
    http_referer  text,

    bytes_in      bigint,
    bytes_out     bigint,
    latency_ms    integer,

    process       text,
    pid           integer,
    file_path     text,
    tls_sni       text,
    tls_ja4       text,

    geo_country   text,
    geo_asn       integer,
    geo_as_org    text,
    reputation    text[]      NOT NULL DEFAULT '{}',

    raw           jsonb       NOT NULL DEFAULT '{}'::jsonb,

    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

-- Indexes on the parent propagate to every partition, existing and future.
CREATE INDEX raw_events_ts_idx        ON raw_events (ts DESC);
CREATE INDEX raw_events_src_ip_idx    ON raw_events (src_ip, ts DESC) WHERE src_ip IS NOT NULL;
CREATE INDEX raw_events_asset_idx     ON raw_events (asset_id, ts DESC);
CREATE INDEX raw_events_source_idx    ON raw_events (source, action, ts DESC);
CREATE INDEX raw_events_http_path_idx ON raw_events (http_path) WHERE http_path IS NOT NULL;
CREATE INDEX raw_events_raw_gin       ON raw_events USING gin (raw);

-- Somewhere for rows to land before the maintenance job creates real
-- partitions. Without it the first INSERT after a gap fails.
CREATE TABLE raw_events_default PARTITION OF raw_events DEFAULT;

-- Pre-aggregated counters. Anything asking about more than ~24 hours reads
-- these; querying raw_events across weeks is slow and the aggregate was what
-- the question wanted anyway.
CREATE TABLE event_rollup_1m (
    bucket         timestamptz NOT NULL,
    asset_id       bigint,
    source         text        NOT NULL,
    action         text        NOT NULL,
    n              bigint      NOT NULL,
    uniq_src       integer     NOT NULL,
    bytes_in       bigint      NOT NULL DEFAULT 0,
    bytes_out      bigint      NOT NULL DEFAULT 0,
    p95_latency_ms integer,
    PRIMARY KEY (bucket, asset_id, source, action)
);

CREATE TABLE event_rollup_1h (
    LIKE event_rollup_1m INCLUDING ALL
);

-- ---------------------------------------------------------------------------
-- Actors
-- ---------------------------------------------------------------------------
CREATE TABLE actors (
    actor_key         text        PRIMARY KEY,   -- an IP, or 'cluster:<hash>'
    kind              text        NOT NULL DEFAULT 'ip' CHECK (kind IN ('ip','cluster')),
    member_ips        inet[]      NOT NULL DEFAULT '{}',

    killchain_stage   smallint    NOT NULL DEFAULT 0 CHECK (killchain_stage BETWEEN 0 AND 6),
    -- How long they have sat at the current stage is often more informative
    -- than the stage itself: two days at stage 2 is a crawler, eleven minutes
    -- from 1 to 3 is a script that will reach stage 4 shortly.
    stage_entered_at  timestamptz NOT NULL DEFAULT now(),

    first_seen        timestamptz NOT NULL DEFAULT now(),
    last_seen         timestamptz NOT NULL DEFAULT now(),
    event_count       bigint      NOT NULL DEFAULT 0,
    detection_count   bigint      NOT NULL DEFAULT 0,

    countries         text[]      NOT NULL DEFAULT '{}',
    asns              integer[]   NOT NULL DEFAULT '{}',
    user_agents       text[]      NOT NULL DEFAULT '{}',
    ja4_fingerprints  text[]      NOT NULL DEFAULT '{}',
    targeted_assets   bigint[]    NOT NULL DEFAULT '{}',
    reputation        text[]      NOT NULL DEFAULT '{}',

    -- Reputation feeds that classify a source as internet-measurement research
    -- rather than an attacker. Suppresses a large share of false positives.
    is_known_scanner  boolean     NOT NULL DEFAULT false,

    risk_score        smallint    NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    is_blocked        boolean     NOT NULL DEFAULT false,
    is_allowlisted    boolean     NOT NULL DEFAULT false,
    notes             text
);

CREATE INDEX actors_stage_idx    ON actors (killchain_stage DESC, stage_entered_at);
CREATE INDEX actors_risk_idx     ON actors (risk_score DESC);
CREATE INDEX actors_lastseen_idx ON actors (last_seen DESC);

-- ---------------------------------------------------------------------------
-- Detections
-- ---------------------------------------------------------------------------
CREATE TABLE detections (
    id           bigserial   PRIMARY KEY,
    ts           timestamptz NOT NULL DEFAULT now(),
    rule_id      text        NOT NULL,          -- 'auth.ssh_bruteforce'
    rule_family  text        NOT NULL,          -- 'auth' | 'web' | 'scan' | ...
    severity     text        NOT NULL
                   CHECK (severity IN ('info','low','medium','high','critical')),
    score        numeric(6,2),                   -- robust z-score, anomaly rules only

    actor_key    text        REFERENCES actors(actor_key) ON DELETE SET NULL,
    asset_id     bigint      REFERENCES assets(id) ON DELETE SET NULL,
    src_ip       inet,
    dst_port     integer,

    evidence     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    event_ids    bigint[]    NOT NULL DEFAULT '{}',

    incident_id  bigint,                          -- FK added after incidents exists
    suppressed   boolean     NOT NULL DEFAULT false,
    suppress_reason text
);

CREATE INDEX detections_ts_idx       ON detections (ts DESC);
CREATE INDEX detections_actor_idx    ON detections (actor_key, ts DESC);
CREATE INDEX detections_rule_idx     ON detections (rule_id, ts DESC);
CREATE INDEX detections_incident_idx ON detections (incident_id) WHERE incident_id IS NOT NULL;
CREATE INDEX detections_asset_idx    ON detections (asset_id, ts DESC);

-- ---------------------------------------------------------------------------
-- Incidents
-- ---------------------------------------------------------------------------
CREATE TABLE incidents (
    id                  bigserial   PRIMARY KEY,

    -- rule_family + actor_key + asset_id + 15-minute bucket. Without this,
    -- a brute-force attempt becomes 400 incidents instead of one.
    fingerprint         text        NOT NULL,

    status              text        NOT NULL DEFAULT 'open'
                          CHECK (status IN ('open','acknowledged','resolved',
                                            'false_positive','suppressed')),
    severity            text        NOT NULL
                          CHECK (severity IN ('info','low','medium','high','critical')),

    -- The AI's verdict lands here. It never overwrites the deterministic
    -- severity: both are kept so a disagreement is visible and reviewable.
    ai_severity         text        CHECK (ai_severity IN ('info','low','medium','high','critical')),
    ai_verdict          jsonb,
    ai_confidence       numeric(3,2) CHECK (ai_confidence IS NULL OR ai_confidence BETWEEN 0 AND 1),
    ai_analyzed_at      timestamptz,

    title               text        NOT NULL,
    summary             text,

    actor_key           text        REFERENCES actors(actor_key) ON DELETE SET NULL,
    asset_id            bigint      REFERENCES assets(id) ON DELETE SET NULL,

    detection_count     integer     NOT NULL DEFAULT 1,
    created_at          timestamptz NOT NULL DEFAULT now(),
    first_detection_at  timestamptz NOT NULL DEFAULT now(),
    last_detection_at   timestamptz NOT NULL DEFAULT now(),

    acknowledged_by     text,
    acknowledged_at     timestamptz,
    resolved_at         timestamptz,
    resolution_note     text,

    notified_at         timestamptz
);

CREATE UNIQUE INDEX incidents_fingerprint_open_idx
    ON incidents (fingerprint)
    WHERE status IN ('open', 'acknowledged');

CREATE INDEX incidents_status_idx ON incidents (status, last_detection_at DESC);
CREATE INDEX incidents_actor_idx  ON incidents (actor_key, first_detection_at DESC);
CREATE INDEX incidents_asset_idx  ON incidents (asset_id, first_detection_at DESC);

ALTER TABLE detections
    ADD CONSTRAINT detections_incident_fk
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL;

CREATE TABLE incident_timeline (
    id          bigserial   PRIMARY KEY,
    incident_id bigint      NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    at          timestamptz NOT NULL DEFAULT now(),
    kind        text        NOT NULL,   -- detection | action | note | ai_verdict | status
    actor       text,                    -- 'auto' | 'telegram:<id>' | 'operator:<user>'
    detail      jsonb       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX incident_timeline_idx ON incident_timeline (incident_id, at);
