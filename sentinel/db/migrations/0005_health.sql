-- 0005_health: availability and capacity, live and historical.
--
-- health_samples is partitioned like raw_events: at one sample per asset per
-- 30 s, ten assets produce ~29k rows a day, and retention needs to be a
-- partition drop rather than a DELETE.
--
-- availability_rollup is what the SLA views read. Computing uptime from raw
-- samples over a month works but is slow and gets slower; the rollup does not.

CREATE TABLE health_samples (
    id           bigserial,
    ts           timestamptz NOT NULL,
    asset_id     bigint      NOT NULL,

    status       text        NOT NULL CHECK (status IN ('up','degraded','down','unknown')),
    latency_ms   integer,
    http_status  integer,
    error        text,
    probe        text        NOT NULL DEFAULT 'http',  -- http | tcp | systemd | docker | db

    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

CREATE INDEX health_samples_asset_idx ON health_samples (asset_id, ts DESC);
CREATE INDEX health_samples_ts_idx    ON health_samples (ts DESC);
CREATE INDEX health_samples_down_idx  ON health_samples (asset_id, ts DESC)
    WHERE status IN ('down','degraded');

CREATE TABLE health_samples_default PARTITION OF health_samples DEFAULT;

CREATE TABLE availability_rollup (
    asset_id          bigint      NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    day               date        NOT NULL,

    samples           integer     NOT NULL DEFAULT 0,
    up_samples        integer     NOT NULL DEFAULT 0,
    degraded_samples  integer     NOT NULL DEFAULT 0,
    down_samples      integer     NOT NULL DEFAULT 0,

    -- Degraded counts as up for availability but is visible separately; a
    -- service answering in 8 seconds is technically up and practically not.
    uptime_pct        numeric(6,3),
    p50_latency_ms    integer,
    p95_latency_ms    integer,
    p99_latency_ms    integer,
    max_latency_ms    integer,

    incidents_count   integer     NOT NULL DEFAULT 0,
    longest_outage_s  integer     NOT NULL DEFAULT 0,

    PRIMARY KEY (asset_id, day)
);

CREATE INDEX availability_rollup_day_idx ON availability_rollup (day DESC);

-- Discrete outage records, so "we were down for 4 minutes on Tuesday" is a row
-- rather than something you derive from a gap in samples.
CREATE TABLE outages (
    id           bigserial   PRIMARY KEY,
    asset_id     bigint      NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    started_at   timestamptz NOT NULL,
    ended_at     timestamptz,
    duration_s   integer,
    kind         text        NOT NULL DEFAULT 'down' CHECK (kind IN ('down','degraded')),
    cause        text,
    incident_id  bigint      REFERENCES incidents(id) ON DELETE SET NULL,
    -- True when the outage falls inside a maintenance window, so planned work
    -- does not pollute the availability figure.
    planned      boolean     NOT NULL DEFAULT false
);

CREATE INDEX outages_asset_idx ON outages (asset_id, started_at DESC);
CREATE INDEX outages_open_idx  ON outages (asset_id) WHERE ended_at IS NULL;

-- ---------------------------------------------------------------------------
-- Host capacity
-- ---------------------------------------------------------------------------
-- On a shared host, memory is the binding constraint: the OOM killer picks the
-- largest process, which is usually the application Sentinel was installed to
-- protect. mem_available_mb is the number to watch.
CREATE TABLE capacity_samples (
    id                bigserial,
    ts                timestamptz NOT NULL,

    cpu_pct           numeric(5,2),
    load1             numeric(6,2),
    load5             numeric(6,2),
    load15            numeric(6,2),

    mem_total_mb      integer,
    mem_used_mb       integer,
    mem_available_mb  integer,
    swap_used_mb      integer,

    -- {"/": {"used_pct": 43.2, "free_gb": 51.1}, "/var": {...}}
    disks             jsonb       NOT NULL DEFAULT '{}'::jsonb,
    disk_used_pct     numeric(5,2),               -- the busiest mount, denormalised for queries
    inode_used_pct    numeric(5,2),

    conn_count        integer,
    -- {"sentinel-detect": 84, "nginx": 42, "postgres": 310}
    per_service_rss   jsonb       NOT NULL DEFAULT '{}'::jsonb,

    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

CREATE INDEX capacity_samples_ts_idx ON capacity_samples (ts DESC);

CREATE TABLE capacity_samples_default PARTITION OF capacity_samples DEFAULT;

CREATE TABLE capacity_rollup_1h (
    bucket                timestamptz PRIMARY KEY,
    cpu_pct_avg           numeric(5,2),
    cpu_pct_max           numeric(5,2),
    load1_avg             numeric(6,2),
    mem_available_mb_avg  integer,
    mem_available_mb_min  integer,
    disk_used_pct_max     numeric(5,2),
    conn_count_max        integer
);

-- Linear projection from the 30-day disk trend. Turns "the disk is at 71%"
-- into "the disk fills on 14 August", which is the actionable form.
CREATE TABLE capacity_projections (
    id             bigserial   PRIMARY KEY,
    computed_at    timestamptz NOT NULL DEFAULT now(),
    metric         text        NOT NULL,       -- disk_root | disk_var | db_size
    current_value  numeric,
    daily_growth   numeric,
    exhausted_at   timestamptz,
    confidence     numeric(3,2)
);

CREATE INDEX capacity_projections_idx ON capacity_projections (metric, computed_at DESC);
