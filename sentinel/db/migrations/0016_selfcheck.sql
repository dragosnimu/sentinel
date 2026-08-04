-- 0016_selfcheck: what the self-check saw last time.
--
-- Only the LAST result per check is kept, not a history. The question this
-- table answers is "has this changed since I last looked?", because alerting on
-- state changes is the difference between a channel that gets read and one that
-- sends the same line every minute until it is muted.
--
-- History would be nice and is deliberately not here: it belongs in a rollup if
-- anyone ever wants trends, and until then an unbounded table of "still fine"
-- rows is just disk that fills up.

CREATE TABLE IF NOT EXISTS selfcheck_state (
    key            text        PRIMARY KEY,
    status         text        NOT NULL
                     CHECK (status IN ('ok','degraded','down','unknown')),
    title          text        NOT NULL,
    detail         text        NOT NULL DEFAULT '',
    facts          jsonb       NOT NULL DEFAULT '{}'::jsonb,

    -- When this check first entered its CURRENT status. Lets an alert say "down
    -- for 3 hours" rather than "down", which is the difference between a
    -- glance and an investigation.
    since          timestamptz NOT NULL DEFAULT now(),
    last_seen      timestamptz NOT NULL DEFAULT now(),

    -- Last time a message about this check was actually sent. A problem that
    -- persists is re-announced on a slow cadence rather than never: an alert
    -- from four hours ago scrolls away, and the fault is still there.
    last_alert_at  timestamptz
);

CREATE INDEX IF NOT EXISTS selfcheck_state_bad_idx
    ON selfcheck_state (status, since)
    WHERE status IN ('down','degraded');

COMMENT ON TABLE selfcheck_state IS
    'Latest result per self-check. Rows are compared, not accumulated.';

-- The runs themselves, so "when did the self-check last complete" is answerable
-- — including by the self-check that comes after a crash. Small and bounded by
-- the maintenance job.
CREATE TABLE IF NOT EXISTS selfcheck_runs (
    id           bigserial   PRIMARY KEY,
    started_at   timestamptz NOT NULL DEFAULT now(),
    duration_ms  integer,
    worst_status text        NOT NULL DEFAULT 'unknown',
    checks_run   integer     NOT NULL DEFAULT 0,
    checks_bad   integer     NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS selfcheck_runs_recent_idx ON selfcheck_runs (started_at DESC);
