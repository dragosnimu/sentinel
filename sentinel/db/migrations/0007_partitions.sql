-- 0007_partitions: partition management and retention.
--
-- Retention is DETACH + DROP, not DELETE. Dropping a partition is O(1) and
-- returns the space immediately; deleting 30 million rows leaves the table the
-- same size, needs a VACUUM FULL to reclaim anything, and takes an exclusive
-- lock while it does so. On a box that is also running something else, that
-- matters.
--
-- These functions are called hourly by sentinel-maintenance. They are written
-- so that calling them twice, or after a gap, is safe.

-- ---------------------------------------------------------------------------
-- Creation
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION sentinel_create_partition(
    parent  text,
    day     date
) RETURNS text AS $$
DECLARE
    part_name text := format('%s_%s', parent, to_char(day, 'YYYYMMDD'));
BEGIN
    IF to_regclass(part_name) IS NOT NULL THEN
        RETURN part_name;
    END IF;

    EXECUTE format(
        'CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
        part_name, parent, day, day + 1
    );
    RETURN part_name;
END;
$$ LANGUAGE plpgsql;

-- Create partitions ahead of time. Called hourly; `ahead => 3` means a
-- maintenance outage of up to three days cannot cause an insert to fail.
CREATE OR REPLACE FUNCTION sentinel_ensure_partitions(ahead integer DEFAULT 3)
RETURNS integer AS $$
DECLARE
    parent  text;
    d       date;
    created integer := 0;
BEGIN
    FOREACH parent IN ARRAY ARRAY['raw_events', 'health_samples', 'capacity_samples'] LOOP
        FOR d IN
            SELECT generate_series(current_date, current_date + ahead, '1 day')::date
        LOOP
            IF to_regclass(format('%s_%s', parent, to_char(d, 'YYYYMMDD'))) IS NULL THEN
                PERFORM sentinel_create_partition(parent, d);
                created := created + 1;
            END IF;
        END LOOP;
    END LOOP;
    RETURN created;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- Retention
-- ---------------------------------------------------------------------------
-- Never touches the DEFAULT partition: rows land there when a real partition
-- was missing, and dropping it would silently discard exactly the data that
-- arrived while something was broken.
CREATE OR REPLACE FUNCTION sentinel_drop_old_partitions(
    parent     text,
    keep_days  integer
) RETURNS TABLE (dropped text, rows_estimate bigint) AS $$
DECLARE
    cutoff date := current_date - keep_days;
    rec    record;
BEGIN
    FOR rec IN
        SELECT c.relname,
               c.reltuples::bigint AS est
        FROM pg_class c
        JOIN pg_inherits i ON i.inhrelid = c.oid
        JOIN pg_class p    ON p.oid = i.inhparent
        WHERE p.relname = parent
          AND c.relname ~ '_[0-9]{8}$'
          AND to_date(right(c.relname, 8), 'YYYYMMDD') < cutoff
    LOOP
        EXECUTE format('ALTER TABLE %I DETACH PARTITION %I', parent, rec.relname);
        EXECUTE format('DROP TABLE %I', rec.relname);
        dropped := rec.relname;
        rows_estimate := rec.est;
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- The disk guard. When free space falls below the threshold, retention is
-- shortened progressively rather than waiting for the disk to fill: a full
-- filesystem stops ingestion, stops PostgreSQL, and on this host would take
-- everything else on the host with it.
CREATE OR REPLACE FUNCTION sentinel_emergency_retention(
    target_days integer DEFAULT 7
) RETURNS integer AS $$
DECLARE
    total integer := 0;
    r     record;
BEGIN
    FOR r IN SELECT * FROM sentinel_drop_old_partitions('raw_events', target_days) LOOP
        total := total + 1;
    END LOOP;
    FOR r IN SELECT * FROM sentinel_drop_old_partitions('health_samples', target_days) LOOP
        total := total + 1;
    END LOOP;
    FOR r IN SELECT * FROM sentinel_drop_old_partitions('capacity_samples', target_days) LOOP
        total := total + 1;
    END LOOP;
    RETURN total;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- Rollups
-- ---------------------------------------------------------------------------
-- Idempotent: re-running for the same window overwrites rather than duplicating,
-- so a maintenance job that was interrupted can simply be run again.
CREATE OR REPLACE FUNCTION sentinel_rollup_events_1m(
    from_ts timestamptz,
    to_ts   timestamptz
) RETURNS integer AS $$
DECLARE
    n integer;
BEGIN
    INSERT INTO event_rollup_1m (bucket, asset_id, source, action, n, uniq_src,
                                 bytes_in, bytes_out, p95_latency_ms)
    SELECT date_trunc('minute', ts),
           COALESCE(asset_id, 0),
           source,
           action,
           count(*),
           count(DISTINCT src_ip),
           COALESCE(sum(bytes_in), 0),
           COALESCE(sum(bytes_out), 0),
           percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms)::integer
    FROM raw_events
    WHERE ts >= from_ts AND ts < to_ts
    GROUP BY 1, 2, 3, 4
    ON CONFLICT (bucket, asset_id, source, action) DO UPDATE
        SET n = EXCLUDED.n,
            uniq_src = EXCLUDED.uniq_src,
            bytes_in = EXCLUDED.bytes_in,
            bytes_out = EXCLUDED.bytes_out,
            p95_latency_ms = EXCLUDED.p95_latency_ms;

    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION sentinel_rollup_events_1h(
    from_ts timestamptz,
    to_ts   timestamptz
) RETURNS integer AS $$
DECLARE
    n integer;
BEGIN
    -- Built from the 1m rollup, not from raw_events, so this stays cheap even
    -- once raw retention has expired.
    INSERT INTO event_rollup_1h (bucket, asset_id, source, action, n, uniq_src,
                                 bytes_in, bytes_out, p95_latency_ms)
    SELECT date_trunc('hour', bucket),
           asset_id, source, action,
           sum(n),
           max(uniq_src),           -- an upper bound; exact distinctness is not
                                    -- reconstructable from minute buckets
           sum(bytes_in),
           sum(bytes_out),
           max(p95_latency_ms)
    FROM event_rollup_1m
    WHERE bucket >= from_ts AND bucket < to_ts
    GROUP BY 1, 2, 3, 4
    ON CONFLICT (bucket, asset_id, source, action) DO UPDATE
        SET n = EXCLUDED.n,
            uniq_src = EXCLUDED.uniq_src,
            bytes_in = EXCLUDED.bytes_in,
            bytes_out = EXCLUDED.bytes_out,
            p95_latency_ms = EXCLUDED.p95_latency_ms;

    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION sentinel_rollup_availability(target_day date)
RETURNS integer AS $$
DECLARE
    n integer;
BEGIN
    INSERT INTO availability_rollup (
        asset_id, day, samples, up_samples, degraded_samples, down_samples,
        uptime_pct, p50_latency_ms, p95_latency_ms, p99_latency_ms, max_latency_ms
    )
    SELECT asset_id,
           target_day,
           count(*),
           count(*) FILTER (WHERE status = 'up'),
           count(*) FILTER (WHERE status = 'degraded'),
           count(*) FILTER (WHERE status = 'down'),
           -- Degraded counts as available: the service answered. It is tracked
           -- separately so "up but slow" is still visible.
           round(100.0 * count(*) FILTER (WHERE status IN ('up','degraded'))
                 / NULLIF(count(*), 0), 3),
           percentile_cont(0.50) WITHIN GROUP (ORDER BY latency_ms)::integer,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms)::integer,
           percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms)::integer,
           max(latency_ms)
    FROM health_samples
    WHERE ts >= target_day AND ts < target_day + 1
    GROUP BY asset_id
    ON CONFLICT (asset_id, day) DO UPDATE
        SET samples          = EXCLUDED.samples,
            up_samples       = EXCLUDED.up_samples,
            degraded_samples = EXCLUDED.degraded_samples,
            down_samples     = EXCLUDED.down_samples,
            uptime_pct       = EXCLUDED.uptime_pct,
            p50_latency_ms   = EXCLUDED.p50_latency_ms,
            p95_latency_ms   = EXCLUDED.p95_latency_ms,
            p99_latency_ms   = EXCLUDED.p99_latency_ms,
            max_latency_ms   = EXCLUDED.max_latency_ms;

    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$ LANGUAGE plpgsql;

-- Create the first few partitions now so the very first insert has a home.
SELECT sentinel_ensure_partitions(3);
