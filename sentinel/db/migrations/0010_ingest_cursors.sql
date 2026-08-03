-- 0010_ingest_cursors: where each collector stopped reading.
--
-- A collector that restarts must resume exactly where it left off — not from the
-- start (which would re-ingest and double-count every past event) and not from
-- "now" (which would silently drop everything logged while it was down). The
-- cursor is opaque and collector-specific: journald's is its own cursor string,
-- a file tailer's is "<inode>:<offset>". Persisting it in the database, updated
-- in the same transaction as the batch it covers, means the bookmark and the
-- data it refers to can never disagree.

CREATE TABLE collector_cursors (
    name        text        PRIMARY KEY,   -- 'sshd', 'nginx:/var/log/nginx/access.log', ...
    cursor      text        NOT NULL,
    events_seen bigint      NOT NULL DEFAULT 0,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
