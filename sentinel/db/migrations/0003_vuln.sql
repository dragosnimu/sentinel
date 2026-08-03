-- 0003_vuln: scan runs and deduplicated vulnerability findings.
--
-- The value here is not the scanning; it is `finding_key` and `priority`.
--
--   finding_key makes a finding a *thing with a history* rather than a new row
--   every night. Without it you cannot answer "how long has this been open",
--   which is the only vulnerability metric that matters.
--
--   priority is what the operator sorts by. CVSS alone ranks an unreachable
--   library above an internet-facing app that is being actively exploited.

CREATE TABLE scans (
    id              bigserial   PRIMARY KEY,
    scanner         text        NOT NULL,   -- dnf | trivy_fs | trivy_image | nuclei | semgrep | lynis | web_checks | tls
    target          text        NOT NULL,
    asset_id        bigint      REFERENCES assets(id) ON DELETE SET NULL,

    status          text        NOT NULL DEFAULT 'running'
                      CHECK (status IN ('running','completed','failed','timeout','skipped')),
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    duration_ms     integer,
    exit_code       integer,

    findings_count  integer     NOT NULL DEFAULT 0,
    new_findings    integer     NOT NULL DEFAULT 0,
    resolved_findings integer   NOT NULL DEFAULT 0,

    raw_output_path text,
    -- A clean report from a scanner whose database is three weeks old is a
    -- partial picture, and the operator needs to know that.
    db_version      text,
    error           text,
    triggered_by    text        NOT NULL DEFAULT 'schedule'
);

CREATE INDEX scans_recent_idx  ON scans (started_at DESC);
CREATE INDEX scans_scanner_idx ON scans (scanner, started_at DESC);

CREATE TABLE findings (
    id                 bigserial   PRIMARY KEY,

    -- sha256(scanner + asset + package + cve + location). Stable across runs.
    finding_key        text        NOT NULL UNIQUE,

    asset_id           bigint      REFERENCES assets(id) ON DELETE CASCADE,
    scanner            text        NOT NULL,

    cve                text,
    advisory_id        text,                     -- ALSA-2026:1234 — authoritative on AlmaLinux
    title              text,
    description        text,

    severity           text        NOT NULL DEFAULT 'medium'
                         CHECK (severity IN ('info','low','medium','high','critical')),
    cvss               numeric(3,1) CHECK (cvss IS NULL OR cvss BETWEEN 0 AND 10),
    cvss_vector        text,

    -- FIRST EPSS: probability of exploitation in the next 30 days. Refreshed
    -- daily. Far better than CVSS at predicting what actually gets attacked.
    epss               numeric(5,4) CHECK (epss IS NULL OR epss BETWEEN 0 AND 1),
    -- CISA Known Exploited Vulnerabilities: it is being exploited right now.
    kev                boolean     NOT NULL DEFAULT false,
    kev_due_date       date,

    package            text,
    installed_version  text,
    fixed_version      text,
    location           text,                     -- file path, image, or URL
    ecosystem          text,                     -- rpm | npm | pypi | composer | go | container

    -- CVSS x EPSS x KEV x internet-exposed x asset criticality x fix availability.
    priority           smallint    NOT NULL DEFAULT 0 CHECK (priority BETWEEN 0 AND 100),

    status             text        NOT NULL DEFAULT 'open'
                         CHECK (status IN ('open','patch_planned','patching','resolved',
                                           'accepted_risk','deferred','false_positive')),

    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_seen          timestamptz NOT NULL DEFAULT now(),
    resolved_at        timestamptz,
    -- Set when the post-patch verification still fires. That is itself valuable
    -- information: the patch applied but did not fix the finding.
    resolution         text,

    deferred_until     timestamptz,
    accepted_by        text,
    accepted_reason    text,

    -- Protected assets. No automated plan will ever be generated.
    requires_manual_intervention boolean NOT NULL DEFAULT false,

    scan_id            bigint      REFERENCES scans(id) ON DELETE SET NULL,
    raw                jsonb       NOT NULL DEFAULT '{}'::jsonb,

    -- AI assessment from sentinel-vuln-analyst: exploitability in this
    -- deployment, backported-patch false positives, mitigation advice.
    ai_assessment      jsonb,
    ai_assessed_at     timestamptz
);

CREATE INDEX findings_open_priority_idx ON findings (priority DESC, cvss DESC NULLS LAST)
    WHERE status = 'open';
CREATE INDEX findings_asset_idx  ON findings (asset_id, status);
CREATE INDEX findings_cve_idx    ON findings (cve) WHERE cve IS NOT NULL;
CREATE INDEX findings_kev_idx    ON findings (kev, priority DESC) WHERE kev AND status = 'open';
CREATE INDEX findings_age_idx    ON findings (first_seen) WHERE status = 'open';

-- Every time a finding is seen or changes state. Answers "when did this appear,
-- when was it planned, when was it fixed, did it come back".
CREATE TABLE finding_history (
    id          bigserial   PRIMARY KEY,
    finding_id  bigint      NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    at          timestamptz NOT NULL DEFAULT now(),
    event       text        NOT NULL,   -- seen | status_change | reappeared | priority_change
    from_value  text,
    to_value    text,
    scan_id     bigint      REFERENCES scans(id) ON DELETE SET NULL,
    note        text
);

CREATE INDEX finding_history_idx ON finding_history (finding_id, at DESC);
