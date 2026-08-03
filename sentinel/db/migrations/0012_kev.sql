-- 0012_kev: a local mirror of CISA's Known Exploited Vulnerabilities catalog.
--
-- KEV is the single strongest signal in prioritisation: CISA is asserting the
-- CVE is being exploited in the wild RIGHT NOW. A CVSS 6.5 on the KEV list
-- outranks a CVSS 9.8 that nobody has ever exploited. Mirrored locally so a scan
-- does not depend on reaching cisa.gov, and refreshed daily by the scan service.

CREATE TABLE kev_catalog (
    cve         text        PRIMARY KEY,
    vendor      text,
    product     text,
    name        text,
    added_date  date,
    due_date    date,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
