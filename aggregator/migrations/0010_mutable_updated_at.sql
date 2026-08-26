-- `updated_at` pentru celelalte trei fluxuri mutabile: findings, blocklist,
-- patch_plans.
--
-- `0006_incident_updated_at.sql` a făcut același lucru pentru `incidents`, cu
-- motivul întreg scris acolo. Se repetă aici pe scurt, fiindcă cine citește
-- migrația asta n-are de ce s-o citească pe aia:
--
--   * un flux mutabil se expediază în ordinea `(updated_at, id)`, iar
--     `_collect_mutable` din `sentinel/report/shipper.py` SELECTEAZĂ coloana ca
--     să-și mute poziția locală — deci ea pleacă pe sârmă cu fiecare rând;
--   * ingestia REFUZĂ un câmp necunoscut, dinadins: ignorat, ar fi un rând
--     pierdut definitiv, fiindcă ce trece de cursor nu se mai retrimite;
--   * deci fără coloana asta fluxul s-ar opri la primul lot, cu mesajul „câmpul
--     necunoscut updated_at". Vizibil, dar oprit — iar de pe gazdă se vede doar
--     ca restanță în `ship:lag`.
--
-- Pe server coloanele există din `0023_ship_watermarks.sql`, întreținute de un
-- trigger `BEFORE UPDATE`. Valoarea e momentul de pe SERVER la care rândul s-a
-- schimbat ultima oară — nu `received_at`, și nu o poziție de flux.
--
-- `NULL` acceptat, din același motiv ca la incidente: coloana se adaugă DUPĂ ce
-- tabela există, iar un rând sosit înainte n-are de unde să aibă valoarea.
-- `NULL` înseamnă „nu se știe", care e adevărat; o valoare implicită inventată
-- ar spune „s-a schimbat la 1970", care nu e.

-- @guard column finding_entries updated_at
ALTER TABLE finding_entries
    ADD COLUMN updated_at DATETIME(6) NULL
    COMMENT 'findings.updated_at de pe server; ordinea de expediere, nu ora sosirii';

-- @guard index finding_entries ix_finding_entries_updated
CREATE INDEX ix_finding_entries_updated
    ON finding_entries (instance_id, updated_at);

-- @guard column blocklist_entries updated_at
ALTER TABLE blocklist_entries
    ADD COLUMN updated_at DATETIME(6) NULL
    COMMENT 'blocklist.updated_at de pe server; ordinea de expediere, nu ora sosirii';

-- @guard index blocklist_entries ix_blocklist_entries_updated
CREATE INDEX ix_blocklist_entries_updated
    ON blocklist_entries (instance_id, updated_at);

-- @guard column patch_plan_entries updated_at
ALTER TABLE patch_plan_entries
    ADD COLUMN updated_at DATETIME(6) NULL
    COMMENT 'patch_plans.updated_at de pe server; ordinea de expediere, nu ora sosirii';

-- @guard index patch_plan_entries ix_patch_plan_entries_updated
CREATE INDEX ix_patch_plan_entries_updated
    ON patch_plan_entries (instance_id, updated_at);
