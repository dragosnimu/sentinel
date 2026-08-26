-- `incident_entries.updated_at`: coloana pe care o CERE cursorul mutabil.
--
-- Capul lui `0005_patch.sql` scria că `updated_at` nu se adaugă fiindcă migrația
-- serverului care îl creează (`0023_ship_watermarks.sql`) nu era livrată, iar o
-- coloană modelată după una nelivrată e o ghicire cu formă de fapt. Acum e
-- livrată, iar fluxul `incidents` se înregistrează la ambele capete — deci
-- coloana se adaugă, cu cartografierea ei verificată.
--
-- ============================================================================
-- De ce e OBLIGATORIE, nu o comoditate
-- ============================================================================
--
-- Un flux mutabil se expediază în ordinea `(updated_at, id)`. Expeditorul
-- SELECTEAZĂ coloana aia — `sentinel/report/shipper.py`, `_collect_mutable`
-- citește `last[stream.time_column]` ca să-și mute poziția locală —, deci ea
-- pleacă pe sârmă cu fiecare rând. Iar ingestia REFUZĂ un câmp pe care nu-l
-- cunoaște, dinadins: un câmp ignorat ar fi un rând pierdut definitiv, fiindcă
-- ce trece de cursor nu se mai retrimite.
--
-- Fără coloana asta, fluxul `incidents` s-ar opri la primul lot, cu mesajul
-- „câmpul necunoscut updated_at" — vizibil, dar oprit.
--
-- ============================================================================
-- Ce înseamnă valoarea, și ce NU înseamnă
-- ============================================================================
--
-- E momentul de pe SERVER la care rândul s-a schimbat ultima oară, întreținut
-- acolo de un trigger `BEFORE UPDATE`. Nu e `received_at` (când a ajuns aici) și
-- nu e o poziție: poziția fluxului e perechea `(updated_at, id)` și trăiește la
-- expeditor. Vezi `lib/chain.ts` pentru ce se strică dacă cineva citește un
-- filigran ca poziție.
--
-- `NULL` acceptat, dinadins: coloana se adaugă DUPĂ ce tabela există, iar un
-- rând sosit înainte n-are de unde să aibă valoarea. `NULL` înseamnă „nu se
-- știe", care e adevărat; o valoare implicită inventată ar spune „s-a schimbat
-- la 1970", care nu e.

-- @guard column incident_entries updated_at
ALTER TABLE incident_entries
    ADD COLUMN updated_at DATETIME(6) NULL
    COMMENT 'incidents.updated_at de pe server; ordinea de expediere, nu ora sosirii';

-- @guard index incident_entries ix_incident_entries_updated
--
-- Ordinea în care sosesc rândurile unui flux mutabil e chiar ordinea asta, deci
-- „ce s-a schimbat de la momentul X" se citește pe ea. Nu e unic: pe replică,
-- două instanțe pot avea același moment, iar `(instance_id, updated_at)` nu e o
-- identitate — identitatea rămâne `(instance_id, source_id)`.
CREATE INDEX ix_incident_entries_updated
    ON incident_entries (instance_id, updated_at);
