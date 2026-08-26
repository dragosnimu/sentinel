-- `selfcheck_state_entries.updated_at`: coloana pe care o cere cursorul mutabil.
--
-- A patra oară când se adaugă exact coloana asta, cu exact același motiv, iar
-- repetiția e ea însăși informația: `0006` a făcut-o pentru incidente, `0010`
-- pentru constatări, blocări și planuri de patch. Regula, pe scurt:
--
--   * un flux mutabil se expediază în ordinea `(updated_at, cheie)`, iar
--     `_collect_mutable` din `sentinel/report/shipper.py` SELECTEAZĂ coloana ca
--     să-și mute poziția locală — deci ea pleacă pe sârmă cu fiecare rând;
--   * ingestia REFUZĂ un câmp necunoscut, dinadins;
--   * deci fără coloana asta fluxul s-ar opri la primul lot, iar de pe gazdă s-ar
--     vedea doar ca restanță în `ship:lag`.
--
-- Ce e DIFERIT aici: fluxul ăsta e primul cu filigran TEXT. Cheia lui e
-- `check_key`, nu un `source_id`, iar jetonul de ecou e cheia maximă pe octeți.
-- Vezi `0011_text_watermark.sql` pentru de ce cursorul are două coloane.

-- @guard column selfcheck_state_entries updated_at
ALTER TABLE selfcheck_state_entries
    ADD COLUMN updated_at DATETIME(6) NULL
    COMMENT 'selfcheck_state.updated_at de pe server; ordinea de expediere';

-- @guard index selfcheck_state_entries ix_selfcheck_state_entries_updated
CREATE INDEX ix_selfcheck_state_entries_updated
    ON selfcheck_state_entries (instance_id, updated_at);
