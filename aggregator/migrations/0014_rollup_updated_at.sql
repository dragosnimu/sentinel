-- `event_rollup_1h_entries.updated_at`: coloana pe care merge acum filigranul.
--
-- ## De ce s-a mutat
--
-- Măsurat pe 24 august 2026, aceeași oră pe cele două capete:
--
--     interval   server                 agregator
--     04:00      6 rânduri, 1385 ev     5 rânduri,   60 ev
--     05:00      6 rânduri,  977 ev     5 rânduri,   22 ev
--
-- Rândurile existau la ambele capete. Erau VECHI.
--
-- `maintenance_service` de pe server scrie agregatul pentru fereastra SCURSĂ, nu
-- pentru ora încheiată — raportul lui spune „12 rânduri pe 0,9h". Deci ora 04:00
-- e scrisă o dată la 04:56, cu cât se adunase, și completată la 05:56.
--
-- Cursorul expedierii mergea strict pe `bucket`: odată ce ora se încheia după
-- ceas, rândurile plecau — versiunea parțială — iar cursorul trecea dincolo și
-- nu se mai întorcea. Un grafic desenat peste valorile alea ar fi arătat perfect
-- normal și ar fi fost de douăzeci de ori mai mic decât realitatea.
--
-- Pe `updated_at`, un interval recalculat trece din nou de cursor. Ingestia e
-- upsert pe `(instance_id, bucket, asset_source_id, source, action)`, deci a
-- doua sosire SUPRASCRIE prima în loc să se adune lângă ea.
--
-- NULL-abilă, ca la celelalte: rândurile sosite înainte de migrație n-au de unde
-- s-o aibă, iar un `DEFAULT` ar inventa un moment. „Nu știu când" nu e „la 1970".

-- @guard column event_rollup_1h_entries updated_at
ALTER TABLE event_rollup_1h_entries
    ADD COLUMN updated_at DATETIME(6) NULL
    COMMENT 'event_rollup_1h.updated_at de pe server; ordinea de expediere';

-- @guard index event_rollup_1h_entries ix_event_rollup_1h_entries_updated
CREATE INDEX ix_event_rollup_1h_entries_updated
    ON event_rollup_1h_entries (instance_id, updated_at);
