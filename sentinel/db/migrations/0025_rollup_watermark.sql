-- 0025_rollup_watermark: un agregat RECALCULAT trebuie să plece din nou.
--
-- ## Eșecul, măsurat
--
-- Pe 24 august 2026, aceeași oră pe cele două capete:
--
--     interval   server                 agregator
--     04:00      6 rânduri, 1385 ev     5 rânduri,   60 ev
--     05:00      6 rânduri,  977 ev     5 rânduri,   22 ev
--     07:00      6 rânduri, 1312 ev     6 rânduri,   17 ev
--
-- De zece până la douăzeci de ori mai puțin, pe rânduri care există la ambele
-- capete. Nu lipseau: erau VECHI.
--
-- ## De ce
--
-- `maintenance_service` scrie agregatul pentru fereastra SCURSĂ, nu pentru ora
-- încheiată — raportul lui spune „event_rollup_1h: 12 rânduri pe 0,9h". Deci
-- intervalul 04:00 e scris o dată la 04:56, cu cât se adunase până atunci, și
-- completat la 05:56.
--
-- Cursorul fluxului mergea strict pe `bucket`: odată ce ora 04:00 se încheia
-- după ceas, rândurile ei plecau — versiunea parțială — iar cursorul trecea
-- dincolo și nu se mai întorcea. Comentariul din `shipper.py` spunea pe față pe
-- ce se sprijină: „dacă serverul ar recalcula vreodată un interval DUPĂ ce a
-- fost expediat, schimbarea aia n-ar mai pleca — mentenanța își încheie
-- intervalele înainte de a trece mai departe, și pe asta se sprijină".
-- Presupunerea era falsă. Scrisă, măcar s-a putut găsi.
--
-- ## Reparația
--
-- Aceeași ca la orice entitate care se schimbă după ce a fost scrisă: filigran
-- pe `(updated_at, bucket)`, întreținut de trigger. Un interval recalculat își
-- mută `updated_at`, deci trece din nou de cursor și pleacă cu valoarea nouă.
-- Ingestia e upsert pe `(instance_id, bucket, asset_source_id, source, action)`,
-- deci a doua sosire suprascrie prima în loc să se adune lângă ea.
--
-- `set_updated_at()` există din 0023; aici doar se leagă.

ALTER TABLE event_rollup_1h ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
DROP TRIGGER IF EXISTS event_rollup_1h_set_updated_at ON event_rollup_1h;
CREATE TRIGGER event_rollup_1h_set_updated_at
    BEFORE UPDATE ON event_rollup_1h
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX event_rollup_1h_updated_idx ON event_rollup_1h (updated_at, bucket);
