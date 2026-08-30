-- 0037_suricata_signature_index: indexul care face `ids_signatures` posibil
-- de citit fără heap, peste coloana reală din 0035/0036.
--
-- ## De ce dupăâ 0036, nu înainte și nu în aceeași migrație
--
-- Backfill-ul (0036) trebuie să termine înaintea acestui index, din două
-- motive, nu unul:
--
--   * corectitudine minoră: un index construit peste o coloană încă plină de
--     `NULL` ar indexa aceleași rânduri, doar cu chei goale — planificatorul
--     tot ar alege `Index Only Scan`, dar rezultatul afișat pe panou ar arăta
--     „semnătură necunoscută" pentru rânduri vechi până la backfill;
--   * separat de fișier, la fel ca 0035/0036: `CREATE INDEX` fără
--     `CONCURRENTLY` cere `SHARE` pe `raw_events`, care BLOCHEAZĂ scrierile
--     (nu și citirile) cât ține construcția. Dacă ar fi în aceeași tranzacție
--     ca declanșatorul din 0035, ar moșteni `ACCESS EXCLUSIVE`-ul deja ținut și
--     ar bloca și panoul, nu doar ingestia — exact argumentul de la 0036.
--
-- ## Forma indexului, măsurată pe replică
--
--     CREATE INDEX raw_events_suricata_sig_idx ON raw_events (ts DESC, signature)
--         INCLUDE (src_ip) WHERE source = 'suricata';
--
-- Mărimea: 27 MB pentru fereastra de retenție construită pe replică (11
-- partiții zilnice, ~301 600 de rânduri de suricata în ultimele 7 zile din
-- 318 610 în total). Planul, cu `shared_buffers` reîmprospătat între rulări ca
-- să nu se compare o rulare caldă cu una rece:
--
--     ids_signatures (interogarea REALĂ, cu LIMIT 6, fereastra de 7 zile)
--       cu raw->>'signature' (forma veche)
--         Bitmap Heap Scan pe raw_events_source_action_ts_idx (0001),
--         Filter: (raw ->> 'signature') !~~ 'SURICATA %'
--         51 348 de buffere (shared hit=422 read=50926)
--       cu signature (coloana + indexul ăsta)
--         Index Only Scan pe raw_events_suricata_sig_idx, Heap Fetches: 0
--         24 758 de buffere (shared hit=21492 read=3266)
--
-- Reducerea măsurată aici e de ~2,1×, mai mică decât raportul de ~66× citat
-- pentru interogarea izolată pe o tabelă de 200 000 de rânduri (0035). Diferența
-- vine din plan: pe replica asta, planificatorul alege deja `Bitmap Heap Scan`
-- prin `raw_events_source_action_ts_idx` — nu `Seq Scan` — pentru forma veche,
-- ceea ce reduce costul FĂRĂ Index Only Scan. Ce contează, verificat direct:
-- forma nouă e `Index Only Scan` cu `Heap Fetches: 0` pe toate partițiile din
-- fereastră, adică nu mai depinde de câte pagini are `raw_events` în total —
-- proprietatea pe care o cere toată seria 0030–0037, nu cifra absolută.
--
-- Replica are alt disc, alt cache și altă distribuție de date decât gazda —
-- avertismentul de la 0033 rămâne valabil: CIFRELE ABSOLUTE nu se transferă.
--
-- ## Corectitudinea: EXCEPT între forma veche și forma nouă
--
-- Rescrisă în `aggregate.ids_signatures` pe `signature` în loc de
-- `raw->>'signature'`, păstrând exact `NOT LIKE 'SURICATA %'`, gruparea pe
-- (semnătură, ip) și `LIMIT`-ul. Verificat pe replică, pe fereastra de 7 zile,
-- FĂRĂ `LIMIT` — comparând tot setul agregat, nu doar primele 6 rânduri:
--
--     SELECT * FROM (forma_veche) EXCEPT SELECT * FROM (forma_noua)  →  0 rânduri
--     SELECT * FROM (forma_noua) EXCEPT SELECT * FROM (forma_veche)  →  0 rânduri
--
-- Zero rânduri diferite în ambele sensuri, după ce backfill-ul din 0036 s-a
-- încheiat.
SET LOCAL statement_timeout = '10min';
SET LOCAL lock_timeout = '60s';

CREATE INDEX IF NOT EXISTS raw_events_suricata_sig_idx
    ON raw_events (ts DESC, signature)
    INCLUDE (src_ip)
    WHERE source = 'suricata';

COMMENT ON INDEX raw_events_suricata_sig_idx IS
    'Semnăturile suricata pe coloana reală, citite fără heap. Vezi aggregate.ids_signatures și 0035/0036.';

-- ## Garda: ce a rămas în catalog, la fel ca 0033/0034
--
-- Aceleași trei feluri de „succes" fals sub numele corect: predicat fără
-- `source = 'suricata'` (planul redevine dependent de heap), index fără
-- `INCLUDE (src_ip)` (numărătoarea de IP-uri distincte cere heap-ul), sau un
-- `CONCURRENTLY` întrerupt care lasă un index INVALID cu numele corect.
DO $$
DECLARE
    definitie text;
    e_bun     boolean;
BEGIN
    SELECT pg_get_indexdef(i.indexrelid), i.indisvalid AND i.indisready
      INTO definitie, e_bun
      FROM pg_index i
      JOIN pg_class ci ON ci.oid = i.indexrelid
      JOIN pg_class ct ON ct.oid = i.indrelid
     WHERE ci.relname = 'raw_events_suricata_sig_idx'
       AND ct.relname = 'raw_events';

    IF definitie IS NULL THEN
        RAISE EXCEPTION
            'raw_events_suricata_sig_idx nu există pe raw_events după CREATE INDEX';
    END IF;

    IF definitie !~ 'USING btree \(ts DESC, signature\) INCLUDE \(src_ip\)' THEN
        RAISE EXCEPTION
            'raw_events_suricata_sig_idx există, dar pe alte coloane: %', definitie;
    END IF;

    IF definitie !~ 'source = ''suricata''' THEN
        RAISE EXCEPTION
            'raw_events_suricata_sig_idx nu are source în predicat, deci Index Only Scan rămâne imposibil: %',
            definitie;
    END IF;

    IF NOT e_bun THEN
        RAISE EXCEPTION
            'raw_events_suricata_sig_idx există dar e INVALID — un CREATE INDEX CONCURRENTLY întrerupt. Ștergeți-l și reluați migrația.';
    END IF;
END $$;
