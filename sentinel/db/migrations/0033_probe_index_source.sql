-- 0033_probe_index_source: indexul sondărilor 404 primește `source` în predicat,
-- ca panoul „Căi sondate" să nu mai atingă heap-ul.
--
-- ## Ce s-a măsurat, și de ce ăsta e defectul
--
-- Pe gazdă, panoul principal cade de 2–6 ori pe oră, în fiecare oră, cu
-- «datele paginii au eșuat după 47,0 s: canceling statement due to statement
-- timeout». Selfcheck-ul încarcă pagina la 5 minute, deci ~3 din 12 încărcări
-- pică — inclusiv la 4 dimineața, când nimeni nu atinge gazda.
--
-- Cauza e cea din 0030, netratată până la capăt: `raw_events_20260824` are
-- 5 640 790 de rânduri / 2967 MB, din care 3 835 932 sunt `auditd|command`
-- rămase de la deploy-urile vechi. Rândurile care interesează panourile sunt
-- împrăștiate printre ele, câte una la ~15 rânduri, adică una pe pagină de
-- heap. Orice panou care trebuie să citească heap-ul plătește o pagină pe
-- rând, iar costul lui crește cu volumul BRUT al partiției, nu cu volumul
-- propriu.
--
-- 0030 a scos `by_country`, `by_asn`, `top_attackers` și `hourly_activity` de
-- sub asta, cu indecși acoperitori. `raw_events_notfound_idx` de acolo NU a
-- reușit același lucru pentru `probed_paths` și `_probe_campaign_insights`, și
-- motivul e o singură coloană:
--
--     CREATE INDEX raw_events_notfound_idx
--         ON raw_events (ts DESC, http_path) INCLUDE (src_ip)
--         WHERE http_status = 404;
--
-- Amândouă interogările filtrează `source = 'nginx' AND http_status = 404`.
-- Predicatul indexului acoperă a doua condiție, deci planificatorul n-o mai
-- cere; prima nu e nici cheie, nici `INCLUDE`, nici implicată de predicat, deci
-- `source` trebuie citit din heap PENTRU FIECARE RÂND. Planul o spune pe față:
-- `Index Scan`, cu `Filter: (source = 'nginx')` — nu `Index Only Scan`.
--
-- Măsurat pe replică (mai jos): 53 375 de accese la buffere pentru 55 674 de
-- rânduri de 404. Aproape un buffer pe rând, adică exact boala pe care 0030 o
-- vindecase în altă parte.
--
-- ## Ce se adaugă
--
-- `raw_events_probes_idx` — același corp, cu `source = 'nginx'` mutat ÎN
-- PREDICAT. Atât. Cu el, tot ce cer cele două interogări — `http_path`,
-- `src_ip`, marginea de timp — stă în index, iar restul filtrelor sunt
-- implicate de predicat. Planul devine `Index Only Scan` cu `Heap Fetches: 0`.
--
-- Ordinea cheilor rămâne cea din 0030, `(ts DESC, http_path)`: pe `ts` se
-- filtrează cu INTERVAL, deci vrem coborârea la marginea ferestrei, iar
-- retenția e de 30 de zile pentru o fereastră de 7 — restul indexului nici nu
-- se citește. `http_path` a doua fiindcă `IS NOT NULL` devine astfel condiție
-- de index, nu filtru. `src_ip` rămâne `INCLUDE`: nu se filtrează pe el
-- niciodată, doar se numără adresele distincte.
--
-- ## Ce s-a măsurat cu el, și unde
--
-- Nu pe gazdă — indexul nu există încă acolo. Pe o replică locală
-- (PostgreSQL 16.4, `shared_buffers = 256MB`, `work_mem = 8MB`,
-- `maintenance_work_mem = 64MB`, `random_page_cost = 1.2`, adică valorile din
-- `deploy/postgres/sentinel-tuning.conf`), cu 6 640 790 de rânduri în 11
-- partiții zilnice, dintre care una de 5 640 790 de rânduri / 3148 MB
-- construită cu ACEEAȘI ÎMPRĂȘTIERE ca pe gazdă (14,0 rânduri pe pagină față
-- de 14,9; 68% `auditd|command`, 4,8% `suricata`, 7,4% `nginx`):
--
--     probed_paths
--       înainte   53 375 de buffere, 317,6 ms
--                 Index Scan using raw_events_..._ts_http_path_src_ip_idx
--                   Filter: (source = 'nginx')
--       după         484 de buffere,  67,2 ms
--                 Index Only Scan using raw_events_..._ts_http_path_src_ip_idx1
--                   Heap Fetches: 0
--
--     _probe_campaign_insights — același plan, aceeași trecere la
--                 `Index Only Scan`, `Heap Fetches: 0`.
--
-- Aceleași 55 674 de rânduri de 404 și aceleași 20 de căi în amândouă.
--
-- Replica are alt disc și alt cache decât gazda, deci CIFRELE ABSOLUTE nu se
-- transferă; ce se transferă e forma planului, `Heap Fetches: 0`, și numărul de
-- pagini atinse — 110 ori mai puține. Și proprietatea care contează mai mult
-- decât raportul: după schimbare, costul panoului nu mai depinde de câte
-- rânduri de `auditd` are partiția.
--
-- Marimea indexului, măsurată pe replică: 3408 kB pentru 11 zile, adică
-- ~9 MB pe retenția de 30 de zile. `raw_events_notfound_idx`, pe aceleași
-- date, avea 3400 kB — practic identic, fiindcă amândoi indexează aceleași
-- rânduri; singura diferență e ce scrie în predicat.
--
-- ## De ce dispare `raw_events_notfound_idx`
--
-- Fiindcă indexează exact aceleași rânduri, servește exact aceiași trei
-- consumatori (`aggregate.probed_paths`, `insights._probe_campaign_insights`,
-- `detect.rules.web_enumeration`) și îi servește mai prost. Lăsat pe loc, n-ar
-- aduce niciun plan mai bun, dar s-ar scrie la fiecare 404 care intră. Chiar
-- 0030 spune regula: „un index care nu schimbă nimic dar se scrie la fiecare
-- INSERT e cost curat".
--
-- `web_enumeration` nu regresează: subinterogarea lui pornește de la
-- `id > $1`, iar `id` nu e cheie în niciunul dintre cei doi indecși, deci
-- niciunul nu-i servea marginea. Restul interogării filtrează tot
-- `source = 'nginx'`, deci indexul nou i se aplică oriunde i se aplica cel
-- vechi.
--
-- Ștergerea vine DUPĂ garda care verifică indexul nou. Dacă `CREATE INDEX`
-- pică, tranzacția se derulează înapoi și indexul vechi rămâne exact unde era.
--
-- ## Ce NU e aici: `ids_signatures`
--
-- Al doilea panou scump al paginii — semnăturile Suricata — rămâne neatins, și
-- nu din scăpare. Pe replică, `ids_signatures` costă 233 187 de buffere pentru
-- 301 868 de rânduri de suricata (pe gazdă: 249 378 pentru 273 595, același
-- raport). Niciun index nu-l repară, fiindcă `signature` stă în `raw`, iar
-- cheia utilă e o EXPRESIE.
--
-- S-a construit indexul de expresie și s-a măsurat. PostgreSQL 16.4 nu poate
-- întoarce valoarea unei coloane-expresie dintr-un index: `check_index_only`
-- ignoră expresiile, deci `raw` rămâne un atribut cerut din heap. Dovada, pe o
-- tabelă de 200 000 de rânduri unde indexul de expresie era SINGURUL posibil,
-- cu `enable_seqscan` și `enable_bitmapscan` stinse și tabela proaspăt
-- vacuumată:
--
--     index pe (raw->>'signature')   Index Scan,      13 264 de buffere
--     coloană reală                  Index Only Scan,    175 de buffere
--
-- Pe `raw_events`, cu indexul de expresie prezent, planificatorul nici măcar
-- nu-l alege: rămâne pe `raw_events_..._source_action_ts_idx` și citește
-- aceleași 233 187 de buffere. Deci nu se adaugă.
--
-- Ce ar rezolva panoul ăla e o COLOANĂ reală pentru semnătură, iar felul în
-- care ajunge acolo e o decizie a operatorului, nu un detaliu de
-- implementare — amândouă căile costă ceva real, măsurat pe aceeași replică:
--
--   * coloană GENERATED ... STORED: `ALTER TABLE` a durat 89,9 s cu
--     `ACCESS EXCLUSIVE` pe toată tabela (deci și panoul, și detecția, și
--     ingestia stau), a generat 4769 MB de WAL și cere spațiu liber cât o a
--     doua copie a lui `raw_events` cu tot cu indecși (~4,9 GB pe replică).
--     În schimb, garanția e a motorului și nu există cod de scris.
--
--   * coloană simplă + declanșator BEFORE INSERT + backfill: `ADD COLUMN` e
--     de 1,7 ms, backfill-ul a durat 29,4 s sub `ROW EXCLUSIVE` (deci panoul
--     rămâne viu), 3596 MB de WAL, ~129 MB de balonare rămasă. Costul
--     permanent e pe calea cea mai fierbinte: +14,5% la INSERT, măsurat pe
--     300 000 de rânduri (1296 ms → 1484 ms).
--
-- Cu oricare dintre ele, indexul acoperitor măsurat e de 27 MB, iar
-- `ids_signatures` trece de la 233 187 de buffere la 3536, cu `Heap Fetches:
-- 0` și exact aceleași cifre în panou (verificat cu `EXCEPT`: zero rânduri
-- diferite).
--
-- Cât spațiu liber are gazda NU am putut citi, iar `sentinel_disk_guard` taie
-- partiții sub 15% liber — de-asta varianta cu rescriere nu se pornește de
-- aici fără ca operatorul să spună da.
--
-- ## De ce nu CONCURRENTLY
--
-- `sentinel/db/migrate.py` aplică fiecare fișier într-o singură tranzacție, iar
-- PostgreSQL refuză „CONCURRENTLY" într-una (25001) — aceeași constrângere ca
-- la 0019, 0030 și 0031. Deci index obișnuit, cu lacăt `SHARE` pe `raw_events`
-- cât ține construcția, plus `ACCESS EXCLUSIVE` pentru o clipă la ștergerea
-- celui vechi. INSERT-urile ingestiei așteaptă în intervalul ăla; nu se pierd
-- evenimente, colectorii au cursoare proprii.
--
-- Cât ține construcția pe gazdă NU am putut măsura — ar fi însemnat s-o
-- construiesc acolo. Pe replică au fost 1,6 s pentru toate cele 11 partiții,
-- pe indexul cel mai mic din tabelă. Discul gazdei e împărțit cu ingestia, cu
-- Suricata și cu nginx, deci așteaptă-te la ordinul zecilor de secunde.
--
-- Timeout-urile urcă din același motiv ca la 0031, cu aceleași valori și
-- același `LOCAL`: `deploy/postgres/sentinel-tuning.conf` pune
-- `statement_timeout = 60s` pe toată instanța, iar `migrate.py` se conectează
-- fără să-l schimbe; o construcție omorâtă la 60 s ar derula migrația înapoi
-- și ar opri schema aici. `lock_timeout` urcă la 60 s fiindcă, cât stă
-- construcția la coadă după lacăt, fiecare INSERT care sosește se așază în
-- spatele ei — mărginit, deci: ori ia lacătul în primul minut, ori se retrage
-- și reia operatorul.
SET LOCAL statement_timeout = '10min';
SET LOCAL lock_timeout = '60s';

CREATE INDEX IF NOT EXISTS raw_events_probes_idx
    ON raw_events (ts DESC, http_path)
    INCLUDE (src_ip)
    WHERE source = 'nginx' AND http_status = 404;

COMMENT ON INDEX raw_events_probes_idx IS
    'Sondările 404 ale nginx, citite fără heap. source e în PREDICAT anume: fără el, Index Only Scan e imposibil. Vezi aggregate.probed_paths.';

-- ## Garda: ce a rămas în catalog, nu ce s-a cerut
--
-- `IF NOT EXISTS` e acolo din motivul de la 0031: dacă indexul a fost construit
-- de mână cu „CONCURRENTLY", în afara oricărei tranzacții, varianta simplă ar
-- pica cu «relation already exists» și ar opri schema definitiv aici.
--
-- Dar `IF NOT EXISTS` se uită DOAR LA NUME, iar trei feluri de „succes" fals
-- încap sub numele ăsta:
--
--   * un index cu numele corect dar cu predicatul lui 0030, adică fără
--     `source` — exact defectul pe care îl repară migrația, binecuvântat;
--   * un index fără `INCLUDE (src_ip)` — planul ar rămâne `Index Scan`, fiindcă
--     `src_ip` s-ar cere din heap;
--   * un „CONCURRENTLY" întrerupt, care lasă un index INVALID cu numele corect:
--     există în catalog, e scris la fiecare INSERT, și nu-l folosește nimeni.
--
-- Din codul de ieșire zero, toate trei arată la fel. Deci se citește definiția.
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
     WHERE ci.relname = 'raw_events_probes_idx'
       AND ct.relname = 'raw_events';

    IF definitie IS NULL THEN
        RAISE EXCEPTION
            'raw_events_probes_idx nu există pe raw_events după CREATE INDEX';
    END IF;

    IF definitie !~ 'USING btree \(ts DESC, http_path\) INCLUDE \(src_ip\)' THEN
        RAISE EXCEPTION
            'raw_events_probes_idx există, dar pe alte coloane: %', definitie;
    END IF;

    IF definitie !~ 'source = ''nginx''' THEN
        RAISE EXCEPTION
            'raw_events_probes_idx nu are source în predicat, deci Index Only Scan rămâne imposibil: %',
            definitie;
    END IF;

    IF definitie !~ 'http_status = 404' THEN
        RAISE EXCEPTION
            'raw_events_probes_idx nu e parțial pe 404, deci ar indexa toate cererile nginx: %',
            definitie;
    END IF;

    IF NOT e_bun THEN
        RAISE EXCEPTION
            'raw_events_probes_idx există dar e INVALID — un CREATE INDEX CONCURRENTLY întrerupt. Ștergeți-l și reluați migrația.';
    END IF;
END $$;

DROP INDEX IF EXISTS raw_events_notfound_idx;

-- `DROP INDEX IF EXISTS` întoarce succes și când n-a șters nimic. Dacă cineva a
-- redenumit indexul vechi, el ar rămâne pe loc, scris la fiecare 404, iar
-- migrația ar raporta „gata". Deci se verifică EFECTUL: pe `raw_events` nu mai
-- are voie să existe niciun index parțial pe 404 în afară de cel nou.
DO $$
DECLARE
    ramase text;
BEGIN
    SELECT string_agg(ci.relname || ' => ' || pg_get_indexdef(i.indexrelid), '; ')
      INTO ramase
      FROM pg_index i
      JOIN pg_class ci ON ci.oid = i.indexrelid
      JOIN pg_class ct ON ct.oid = i.indrelid
     WHERE ct.relname = 'raw_events'
       AND ci.relname <> 'raw_events_probes_idx'
       AND pg_get_indexdef(i.indexrelid) ~ 'http_status = 404';

    IF ramase IS NOT NULL THEN
        RAISE EXCEPTION
            'a rămas un al doilea index parțial pe 404, scris la fiecare cerere fără să aducă vreun plan mai bun: %',
            ramase;
    END IF;
END $$;
