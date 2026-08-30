-- 0034_targeted_accounts_index: contul cel mai atacat, citit fără heap.
--
-- ## Ce a rămas nereparat de 0033
--
-- 0033 a scos panoul „Căi sondate" de sub volumul brut al lui `raw_events`.
-- Cardul „Conturi țintă" — `aggregate.targeted_accounts` — plătește exact
-- aceeași boală, cu alt filtru:
--
--     SELECT username, sum(n)::bigint AS n, count(ip) AS ips
--     FROM (SELECT username, host(src_ip) AS ip, count(*) AS n
--             FROM raw_events
--            WHERE source = 'sshd' AND action = 'auth_fail'
--              AND username IS NOT NULL
--              AND ts > now() - interval '7 days'
--            GROUP BY 1, 2) pereche
--     GROUP BY 1 ORDER BY n DESC LIMIT $1
--
-- Niciun index de pe `raw_events` acoperă `(source, action)` ȘI are `ts` în
-- frunte: `raw_events_source_idx` are ordinea inversă — `(source, action, ts
-- DESC)` — deci filtrează perechea repede, dar nu se poate mărgini pe
-- fereastra de 7 zile fără să parcurgă tot ce a strâns `sshd|auth_fail` de la
-- începutul retenției. Rândurile de `sshd` sunt și ele împrăștiate printre cele
-- de `auditd|command`, deci fiecare cere o pagină de heap pentru `username` și
-- `src_ip`.
--
-- Măsurat pe o replică locală, cu ACEEAȘI împrăștiere ca pe gazdă (14,0 rânduri
-- pe pagină, 68% `auditd|command`), 6 640 790 de rânduri în 11 partiții
-- zilnice:
--
--     targeted_accounts
--       înainte   227 406 de buffere
--       după        1 691 de buffere  (shared hit=187 read=1504)
--                 Index Only Scan, Heap Fetches: 0, pe toate cele 8 partiții
--                 din fereastra de 7 zile
--
-- Replica are alt disc și alt cache decât gazda, deci CIFRA ABSOLUTĂ nu se
-- transferă; ce se transferă e forma planului și raportul de reducere — de
-- ordinul a 130 de ori mai puține pagini.
--
-- ## Forma indexului
--
--     CREATE INDEX raw_events_authfail_idx ON raw_events (ts DESC, username)
--         INCLUDE (src_ip) WHERE source = 'sshd' AND action = 'auth_fail';
--
-- Același tipar ca `raw_events_probes_idx` din 0033, pe alte coloane:
--
--   * `source = 'sshd' AND action = 'auth_fail'` ÎN PREDICAT, nu doar ca
--     filtru — sunt cele două condiții de egalitate ale interogării, deci tot
--     ce implică predicatul nu se mai cere din heap;
--   * `ts` prima cheie, fiindcă fereastra e un INTERVAL și un B-tree se poate
--     mărgini la o porțiune contiguă doar pe prefix. Cu `ts` mai încolo,
--     retenția întreagă s-ar citi pentru o întrebare de 7 zile;
--   * `username` a doua cheie, fiindcă `IS NOT NULL` devine condiție de index,
--     nu filtru aplicat rând cu rând;
--   * `src_ip` doar `INCLUDE`: nu se filtrează niciodată pe el, doar se numără
--     adresele distincte prin perechea `(username, ip)` din subinterogare.
--
-- Mărimea, măsurată pe replică: sub 1 MB pentru 8 zile de date, adică sub
-- 4 MB pe retenția de 30. `raw_events_source_idx` (0001) rămâne neatins: alte
-- interogări îl folosesc pentru alte perechi `(source, action)`, iar el nu
-- poate acoperi asta oricum, din motivul de mai sus.
--
-- ## De ce nu CONCURRENTLY, și ridicarea timeout-urilor
--
-- Aceeași constrângere ca la 0019, 0030, 0031, 0033: `sentinel/db/migrate.py`
-- aplică fiecare fișier într-o singură tranzacție, iar PostgreSQL refuză
-- „CONCURRENTLY" într-una (25001). Index obișnuit, deci, cu lacăt `SHARE` pe
-- `raw_events` cât ține construcția — INSERT-urile ingestiei așteaptă, nu se
-- pierd, colectorii au cursoare proprii.
--
-- Timeout-urile urcă din același motiv și cu aceleași valori ca la 0031/0033:
-- `sentinel-tuning.conf` pune `statement_timeout = 60s` pe toată instanța, iar
-- o construcție pe un disc împărțit cu ingestia, Suricata și nginx poate trece
-- de atât. `SET LOCAL` fiindcă valoarea nu are voie să rămână agățată de
-- conexiune după ce tranzacția migrației se termină.
--
-- Cât ține construcția pe gazdă NU am putut măsura — ar fi însemnat s-o
-- construiesc acolo. Pe replică, sub 200 ms pentru toate cele 11 partiții.
SET LOCAL statement_timeout = '10min';
SET LOCAL lock_timeout = '60s';

CREATE INDEX IF NOT EXISTS raw_events_authfail_idx
    ON raw_events (ts DESC, username)
    INCLUDE (src_ip)
    WHERE source = 'sshd' AND action = 'auth_fail';

COMMENT ON INDEX raw_events_authfail_idx IS
    'Conturile cele mai atacate pe sshd, citite fără heap. Vezi aggregate.targeted_accounts.';

-- ## Garda: ce a rămas în catalog, nu ce s-a cerut
--
-- `IF NOT EXISTS` se uită DOAR LA NUME. Trei feluri de „succes" fals încap sub
-- numele ăsta, ca la 0033:
--
--   * un index cu numele corect dar fără `action = 'auth_fail'` în predicat —
--     ar acoperi toate eșecurile de-a lungul lui `sshd`, nu doar autentificarea,
--     și tot ar cere `username` din heap dacă ordinea cheilor s-a schimbat;
--   * un index fără `INCLUDE (src_ip)` — planul ar rămâne `Index Scan`, fiindcă
--     `src_ip` s-ar cere din heap;
--   * un „CONCURRENTLY" întrerupt, care lasă un index INVALID cu numele corect:
--     există în catalog, e scris la fiecare `auth_fail`, și nu-l folosește
--     nimeni.
--
-- Dintr-un cod de ieșire zero, toate trei arată la fel. Deci se citește
-- definiția.
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
     WHERE ci.relname = 'raw_events_authfail_idx'
       AND ct.relname = 'raw_events';

    IF definitie IS NULL THEN
        RAISE EXCEPTION
            'raw_events_authfail_idx nu există pe raw_events după CREATE INDEX';
    END IF;

    IF definitie !~ 'USING btree \(ts DESC, username\) INCLUDE \(src_ip\)' THEN
        RAISE EXCEPTION
            'raw_events_authfail_idx există, dar pe alte coloane: %', definitie;
    END IF;

    IF definitie !~ 'source = ''sshd''' THEN
        RAISE EXCEPTION
            'raw_events_authfail_idx nu are source în predicat: %', definitie;
    END IF;

    IF definitie !~ 'action = ''auth_fail''' THEN
        RAISE EXCEPTION
            'raw_events_authfail_idx nu e parțial pe auth_fail, deci ar indexa tot traficul sshd: %',
            definitie;
    END IF;

    IF NOT e_bun THEN
        RAISE EXCEPTION
            'raw_events_authfail_idx există dar e INVALID — un CREATE INDEX CONCURRENTLY întrerupt. Ștergeți-l și reluați migrația.';
    END IF;
END $$;
