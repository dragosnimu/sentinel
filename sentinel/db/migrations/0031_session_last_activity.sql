-- 0031_session_last_activity: ultima comandă a UNEI sesiuni, luată din index.
--
-- ## Ce s-a măsurat, pe gazdă, 28 august 2026
--
-- Panoul a picat de șase ori în șapte ore, cu «🔴 SENTINEL NU FUNCȚIONEAZĂ
-- COMPLET / datele paginii au eșuat după 46,1 s: canceling statement due to
-- statement timeout». În jurnalul PostgreSQL (`log_min_duration_statement =
-- 2000`) cele mai lente instrucțiuni ale zilei au fost 37 856, 26 218, 26 181,
-- 24 347, 24 067 și 22 072 ms, plus una oprită de `statement_timeout` la 60 s.
-- Toate, aceeași instrucțiune — măturătoarea de sesiuni din
-- `close_stale_sessions` (`sentinel/db/repo/logins.py`):
--
--     UPDATE login_sessions s
--        SET closed_at = COALESCE(
--                (SELECT max(ts) FROM session_commands c
--                  WHERE c.session_id = s.id),
--                s.opened_at), ...
--
-- Volumele spun de unde vine munca: `session_commands` are 2 983 178 de rânduri
-- și 661 MB, `login_sessions` are 341. Deci nu din câte sesiuni sunt, ci din cât
-- costă UN `max(ts)` pentru o sesiune. Planul cerut pe gazdă:
--
--     Result  (cost=134.71..134.72 rows=1 width=8)
--       InitPlan 1 (returns $0)
--         ->  Limit  (cost=0.43..134.71 rows=1 width=8)
--               ->  Index Scan using session_commands_ts_idx on session_commands c
--                     (cost=0.43..127834.86 rows=952 width=8)
--                     Index Cond: (ts IS NOT NULL)
--                     Filter: (session_id = 12345)
--
-- Planificatorul rescrie `max(ts)` în «primul rând, coborând pe `ts DESC`», iar
-- singurul index care are `ts` în față e `session_commands_ts_idx (ts DESC)` —
-- al ÎNTREGII tabele. Așa că trece prin comenzile TUTUROR sesiunilor și aruncă,
-- una câte una, rândurile care nu-s ale sesiunii cerute: `session_id = 12345`
-- apare ca `Filter`, nu ca `Index Cond`.
--
-- `Limit` oprește căutarea la primul rând potrivit, deci 134,71 e costul unei
-- sesiuni cu activitate RECENTĂ. Pentru o sesiune fără nicio comandă, sau a
-- cărei ultimă comandă e mai veche decât tot ce s-a scris de atunci, nu există
-- rând potrivit și se parcurge TOT indexul — costul complet, 127 834.
--
-- Și exact alea sunt sesiunile pe care le caută măturătoarea: ea selectează
-- sesiunile fără activitate de peste `STALE_SESSION_H` ore. Cazul cel mai
-- scump nu e o excepție, e populația-țintă. Se repetă la fiecare trecere a
-- daemonului de detecție — `INTERVAL_S = 10` în
-- `sentinel/services/detect_service.py` — și de două ori per sesiune, fiindcă
-- același subselect e scris și în `WHERE`, și în `SET`.
--
-- De ce se vede ca o cădere a PANOULUI, deși vinovatul e măturătoarea: 661 MB
-- citiți în buclă prin `shared_buffers` de 256 MB scot din cache tocmai
-- paginile de care are nevoie pagina, iar discul e împărțit cu ingestia.
--
-- ## De ce ordinea (session_id, ts DESC)
--
-- `session_id` prima fiindcă pe ea se filtrează cu EGALITATE. Un B-tree se
-- poate mărgini la o porțiune contiguă doar pe prefixul de coloane pentru care
-- are o valoare; cu `ts` prima, `session_id` nu poate fi decât un filtru aplicat
-- după citire — adică fix planul de mai sus. Cu `session_id` prima, `max(ts)`
-- devine o coborâre la marginea unei singure sesiuni.
--
-- Direcția `DESC` a coloanei a doua NU e ce face reparația: un B-tree se poate
-- parcurge și invers, deci `(session_id, ts)` ar servi `max(ts)` la fel de bine.
-- E scrisă `DESC` fiindcă restul tabelei folosește deja convenția asta
-- (`session_commands_ts_idx`, `session_commands_user_idx`) și fiindcă «ultimele
-- comenzi ale sesiunii X» iese din ea fără sortare.
--
-- ## De ce `session_commands_session_idx (session_id, id)` NU rezolvă
--
-- Fiindcă `id` și `ts` nu sunt aceeași ordine, iar planificatorul nu are cum să
-- deducă una din alta — nu există nicio dependență funcțională între ele, și
-- nici n-ar fi adevărată. Docstring-ul din `sentinel/db/repo/logins.py` spune de
-- ce: ordinea în care sosesc înregistrările nu e garantată. O comandă poate fi
-- scrisă înaintea logării care a produs-o, orfanele se leagă mai târziu, iar
-- `id` e ordinea INSERT-ului, nu a faptei. „Ultimul `id`" și „cel mai mare `ts`"
-- sunt două rânduri diferite, și nimic din schemă nu promite altceva.
--
-- Practic, cu indexul ăla `max(ts)` ar cere citirea TUTUROR rândurilor sesiunii,
-- iar `ts` nici măcar nu e în el — deci un acces la heap pentru fiecare rând.
-- Pentru sesiunea de deploy din 0028, cu 558 079 de comenzi, ar fi mai rău decât
-- ce se întâmplă azi.
--
-- Indexul vechi rămâne neatins: `session_commands WHERE session_id = $1 ORDER BY
-- id` și `DISTINCT ON (session_id) ... ORDER BY session_id, id` din
-- `_promote_interactive` merg pe `id`, nu pe `ts`, și el le servește.
--
-- ## Ce s-a măsurat cu el, și unde
--
-- Nu pe gazdă: indexul nu există încă acolo. Pe o replică locală (PostgreSQL
-- 16.4, aceiași `shared_buffers = 256MB`, `work_mem = 8MB`,
-- `maintenance_work_mem = 64MB`, `statement_timeout = 60s`), cu 3 000 050 de
-- comenzi / 868 MB, exact cei cinci indecși de pe gazdă, și 341 de sesiuni din
-- care 20 deschise fără activitate recentă:
--
--     max(ts) pentru O sesiune deschisă fără comenzi
--       înainte   20 280,980 ms, 3 002 879 pagini citite
--                 Index Scan using session_commands_ts_idx
--                   Index Cond: (ts IS NOT NULL)
--                   Filter: (session_id = 5)
--                   Rows Removed by Filter: 3000050
--       după           0,089 ms, 6 pagini
--                 Index Only Scan using session_commands_session_ts_idx
--                   Index Cond: ((session_id = 5) AND (ts IS NOT NULL))
--                   Heap Fetches: 0
--
--     UPDATE-ul întreg, `EXPLAIN (ANALYZE)` derulat înapoi
--       înainte  456 562,035 ms, ~80 de milioane de pagini atinse
--       după           4,342 ms, 282 de pagini
--       aceleași 10 rânduri actualizate în amândouă
--
-- Planul de dinainte e identic ca formă cu cel de pe gazdă: `Index Cond` doar
-- pe `ts IS NOT NULL`, `session_id` rămas `Filter`. Replica are NVMe și alt
-- cache, deci CIFRELE ABSOLUTE nu se transferă; ce se transferă e forma
-- planului și numărul de pagini atinse.
--
-- ## Lacătul, și de ce migrația își ridică singură timeout-urile
--
-- `CREATE INDEX CONCURRENTLY` nu poate rula într-o tranzacție, iar
-- `sentinel/db/migrate.py` aplică fiecare fișier în exact una — aceeași
-- constrângere ca la 0019 și 0030. Deci index obișnuit, cu lacăt `SHARE` pe
-- `session_commands` cât ține construcția. `SHARE` intră în conflict cu `ROW
-- EXCLUSIVE`, deci INSERT-urile ingestiei AȘTEAPTĂ. Nu se pierd evenimente —
-- colectorii au cursoare proprii — dar în intervalul ăla nu intră nimic în
-- tabelă, iar o pasă de ingestie care așteaptă prea mult e omorâtă de propriul
-- `statement_timeout` și se reia la următoarea.
--
-- Ce NU se poate presupune e că se termină în 60 de secunde.
-- `deploy/postgres/sentinel-tuning.conf` pune `statement_timeout = 60s` pe toată
-- instanța, iar `migrate.py` se conectează fără să-l schimbe. O construcție pe
-- 661 MB cu `maintenance_work_mem = 64MB` sortează 3 milioane de rânduri pe
-- disc; dacă trece de 60 s e OMORÂTĂ, migrația se derulează înapoi, și schema se
-- oprește aici. De-asta `SET LOCAL` — `LOCAL`, deci valoarea moare odată cu
-- tranzacția și nu rămâne agățată de conexiune.
--
-- Zece minute, nu zero: dacă chiar durează atât, ceva e în neregulă, și e mai
-- bine să se retragă decât să țină ingestia blocată la nesfârșit.
--
-- Ridicarea NU repară un eșec observat: pe replica de mai sus construcția a
-- durat **1,27 s** și a trecut și fără ea, sub același `statement_timeout` de
-- 60 s. E o margine, și una care costă zero când construcția e rapidă — discul
-- gazdei e împărțit cu ingestia, cu Suricata și cu nginx, iar azi a produs
-- instrucțiuni de 20–38 s. **Cât durează pe gazdă nu am putut măsura**:
-- singurul fel în care aș fi aflat ar fi fost s-o construiesc acolo.
--
-- `lock_timeout` urcă de la 10 s la 60 s din motivul opus: cât timp construcția
-- stă la coadă după lacăt, orice INSERT care sosește se așază ÎN SPATELE EI.
-- Prea mic, migrația pică din cauza unui lot de ingestie perfect normal; zero,
-- coada crește la nesfârșit. Mărginit, deci: ori ia lacătul în primul minut, ori
-- se retrage și reia operatorul.
SET LOCAL statement_timeout = '10min';
SET LOCAL lock_timeout = '60s';

CREATE INDEX IF NOT EXISTS session_commands_session_ts_idx
    ON session_commands (session_id, ts DESC);

COMMENT ON INDEX session_commands_session_ts_idx IS
    'Ultima activitate a unei sesiuni, dintr-o singură coborâre. Vezi close_stale_sessions.';

-- ## De ce `IF NOT EXISTS`, și de ce nu e de ajuns
--
-- Dacă indexul a fost făcut de mână înainte — `CREATE INDEX CONCURRENTLY`, în
-- afara oricărei tranzacții, e chiar calea pe care ar alege-o cineva care nu
-- vrea să blocheze ingestia deloc — atunci varianta simplă ar pica cu «relation
-- already exists», ar derula migrația înapoi, și schema s-ar opri definitiv
-- aici.
--
-- Dar `IF NOT EXISTS` se uită DOAR LA NUME. Două feluri în care ar raporta
-- succes fără să fi făcut nimic:
--
--   * un index cu numele ăsta pe alte coloane — planificatorul rămâne pe
--     `session_commands_ts_idx`, iar panoul continuă să pice exact la fel;
--   * un `CREATE INDEX CONCURRENTLY` întrerupt lasă în urmă un index INVALID cu
--     numele corect. Există în catalog, e scris la fiecare INSERT, și nu e
--     folosit de nimeni.
--
-- Dintr-un cod de ieșire zero, amândouă arată ca «gata». Deci se citește ce a
-- rămas în catalog, nu ce s-a cerut.
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
     WHERE ci.relname = 'session_commands_session_ts_idx'
       AND ct.relname = 'session_commands';

    IF definitie IS NULL THEN
        RAISE EXCEPTION
            'session_commands_session_ts_idx nu există pe session_commands după CREATE INDEX';
    END IF;

    IF definitie !~ 'USING btree \(session_id, ts DESC\)' THEN
        RAISE EXCEPTION
            'session_commands_session_ts_idx există, dar pe alte coloane: %', definitie;
    END IF;

    IF NOT e_bun THEN
        RAISE EXCEPTION
            'session_commands_session_ts_idx există dar e INVALID — un CREATE INDEX CONCURRENTLY întrerupt. Ștergeți-l și reluați migrația.';
    END IF;
END $$;
