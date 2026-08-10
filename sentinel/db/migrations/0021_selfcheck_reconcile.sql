-- 0021_selfcheck_reconcile: o constatare pe care nimeni n-o mai calculează.
--
-- ## Ce era stricat
--
-- `selfcheck_state` se scria prin upsert, cheie cu cheie, și nimic nu împăca
-- tabela cu ce emisese efectiv rularea. O verificare condiționată — una care
-- produce un rând doar cât timp condiția e adevărată — își păstra ultima stare
-- pentru totdeauna după ce înceta să mai fie emisă. Tranziția înapoi spre `ok`
-- nu o scria nimeni, fiindcă nimeni n-o mai calcula.
--
-- Măsurat pe producție, 10 august 2026:
--
--     selfcheck_runs   -> 317 rulări verzi consecutive, 33 verificări, 0 eșecuri
--     selfcheck_state  -> 34 rânduri; 33 atinse în ultimele 5 minute
--                         ingest:all | down | neatins de 1 zi și 2 ore
--
-- Pe 9 august la 07:00 toate sursele chiar au tăcut și `ingest:all` s-a scris.
-- La 08:25 și-au revenit, deci `check_ingest_sources` a încetat s-o mai emită —
-- iar botul i-a arătat operatorului „🔴 Sentinel nu funcționează complet" încă
-- 26 de ore, cu vechimea rândului blocat prezentată drept durata unei pene.
--
-- ## Ce se schimbă
--
-- Runner-ul reconciliază acum tabela după fiecare rulare: cheile pe care rularea
-- nu le-a emis nu mai sunt constatări, sunt resturi. Coloana de aici acoperă
-- singurul caz în care un rest NU are voie să fie șters.
--
-- ## De ce o coloană și nu doar un DELETE
--
-- O cheie poate lipsi dintr-o rulare din două motive care nu seamănă deloc:
--
--   1. verificarea s-a uitat și n-a avut ce raporta — condiția a dispărut;
--   2. grupul de verificări a crăpat înainte s-o ajungă.
--
-- În al doilea caz ștergerea ar transforma o verificare stricată într-un buletin
-- de sănătate curat. Deci o rulare incompletă nu șterge nimic: marchează
-- rândurile neatinse cu `stale = true`, iar interfața le arată ca „neevaluate la
-- ultima rulare", cu vechimea prezentată explicit ca vechimea CONSTATĂRII, nu ca
-- durata unei pene. „Nu se știe" și „e bine" sunt stări diferite, iar a le
-- confunda e exact felul în care un instrument de monitorizare minte.
--
-- Prima rulare completă de după reparație curăță ce a rămas.
--
-- ## De ce nu se atinge niciun rând existent
--
-- `DEFAULT false` înseamnă că tot ce e în tabelă azi rămâne exact cum e, marcat
-- ca evaluat. Rândul blocat `ingest:all` nu se șterge aici: îl șterge prima
-- rulare completă de după instalare, adică codul care a fost testat, nu o
-- migrație care ar face-o o singură dată și fără martori.

ALTER TABLE selfcheck_state
    ADD COLUMN IF NOT EXISTS stale boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN selfcheck_state.stale IS
    'true = rândul a supraviețuit unei rulări INCOMPLETE care nu l-a reevaluat. '
    'Ultima constatare cunoscută, nu starea de acum. O rulare completă fie '
    'rescrie rândul (stale=false), fie îl șterge.';

COMMENT ON TABLE selfcheck_state IS
    'Ultimul rezultat per verificare, reconciliat după fiecare rulare completă: '
    'cheile pe care rularea nu le-a emis se șterg. Rândurile se compară, nu se '
    'acumulează.';
