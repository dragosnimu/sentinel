-- 0029_scans_no_skipped: `skipped` iese din constrângere, nu se învață de citit.
--
-- ## Eșecul, citit din cod — nu văzut pe gazdă
--
-- `check_last_scan` tratează orice status care nu e `running`, `failed` sau
-- `timeout` ca pe o rulare încheiată, deci un rând `skipped` ar fi ieșit «ok |
-- ultima rulare încheiată acum 1h, 0 constatări». „0 constatări" despre o scanare
-- care NU A RULAT e chiar forma de minciună pe care verificarea aia există ca s-o
-- prevină — un panou verde peste o măsurătoare care nu s-a făcut niciodată.
--
-- Pe gazdă nu s-a întâmplat și nu se pretinde că s-a întâmplat: acolo sunt 0
-- rânduri `skipped` (vezi mai jos). E o cale deschisă, nu o pană trăită — iar
-- deosebirea contează, fiindcă aici comentariul e evidența.
--
-- ## De ce se scoate în loc să se trateze
--
-- Nimic nu-l scrie: `finish_scan` (`sentinel/db/repo/findings.py`) scrie doar
-- `completed`, `failed` sau `timeout`, iar `start_scan` scrie `running`. Pe gazda
-- operatorului sunt 0 rânduri `skipped` (30 completed, 4 failed, 0 running,
-- măsurat pe 26 august 2026). Deci valoarea nu descrie nimic real — e o capcană
-- armată pentru primul cod care o va scrie, fiindcă nimic n-o citește corect.
--
-- A face o stare NEREPREZENTABILĂ e mai puternic decât a o gestiona: gestionată,
-- corectitudinea depinde de fiecare cititor viitor; scoasă, baza refuză. Dacă
-- mâine e nevoie de conceptul „scanner sărit", se adaugă deliberat — împreună cu
-- logica ce-l raportează onest, nu ca măsurătoare cu zero constatări.
--
-- ## De ce REFUZĂ în loc să convertească
--
-- O conversie tăcută (`skipped` -> `completed`) ar REscrie istoric: o rulare care
-- n-a măsurat nimic ar deveni, în tabelă, una care a măsurat și n-a găsit nimic.
-- Adică fix afirmația falsă din care a pornit migrația, doar că împietrită în
-- date în loc să fie produsă la citire. Iar o ștergere ar pierde faptul că ceva a
-- scris valoarea aia — informația cea mai valoroasă din tot cazul.
--
-- Pe gazda operatorului blocul de mai jos e operație nulă. Dacă se declanșează
-- vreodată pe altă instanță, aia NU e un obstacol: e singura dovadă că un
-- scriitor necunoscut există, și merită oprit deploy-ul până e găsit.

-- 1. Refuzul. Zgomotos, cu numărul de rânduri și cu ce are de făcut operatorul.
DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM scans WHERE status = 'skipped';
    IF n > 0 THEN
        RAISE EXCEPTION
            '0029_scans_no_skipped: % rând(uri) din `scans` au status ''skipped'', iar migrația NU le convertește', n
            USING
            DETAIL = 'O conversie tăcută ar rescrie istoric: o rulare care n-a măsurat nimic ar deveni una care a măsurat și n-a găsit nimic. Migrația refuză tocmai ca să nu facă asta în locul tău.',
            HINT = 'Uită-te la ele: SELECT id, scanner, target, started_at, finished_at, findings_count, error FROM scans WHERE status = ''skipped'' ORDER BY started_at; Apoi, pentru FIECARE rând, decide tu: dacă rularea chiar s-a încheiat cu rezultate, UPDATE scans SET status = ''completed'' WHERE id = ...; dacă n-a rulat niciodată, DELETE FROM scans WHERE id = ...; . Și află CINE a scris valoarea — `finish_scan` din sentinel/db/repo/findings.py nu o scrie, deci există un scriitor necunoscut.';
    END IF;
END $$;

-- 2. Constrângerea. Numele `scans_status_check` e cel pe care Postgres l-a dat
--    singur constrângerii de coloană din 0003 (`<tabelă>_<coloană>_check`);
--    `IF EXISTS` ca migrația să treacă și pe o bază unde a fost redenumită, iar
--    `ADD CONSTRAINT` cu nume explicit ca de acum înainte să nu mai depindă de o
--    convenție.
--
--    Dacă presupunerea despre nume e greșită, `skipped` tot iese din tabelă:
--    restricțiile CHECK ale unei tabele se CONJUGĂ, deci cea strictă adăugată
--    aici respinge valoarea chiar dacă cea permisivă din 0003 rămâne în picioare
--    sub alt nume. Ce rămâne stricat atunci e catalogul: două constrângeri care
--    spun lucruri diferite, iar un `DROP CONSTRAINT scans_status_check` de mâine
--    — scris de cineva care crede că e singura — ar redeschide `skipped` fără o
--    vorbă. Pasul 3 NU deosebește cazul ăsta de cel bun; ce-l deosebește e
--    catalogul, cu interogarea din HINT-ul de acolo.
ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_status_check;
ALTER TABLE scans ADD CONSTRAINT scans_status_check
    CHECK (status IN ('running','completed','failed','timeout'));

COMMENT ON COLUMN scans.status IS
    'running (deschis de start_scan) | completed | failed | timeout (scrise de finish_scan). `skipped` a fost scos în 0029: nimic nu-l scria și nimic nu-l citea onest.';

-- 3. Dovada efectului, nu a intenției.
--
--    Un `ALTER TABLE` care întoarce succes nu e dovadă că baza respinge acum
--    valoarea: spune doar că instrucțiunea a fost acceptată. O listă scrisă
--    greșit la pasul 2 — `skipped` rămas printre valori, sau o literă în plus la
--    alta — se încheie tot cu succes, și abia la prima scriere s-ar afla.
--    Singura dovadă e că baza chiar refuză valoarea, deci se încearcă o inserare,
--    iar dacă REUȘEȘTE, migrația se rupe.
--
--    Ce NU dovedește proba: că `DROP ... IF EXISTS` a găsit ceva. Dacă n-a găsit,
--    cea permisivă din 0003 rămâne, se conjugă cu cea strictă, iar proba e
--    respinsă la fel — vezi pasul 2 pentru ce se strică atunci.
--
--    Subtranzacția blocului anulează inserarea de probă pe ambele ramuri, deci nu
--    rămâne niciun rând. `bigserial` nu se derulează înapoi, deci se pierde un id
--    din secvență — nimic nu depinde de ids consecutive în `scans`.
--
--    `RAISE EXCEPTION` are SQLSTATE P0001, care NU e prins de `WHEN
--    check_violation`, deci ramura de eșec chiar rupe migrația.
DO $$
BEGIN
    BEGIN
        INSERT INTO scans (scanner, target, status)
        VALUES ('__proba_0029__', '__proba_0029__', 'skipped');
        RAISE EXCEPTION
            '0029_scans_no_skipped: baza a ACCEPTAT status ''skipped'' după rescrierea constrângerii'
            USING
            DETAIL = 'Constrângerea permisivă din 0003 e probabil încă în picioare sub alt nume, deci DROP CONSTRAINT IF EXISTS n-a șters nimic.',
            HINT = 'Vezi ce constrângeri CHECK are tabela: SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = ''scans''::regclass AND contype = ''c'';';
    EXCEPTION WHEN check_violation THEN
        -- Exact ce trebuia să se întâmple. Rândul de probă nu există.
        NULL;
    END;
END $$;
