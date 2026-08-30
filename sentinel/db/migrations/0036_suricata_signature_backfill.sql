-- 0036_suricata_signature_backfill: umple `signature` pentru suricata scris
-- ÎNAINTE de declanșatorul din 0035.
--
-- ## De ce e într-un fișier SEPARAT de 0035, nu în continuarea lui
--
-- Părea firesc să fie „declanșator, apoi backfill, în aceeași migrație": un
-- singur pas, o singură poveste. S-a măsurat direct de ce nu e sigur.
--
-- `sentinel/db/migrate.py` aplică un fișier într-o singură tranzacție. `ALTER
-- TABLE ... ADD COLUMN` și `CREATE TRIGGER` din 0035 cer amândouă `ACCESS
-- EXCLUSIVE` pe `raw_events` — și lacătul ăsta NU se eliberează la finalul
-- instrucțiunii care l-a luat. Rămâne ținut până la COMMIT-ul întregii
-- tranzacții, indiferent ce rulează după el în același fișier.
--
-- Măsurat: cu `ALTER TABLE` + `CREATE TRIGGER` într-o tranzacție ținută
-- deschisă (un `pg_sleep` în locul restului migrației), un `SELECT` obișnuit
-- din altă sesiune — nu un `INSERT`, un `SELECT` — a AȘTEPTAT și a picat la
-- `statement_timeout`. Dacă backfill-ul (24,7–29,4 s măsurat pe replică,
-- pentru ~318 000 de rânduri) ar fi rulat în ACEEAȘI tranzacție ca declanșatorul,
-- tot intervalul ăla ar fi însemnat panoul picat cu EXACT simptomul pe care
-- toată seria 0030–0035 încearcă să-l repare — de data asta produs chiar de
-- migrație, nu de interogare, și pe DASHBOARD, nu doar pe ingestie.
--
-- Un `UPDATE` obișnuit, într-o tranzacție care nu a atins nicio comandă
-- `ACCESS EXCLUSIVE` înainte, cere doar `ROW EXCLUSIVE` — compatibil cu
-- `SELECT` (panoul) și cu alte `ROW EXCLUSIVE` (INSERT-urile ingestiei).
-- Verificat direct: cu backfill-ul rulând singur, un `SELECT` de pe panou și
-- un `INSERT` de ingestie, lansate din altă sesiune CÂT TIMP backfill-ul era
-- încă în lucru, s-au întors amândouă în sub 300 ms. De-asta fișierul ăsta nu
-- conține nicio comandă `ALTER`/`CREATE` — orice ar cere `ACCESS EXCLUSIVE`
-- aici ar strica exact proprietatea pentru care există fișierul separat.
--
-- ## De ce o singură trecere, nu în tranșe
--
-- Tiparul casei pentru ștergeri mari e `DELETE_BATCH = 20_000`
-- (`maintenance_service.py`) — tranșe mici, fiecare propria tranzacție, ca să
-- nu se țină un lacăt lung cât detecția așteaptă. Aici nu se aplică: tranșele
-- își pierd exact rostul ăsta ÎNTR-O SINGURĂ tranzacție de migrație, fiindcă
-- lacătul `ROW EXCLUSIVE` tot rămâne ținut de la primul `UPDATE` până la
-- COMMIT-ul fișierului, indiferent în câte instrucțiuni s-ar împărți munca —
-- tranșarea ar complica fișierul fără să scurteze nimic ținut.
--
-- Rămâne o singură trecere: 24,7–29,4 s măsurat pe replică pentru ~318 000 de
-- rânduri, sub `ROW EXCLUSIVE`, care NU blochează cititorii — deci acceptabil
-- o dată, la deploy. O tranșare adevărată, cu lacăte eliberate între tranșe,
-- ar cere un mecanism din AFARA migrațiilor (un pas de `sentinel maintenance`,
-- de pildă) — nejustificat aici cât timp o singură trecere nu ține niciun
-- cititor.
--
-- ## De ce nu e o cursă cu declanșatorul
--
-- Din momentul în care 0035 s-a aplicat (COMMIT-ul ei), orice rând nou de
-- suricata primește `signature` de la declanșator, înainte ca rândul să
-- ajungă vizibil oricui. `WHERE signature IS NULL` exclude exact rândurile
-- alea — nu le atinge, nu le suprascrie, nu pierde timp pe ele. Rândurile pe
-- care le prinde sunt STRICT cele scrise înainte de 0035, indiferent cât timp
-- a trecut între 0035 și acest fișier. Două rulări ale acestei migrații —
-- ipotetic, dacă cineva ar reseta `schema_version` — ar da a doua oară
-- `UPDATE 0`: verificat direct pe replică.
SET LOCAL statement_timeout = '10min';
SET LOCAL lock_timeout = '60s';

UPDATE raw_events
   SET signature = raw->>'signature'
 WHERE source = 'suricata' AND signature IS NULL;

-- ## Garda: efectul, nu doar codul de ieșire zero
--
-- Un `UPDATE` reușit cu zero rânduri atinse ar însemna, aici, că filtrul n-a
-- găsit NIMIC de reparat — plauzibil doar dacă baza chiar nu are suricata
-- vechi. Nu se poate deosebi de un `WHERE` stricat (o coloană redenumită, un
-- typo în `'suricata'`) decât uitându-se la ce a mai rămas NULL. Dacă rândurile
-- de suricata vechi din fereastra activă tot au `signature IS NULL` după
-- această comandă, migrația a „reușit" fără efect.
DO $$
DECLARE
    ramase bigint;
BEGIN
    SELECT count(*) INTO ramase
      FROM raw_events
     WHERE source = 'suricata' AND signature IS NULL;

    IF ramase > 0 THEN
        RAISE EXCEPTION
            'au rămas % rânduri de suricata cu signature NULL după backfill — WHERE-ul UPDATE-ului nu a acoperit tot ce trebuia',
            ramase;
    END IF;
END $$;
