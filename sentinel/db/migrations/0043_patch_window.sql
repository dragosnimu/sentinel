-- 0043_patch_window: Funcționalitatea 08 — fereastra de reparare cu întoarcere
-- dovedită.
--
-- ## Ce rezolvă
--
-- Astăzi orice plan generat de `planner.generate_for_kev` (`generated_by =
-- 'ai'`) ajunge `status = 'validated'` și e oferit pe Telegram în cel mult 15
-- secunde de bucla de push existentă (`unnotified_plans` / `_push_plans`),
-- fără nicio garanție că întoarcerea lui e dovedită. `sentinel-patch-window`
-- introduce o poartă de eligibilitate (întoarcere dovedită prin exercițiul de
-- restaurare, Funcționalitatea 07) și o oprire la primul eșec, ambele inutile
-- dacă bucla rapidă tot oferă butonul de aprobare înainte ca fereastra să
-- apuce să decidă.
--
-- `proposed_by_window` desparte cele două: bucla rapidă oferă BUTONUL DE
-- APROBARE direct pentru planurile care NU vin de la planner-ul automat (azi,
-- niciunul); cele care vin trec prin fereastră, care marchează coloana asta
-- când planul a trecut poarta — abia atunci `unnotified_plans` atașează
-- butonul. Vezi `sentinel/db/repo/patches.py:unnotified_plans` pentru
-- interogarea amendată și `sentinel/patch/window.py` pentru poartă.
--
-- Runda 2 a arătat că gating-ul ăsta, luat singur, ascunde EXISTENȚA planului
-- timp de o lună (măsurat: primul exercițiu posibil pe 1 octombrie, deci orice
-- candidat e `unproven` până atunci) — „nu poate fi aplicat automat" și „nu
-- trebuie să afli că există" sunt fapte diferite. `window_notice_sent_at`
-- desparte a treia stare: un canal informativ, FĂRĂ buton de aplicare, trimis
-- o singură dată, indiferent dacă fereastra eliberează planul vreodată. Vezi
-- `sentinel/telegram/bot.py:_push_window_gated_notices`.
--
-- ## De ce nu o coloană „eligible" cu trei stări
--
-- Eligibilitatea depinde de dovada CEA MAI RECENTĂ din `restore_drill_items`,
-- care se schimbă lunar, independent de plan. O coloană scrisă o singură
-- dată, la generare, ar fi a doua sursă de adevăr — exact tiparul din
-- CLAUDE.md care se contrazice pe gazda unde contează. Poarta se
-- RECALCULEAZĂ de fiecare dată (`sentinel/patch/window.py:evaluate`), atât de
-- fereastră cât și de verificarea de sănătate; singurul lucru persistat aici
-- e DECIZIA IREVERSIBILĂ „a fost eliberat", nu motivul.
--
-- ## `patch_window_runs`
--
-- La fel ca `restore_drills` pentru Funcționalitatea 07: fără un rând scris
-- la FIECARE rulare, „fereastra n-a rulat niciodată" și „a rulat și n-a găsit
-- nimic eligibil" arată identic — zero planuri propuse. Un rând per rulare
-- desparte cele două, exact tiparul cerut explicit pentru 08.
--
-- ## `patch_window_overrides` — desfacerea zăvorului lasă urmă, nu rescrie
--
-- `window_halt()` se recalculează din `patch_executions` + `proposed_by_
-- window`, niciodată memorată — corect, dar asta a lăsat o singură cale de
-- desfacere: să rescrii `patch_executions.status`, adică exact rândul pe care
-- `sentinel/db/repo/patches.py` îl declară scris-înainte-de-fapt și
-- de nerescris. Peste șase luni, un `UPDATE` acolo e fie istoric contrafăcut,
-- fie o fereastră moartă tăcut, fără să se poată spune care.
--
-- `patch_window_overrides` e un rând NOU, niciodată un `UPDATE`: cine a decis
-- să treacă peste eșecul unei execuții anume, când, și de ce. `window_halt()`
-- exclude execuțiile care au deja un rând de derogare — vezi interogarea
-- amendată în `sentinel/db/repo/patches.py`. Nu există (încă) o comandă
-- Telegram care scrie aici: cine poate desface zăvorul, prin ce ceremonie de
-- confirmare, e o decizie a operatorului, nu una pe care o ia agentul — rândul
-- de azi se scrie manual (psql / un script revizuit separat), auditabil prin
-- construcție.

ALTER TABLE patch_plans
    ADD COLUMN IF NOT EXISTS proposed_by_window boolean NOT NULL DEFAULT false;

-- Nullable, deliberat — la fel ca `notified_at` deja existent pe același
-- tabel: NULL înseamnă „încă netrimis", nu are nevoie de DEFAULT și deci nu
-- poate reproduce defectul de mai sus (un ALTER cu DEFAULT pus DUPĂ coloană,
-- care nu completează retroactiv rândurile vechi și pică la SET NOT NULL).
ALTER TABLE patch_plans
    ADD COLUMN IF NOT EXISTS window_notice_sent_at timestamptz;

COMMENT ON COLUMN patch_plans.proposed_by_window IS
    'true = sentinel-patch-window l-a eliberat catre canalul de aprobare, dupa ce a trecut poarta de eligibilitate. Planurile generated_by=ai NU sunt oferite de unnotified_plans() decat dupa ce coloana asta devine true - vezi 0043 si sentinel/patch/window.py.';
COMMENT ON COLUMN patch_plans.window_notice_sent_at IS
    'Momentul la care s-a trimis anuntul INFORMATIV (fara buton de aplicare) ca planul a fost generat, dar fereastra nu l-a putut elibera inca. Independent de notified_at (care marcheaza butonul de aprobare) - un plan poate primi anuntul acum si butonul luni viitoare, cand fereastra il elibereaza.';

-- Lacătul pe ALTER se ia și se dă drumul imediat — verificat oricum, ca la
-- 0042: `IF NOT EXISTS` se uită doar la NUME, iar dintr-un cod de ieșire zero
-- un tip greșit sau un implicit greșit ar arăta identic cu reușita.
--
-- Verificat aici doar `proposed_by_window`: e singura coloană cu NOT NULL +
-- DEFAULT, deci singura unde tipul greșit, un implicit greșit sau un NULL
-- rămas ar produce o gazdă tăcut coruptă. `window_notice_sent_at` e nullable
-- fără implicit — un `ADD COLUMN` care „reușește" pentru ea nu poate ajunge
-- în starea contrafăcută pe care blocul de mai jos o caută.
DO $$
DECLARE
    tip           text;
    accepta_nul   boolean;
    implicit_text text;
BEGIN
    SELECT format_type(a.atttypid, a.atttypmod), NOT a.attnotnull,
           pg_get_expr(d.adbin, d.adrelid)
      INTO tip, accepta_nul, implicit_text
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
     WHERE c.relname = 'patch_plans'
       AND c.relkind = 'r'
       AND a.attname = 'proposed_by_window'
       AND a.attnum > 0
       AND NOT a.attisdropped;

    IF tip IS NULL THEN
        RAISE EXCEPTION 'patch_plans.proposed_by_window nu exista dupa ALTER TABLE';
    END IF;

    IF tip <> 'boolean' THEN
        RAISE EXCEPTION
            'patch_plans.proposed_by_window are tipul %, nu boolean', tip;
    END IF;

    IF accepta_nul THEN
        RAISE EXCEPTION
            'patch_plans.proposed_by_window accepta NULL - un rand vechi ar deveni neclasificabil in loc de "nu, inca"';
    END IF;

    IF implicit_text IS DISTINCT FROM 'false' THEN
        RAISE EXCEPTION
            'patch_plans.proposed_by_window are valoarea implicita %, nu false - orice plan viitor generat pe alta cale ar porni deja "eliberat"', implicit_text;
    END IF;
END $$;

-- Interogarea ferestrei pentru „mai există un plan validat, neconsiderat încă"
-- e pe (status, proposed_by_window); planurile generate automat sunt rare
-- (câteva pe noapte, plafonate), deci indexul nu ține de volum, ci de a nu
-- scana tabela întreagă la fiecare rulare săptămânală.
CREATE INDEX IF NOT EXISTS patch_plans_window_candidate_idx
    ON patch_plans (status, proposed_by_window);

CREATE TABLE IF NOT EXISTS patch_window_runs (
    id                bigserial   PRIMARY KEY,
    ran_at            timestamptz NOT NULL DEFAULT now(),
    candidates        int         NOT NULL DEFAULT 0,
    proposed_plan_id  bigint      REFERENCES patch_plans(id),
    halted            boolean     NOT NULL DEFAULT false,
    detail            text        NOT NULL DEFAULT '',
    skipped           jsonb       NOT NULL DEFAULT '[]'::jsonb
);

COMMENT ON TABLE patch_window_runs IS
    'Un rand pe rulare a sentinel-patch-window.timer, indiferent de rezultat - "niciodata rulat" trebuie sa ramana distinct de "a rulat si n-a gasit nimic eligibil", altfel amandoua arata ca zero planuri propuse.';
COMMENT ON COLUMN patch_window_runs.halted IS
    'true = un plan anterior propus de fereastra a esuat la aplicare, iar fereastra a refuzat sa mai propuna ceva nou pe canalul automat.';
COMMENT ON COLUMN patch_window_runs.skipped IS
    'Un obiect per plan luat in considerare si respins: {"plan_id": N, "state": "not_reversible sau unproven", "reason": "..."}.';

CREATE INDEX IF NOT EXISTS patch_window_runs_ran_at_idx
    ON patch_window_runs (ran_at DESC);

-- Vezi nota de mai sus: un rând NOU, niciodată un UPDATE pe istoricul din
-- patch_executions.
CREATE TABLE IF NOT EXISTS patch_window_overrides (
    id            bigserial   PRIMARY KEY,
    created_at    timestamptz NOT NULL DEFAULT now(),
    created_by    text        NOT NULL,
    execution_id  bigint      NOT NULL REFERENCES patch_executions(id),
    reason        text        NOT NULL
);

COMMENT ON TABLE patch_window_overrides IS
    'Derogare explicita, atribuita si datata de la oprirea ferestrei pentru o anume executie esuata - vezi window_halt() in sentinel/db/repo/patches.py. Un rand aici nu sterge esecul din patch_executions; doar spune ca un operator l-a citit si a decis, pe numele lui, sa continue oricum.';

CREATE UNIQUE INDEX IF NOT EXISTS patch_window_overrides_execution_idx
    ON patch_window_overrides (execution_id);
