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
-- dacă bucla rapidă tot oferă planul înainte ca fereastra să apuce să decidă.
--
-- `proposed_by_window` desparte cele două: bucla rapidă oferă direct planurile
-- care NU vin de la planner-ul automat (azi, niciunul); cele care vin trec
-- prin fereastră, care marchează coloana asta când planul a trecut poarta —
-- abia atunci `unnotified_plans` îl vede. Vezi
-- `sentinel/db/repo/patches.py:unnotified_plans` pentru interogarea amendată
-- și `sentinel/patch/window.py` pentru poartă.
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

ALTER TABLE patch_plans ADD COLUMN IF NOT EXISTS proposed_by_window boolean;
ALTER TABLE patch_plans ALTER COLUMN proposed_by_window SET DEFAULT false;
ALTER TABLE patch_plans ALTER COLUMN proposed_by_window SET NOT NULL;

COMMENT ON COLUMN patch_plans.proposed_by_window IS
    'true = sentinel-patch-window l-a eliberat către canalul de aprobare, după '
    'ce a trecut poarta de eligibilitate. Planurile generated_by=''ai'' NU '
    'sunt oferite de unnotified_plans() decât după ce coloana asta devine '
    'true — vezi 0043 și sentinel/patch/window.py.';

-- Lacătul pe ALTER se ia și se dă drumul imediat — verificat oricum, ca la
-- 0042: `IF NOT EXISTS` se uită doar la NUME, iar dintr-un cod de ieșire zero
-- un tip greșit sau un implicit greșit ar arăta identic cu reușita.
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
        RAISE EXCEPTION 'patch_plans.proposed_by_window nu există după ALTER TABLE';
    END IF;

    IF tip <> 'boolean' THEN
        RAISE EXCEPTION
            'patch_plans.proposed_by_window are tipul %, nu boolean', tip;
    END IF;

    IF accepta_nul THEN
        RAISE EXCEPTION
            'patch_plans.proposed_by_window acceptă NULL — un rând vechi ar '
            'deveni neclasificabil în loc de "nu, încă"';
    END IF;

    IF implicit_text IS DISTINCT FROM 'false' THEN
        RAISE EXCEPTION
            'patch_plans.proposed_by_window are valoarea implicită %, nu '
            'false — orice plan viitor generat pe altă cale ar porni deja '
            '"eliberat"', implicit_text;
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
    'Un rând pe rulare a sentinel-patch-window.timer, indiferent de rezultat — '
    '"niciodată rulat" trebuie să rămână distinct de "a rulat și n-a găsit '
    'nimic eligibil", altfel amândouă arată ca zero planuri propuse.';
COMMENT ON COLUMN patch_window_runs.halted IS
    'true = un plan anterior propus de fereastră a eșuat la aplicare, iar '
    'fereastra a refuzat să mai propună ceva nou pe canalul automat.';
COMMENT ON COLUMN patch_window_runs.skipped IS
    'Un obiect per plan luat în considerare și respins: '
    '{"plan_id": N, "state": "not_reversible"|"unproven", "reason": "..."}.';

CREATE INDEX IF NOT EXISTS patch_window_runs_ran_at_idx
    ON patch_window_runs (ran_at DESC);
