-- 0042_restore_drill_items: Funcționalitatea 07 — exercițiul de restaurare,
-- programat lunar.
--
-- ## Ce s-a măsurat pe gazdă, 1 septembrie 2026
--
-- `restore_drills` există din 0004 și are ZERO rânduri. Singura oară când
-- mecanismul de întoarcere a fost pus la treabă — execuția 9, pe 3 august — a
-- fost un `rollback_failed`. `verified_at` de pe toate cele trei puncte de
-- restaurare e egal cu `created_at`: verificarea existentă confirmă fișierul
-- tocmai scris, în aceeași secundă, nu că se poate citi înapoi mai târziu.
--
-- Un backup pe care nimeni nu l-a restaurat nu e un backup — e o ipoteză.
--
-- ## Ce NU se schimbă
--
-- `restore_drills` rămâne tabela drill-ului MANUAL, de pe canary, documentat
-- în `docs/PATCHING.md` §6 — `INSERT INTO restore_drills (restore_point_id,
-- performed_by, succeeded, notes) VALUES (...)` scris acolo continuă să
-- funcționeze neschimbat. Coloana nouă `automated` desparte cele două: `false`
-- (implicit) pentru rândul scris de mână de operator pe canary, `true` pentru
-- cel scris de `sentinel-restore-drill.timer`, într-un spațiu izolat, fără să
-- atingă vreodată un fișier real. Un canary dovedește mai mult — un serviciu
-- chiar pornit pe fișierele restaurate — dar rulează o dată pe trimestru, cu
-- un operator. Automatul rulează lunar, singur, și dovedește mai puțin:
-- checksum-uri și structura arhivei, nu că serviciul pornește. Amestecate
-- sub o singură coloană `succeeded`, un operator n-ar putea spune care
-- dovadă o citește.
--
-- ## De ce o tabelă COPIL, nu doar `restore_drills.succeeded`
--
-- Un punct de restaurare poate avea artefacte de DOUĂ feluri (vezi manifestul
-- descris în `sentinel/patch/backup.py`): `is_archive: true` (o arhivă
-- `tar.zst` cu fișiere reale) și `is_archive: false` (o listă de pachete RPM
-- sau un `git rev-parse`, informativ — `restore.sh` însuși scrie „informativ,
-- vezi manifest.json" pentru astea, NU le restaurează).
--
-- Un singur boolean pe rândul drill-ului ar amesteca „am dovedit că arhiva
-- X se reface" cu „acest artefact e doar informativ, nimic de dovedit despre
-- el" — exact confuzia pe care Funcționalitatea 08 nu are voie s-o moștenească,
-- fiindcă ea va aplica reparații automate DOAR pe baza unei întoarceri DOVEDITE
-- prin exercițiu. Deci verdictul se scrie PE ARTEFACT, nu doar pe punct:
-- 08 poate întreba „s-a dovedit vreodată că ACEST FEL de artefact se poate
-- întoarce" agregând `restore_drill_items` după `is_archive`, indiferent ce
-- alte artefacte erau în același punct.
--
-- ## De ce `restore_points` nu capătă coloane noi
--
-- „S-a dovedit vreodată pentru punctul ăsta" e un JOIN ieftin pe
-- `restore_drills.restore_point_id` (câteva rânduri pe punct, niciodată mii).
-- O coloană `last_drill_ok` pe `restore_points`, ținută manual sincronizată cu
-- `restore_drills`, ar fi a doua sursă de adevăr pentru același fapt — tiparul
-- din `CLAUDE.md` care se contrazice exact pe gazda unde contează.

ALTER TABLE restore_drills ADD COLUMN IF NOT EXISTS automated boolean;
ALTER TABLE restore_drills ALTER COLUMN automated SET DEFAULT false;
ALTER TABLE restore_drills ALTER COLUMN automated SET NOT NULL;

-- Rezumat structurat, ca `patch_executions.result` — un `SELECT` fără JOIN
-- pentru verificarea de sănătate care citește ultimul drill al fiecărui punct.
-- Detaliul PE ARTEFACT stă în `restore_drill_items`, mai jos; asta e doar
-- numărătoarea.
ALTER TABLE restore_drills ADD COLUMN IF NOT EXISTS result jsonb;

COMMENT ON COLUMN restore_drills.automated IS
    'true = sentinel-restore-drill.timer, izolat, lunar. false = drill manual '
    'pe canary, docs/PATCHING.md §6. Niciodată amestecate sub același succeeded.';
COMMENT ON COLUMN restore_drills.result IS
    'Numărătoare pe verdict: {"restorable_verified":N,"informational_only":N,'
    '"corrupt":N,"structure_mismatch":N,"skipped_low_disk":N}. Detaliul per '
    'artefact e în restore_drill_items.';

-- Lacătul pe `ALTER` se ia și se dă drumul imediat — `restore_drills` are zero
-- rânduri pe gazda măsurată, deci nu e nimic de rescris. Verificat oricum,
-- pentru același motiv ca la 0032: `IF NOT EXISTS` se uită doar la NUME, iar
-- dintr-un cod de ieșire zero un tip greșit sau o valoare implicită greșită ar
-- arăta identic cu reușita.
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
     WHERE c.relname = 'restore_drills'
       AND c.relkind = 'r'
       AND a.attname = 'automated'
       AND a.attnum > 0
       AND NOT a.attisdropped;

    IF tip IS NULL THEN
        RAISE EXCEPTION 'restore_drills.automated nu există după ALTER TABLE';
    END IF;

    IF tip <> 'boolean' THEN
        RAISE EXCEPTION
            'restore_drills.automated are tipul %, nu boolean — distincția '
            'manual/automat s-ar pierde', tip;
    END IF;

    IF accepta_nul THEN
        RAISE EXCEPTION
            'restore_drills.automated acceptă NULL — un rând vechi, scris '
            'manual înainte de migrația asta, ar deveni neclasificabil în loc '
            'de "manual"';
    END IF;

    IF implicit_text IS DISTINCT FROM 'false' THEN
        RAISE EXCEPTION
            'restore_drills.automated are valoarea implicită %, nu false — '
            'INSERT-ul manual din docs/PATCHING.md §6, care nu setează '
            'coloana asta, ar fi clasificat greșit drept "automat"', implicit_text;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Verdictul pe artefact.
-- ---------------------------------------------------------------------------
CREATE TABLE restore_drill_items (
    id            bigserial   PRIMARY KEY,
    drill_id      bigint      NOT NULL REFERENCES restore_drills(id) ON DELETE CASCADE,

    artifact      text        NOT NULL,
    is_archive    boolean     NOT NULL,
    sha256_ok     boolean     NOT NULL,

    -- restorable_verified   — arhivă, checksum bun, extrasă izolat, iar sursele
    --                         declarate în manifest chiar apar la calea așteptată.
    -- informational_only    — is_archive = false (rpm_state / git_ref). Niciodată
    --                         restaurabil, indiferent de checksum.
    -- corrupt                — checksum greșit, artefact lipsă, sau extragerea
    --                         (tar) a eșuat.
    -- structure_mismatch     — checksum bun, extragerea a reușit, dar NICIO sursă
    --                         declarată nu apare unde ar trebui: arhiva se extrage
    --                         curat și tot nu se întoarce la locul ei real.
    -- skipped_low_disk       — verificată prin checksum, dar neextrasă: nu era
    --                         spațiu sigur. Nici dovedită, nici respinsă.
    verdict       text        NOT NULL
                    CHECK (verdict IN ('restorable_verified', 'informational_only',
                                       'corrupt', 'structure_mismatch',
                                       'skipped_low_disk')),
    detail        text        NOT NULL DEFAULT ''
);

-- Pentru drill-ul unui punct: toate artefactele lui, în ordinea în care au
-- fost scrise (implicit prin `id`).
CREATE INDEX restore_drill_items_drill_idx ON restore_drill_items (drill_id);

-- Interogarea lui 08: „s-a dovedit vreodată că un artefact de FELUL ăsta se
-- poate întoarce" — agregată peste TOATE drill-urile, pe `is_archive`.
CREATE INDEX restore_drill_items_kind_idx ON restore_drill_items (is_archive, verdict);

-- „Ultimul drill al fiecărui punct" — citit de verificarea de sănătate la
-- fiecare rulare.
CREATE INDEX restore_drills_point_idx ON restore_drills (restore_point_id, performed_at DESC);
