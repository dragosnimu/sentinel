-- 0032_assets_retired: un activ scos din inventory.yaml se RETRAGE, nu se șterge.
--
-- ## Ce s-a măsurat, pe gazdă, 29 august 2026
--
-- Panoul arăta `Servicii: 🟢 10 · 🔴 4` de optsprezece zile. Cele patru roșii:
--
--     n8n           ultima dată sus  11.08 07:46   (30 237 sonde reușite din 78 739)
--     n8n-traefik   ultima dată sus  11.08 07:46
--     qdrant        ultima dată sus  11.08 07:45
--     webmin        ultima dată sus  07.08 15:35
--
-- Niciunul nu era picat. Niciunul nu mai era INSTALAT: `rpm -q webmin` nu
-- găsește pachetul, nu există container docker cu numele astea, nu există
-- unitate systemd, și nu ascultă nimic pe 88, 6333 sau 5678. Operatorul le
-- dezinstalase.
--
-- Ce rămăsese erau patru rânduri în `assets`, scrise cândva din
-- `/etc/sentinel/inventory.yaml`, pe care nimic nu le mai putea scoate:
-- `sentinel/scan/inventory.py:sync` făcea DOAR `upsert`. Confirma ce e PREZENT
-- în fișier și nu se uita niciodată la ce LIPSEȘTE — chiar tiparul pe care
-- `CLAUDE.md` îl numește cauza aproape fiecărui defect livrat de aici.
--
-- Costul nu e cosmetic. Trei dintre ele declarau și suprafață de atac care nu
-- mai există (`qdrant` 0.0.0.0:6333, `webmin` 0.0.0.0:10000, `n8n-traefik`
-- 0.0.0.0:88 și :444), iar patru rânduri roșii permanente antrenează exact
-- obiceiul de a nu mai citi roșul.
--
-- ## De ce o coloană nouă și nu una existentă
--
-- S-au cântărit cele care există deja în `assets`:
--
--   * `protected` și `confirmed_by_operator` — sunt intenția operatorului și au
--     deja înțeles propriu, aplicat în `patch/validator.py` și la autorizarea
--     scanării active. Reîncărcate cu «retras», o retragere ar deschide la
--     patch automat sau ar revoca o autorizație de DAST în alt loc.
--   * `last_seen` — e mutat înainte de FIECARE `upsert`, deci un prag de
--     vechime peste el ar fi o ghicitoare, nu o măsurătoare, și n-ar deosebi
--     «scos din fișier» de «sincronizarea n-a mai rulat».
--   * `tags` — e rescris în întregime din `EXCLUDED.tags` la fiecare sincronizare
--     și e spațiul de nume al operatorului. O etichetă rezervată acolo s-ar
--     ciocni de a lui și s-ar filtra prin potrivire de șiruri.
--
-- ## De ce un moment de timp și nu un boolean
--
-- Fiindcă întrebarea de după «unde s-a dus» e «de când», iar schema citește deja
-- starea în forma asta: `asset_drift.resolved_at`, `outages.ended_at`,
-- `login_sessions.closed_at`. NULL înseamnă activ, o valoare înseamnă retras la
-- momentul ăla. Un boolean ar fi cerut o a doua coloană ca să spună același
-- lucru.
--
-- ## De ce NU un DELETE
--
-- Fiindcă `asset_id` e purtat de unsprezece tabele, în trei feluri diferite, și
-- toate trei sunt rele:
--
--   * `ON DELETE CASCADE` — `asset_drift`, `maintenance_windows`, `findings`,
--     `availability_rollup`, `outages`. Rândurile DISPAR. Constatările de
--     vulnerabilitate și panele măsurate ale activului se duc odată cu el.
--   * `ON DELETE SET NULL` — `detections`, `incidents`, `scans`, `patch_plans`,
--     `restore_points`. Rândurile rămân, dar orfane: incidentul există și nu mai
--     spune pe cine a lovit. Exact dosarul pe care îl vrei DUPĂ ce ai scos ceva
--     de pe server, dacă acel ceva a fost atacat cât timp a existat.
--   * fără nicio cheie străină — `health_samples`, `raw_events`,
--     `event_rollup_1m`. Aici `DELETE` nici măcar nu pică și nici nu curăță:
--     rândurile rămân, arătând ca ale unui activ, cu un `asset_id` care nu mai
--     duce nicăieri.
--
-- Retragerea păstrează rândul, deci și `id`-ul, deci toate cele de mai sus
-- rămân interogabile exact ca înainte. Iar un activ scos din greșeală se
-- întoarce prin simpla re-adăugare în fișier, legat de același istoric.
--
-- ## Lacătul
--
-- `ADD COLUMN` fără valoare implicită nu rescrie tabela — se schimbă doar
-- catalogul. Lacătul `ACCESS EXCLUSIVE` se ia și se dă drumul imediat, iar
-- `assets` are paisprezece rânduri pe gazdă. Nu se ridică niciun timeout aici:
-- dacă instrucțiunea asta stă la coadă mai mult de zece secunde, ceva ține un
-- lacăt pe `assets` și e mai bine să se retragă migrația.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS retired_at timestamptz;

COMMENT ON COLUMN assets.retired_at IS
    'Când activul a dispărut din inventory.yaml. NULL = urmărit. Vezi sentinel/scan/inventory.py.';

-- ## De ce se citește catalogul după ALTER
--
-- `IF NOT EXISTS` se uită DOAR LA NUME. Dacă o coloană `retired_at` există deja
-- pe altceva — adăugată de mână, sau de o versiune mai veche a schimbării ăsteia
-- — `ALTER` iese cu zero și nu face nimic, iar felul în care s-ar vedea greșeala
-- e cel mai rău cu putință:
--
--   * tip `boolean` sau `timestamp` fără fus: `retired_at IS NULL` compilează în
--     amândouă cazurile și înseamnă altceva decât aici;
--   * `NOT NULL DEFAULT false`, sau orice valoare implicită: atunci
--     `retired_at IS NULL` nu e adevărat pentru NICIUN rând, `list_all` întoarce
--     lista goală, sonda nu mai verifică nimic și pagina Servicii se golește. Un
--     panou gol arată identic cu «totul e în regulă».
--
-- Dintr-un cod de ieșire zero, toate arată la fel. Deci se citește ce a rămas în
-- catalog, nu ce s-a cerut.
DO $$
DECLARE
    tip           text;
    accepta_nul   boolean;
    are_implicita boolean;
BEGIN
    SELECT format_type(a.atttypid, a.atttypmod), NOT a.attnotnull, a.atthasdef
      INTO tip, accepta_nul, are_implicita
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
     WHERE c.relname = 'assets'
       AND c.relkind = 'r'
       AND a.attname = 'retired_at'
       AND a.attnum > 0
       AND NOT a.attisdropped;

    IF tip IS NULL THEN
        RAISE EXCEPTION
            'assets.retired_at nu există după ALTER TABLE';
    END IF;

    IF tip <> 'timestamp with time zone' THEN
        RAISE EXCEPTION
            'assets.retired_at există, dar are tipul %; „retired_at IS NULL" ar însemna altceva decât retragerea', tip;
    END IF;

    IF NOT accepta_nul THEN
        RAISE EXCEPTION
            'assets.retired_at e NOT NULL — atunci niciun activ nu mai apare ca urmărit și pagina Servicii se golește';
    END IF;

    IF are_implicita THEN
        RAISE EXCEPTION
            'assets.retired_at are o valoare implicită — un activ nou s-ar naște retras';
    END IF;
END $$;

-- Rândurile care există deja rămân cu `retired_at = NULL`, adică urmărite.
-- Migrația NU retrage cele patru intrări moarte de pe gazdă: ele pleacă atunci
-- când operatorul le scoate din `/etc/sentinel/inventory.yaml` și rulează
-- următoarea sincronizare. O migrație care ar șterge rânduri pe baza unei liste
-- scrise aici ar fi o decizie luată acum despre o gazdă citită acum, aplicată
-- oricând mai târziu pe orice gazdă.
